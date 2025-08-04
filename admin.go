package sctx

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zoobzio/flume"
	"github.com/zoobzio/pipz"
	"github.com/zoobzio/zlog"
)

// Config types removed - now using flume schemas for configuration

var (
	ErrInvalidKey = errors.New("invalid private key")
)

// adminService is the security authority that creates and validates tokens
type adminService[M any] struct {
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
	certPool   *x509.CertPool
	cache      ContextCache[M]
	signer     CryptoSigner

	// Pipeline architecture
	contextFactory    *flume.Factory[*Context[M]]       // For certificate → context processing
	contextPipeline   pipz.Chainable[*Context[M]]       // Active context processing pipeline
	assertionPipeline pipz.Chainable[*AssertionContext] // Fixed assertion validation pipeline

	// Guard configuration
	guardCreationPermissions []string // Required permissions to create guards

	// Nonce tracking for replay protection
	nonceMu    sync.RWMutex
	nonceCache map[string]time.Time

	// Typed loggers
	contextLogger     *zlog.Logger[ContextEvent[M]]
	certificateLogger *zlog.Logger[CertificateEvent]
}

// NewAdminService creates a new admin service instance
func NewAdminService[M any](privateKey crypto.PrivateKey, trustedCAs *x509.CertPool) (Admin, error) {
	if privateKey == nil {
		return nil, ErrInvalidKey
	}
	if trustedCAs == nil {
		return nil, errors.New("trusted CAs required")
	}

	// Detect algorithm from key
	algorithm, err := DetectAlgorithmFromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	// Create signer
	signer, err := NewCryptoSigner(algorithm, privateKey)
	if err != nil {
		return nil, err
	}

	// Create cache with 5 minute cleanup
	cache := newMemoryContextCache[M](5 * time.Minute)

	// Create context processing factory and register processors
	contextFactory := flume.New[*Context[M]]()
	processors := CreateProcessors[M]()
	contextFactory.Add(
		// Context manipulation processors
		processors.SetExpiryOneHour,
		processors.SetExpiryFiveMinutes,
		// Permission processors
		processors.GrantRead,
		processors.GrantWrite,
		processors.GrantAdmin,
		processors.GrantCreateGuard,
	)

	// Create typed loggers
	contextLogger := zlog.NewLogger[ContextEvent[M]]()
	certificateLogger := zlog.NewLogger[CertificateEvent]()

	// Add sanitizers before forwarding to global logger
	contextLogger.HookAll(getContextSanitizer[M]())
	certificateLogger.HookAll(certificateSanitizer)

	// Enable global forwarding
	contextLogger.Watch()
	certificateLogger.Watch()

	result := &adminService[M]{
		privateKey:        privateKey,
		publicKey:         signer.PublicKey(),
		certPool:          trustedCAs,
		cache:             cache,
		signer:            signer,
		contextFactory:    contextFactory,
		nonceCache:        make(map[string]time.Time),
		contextLogger:     contextLogger,
		certificateLogger: certificateLogger,
	}

	// Create fixed assertion validation pipeline
	assertionProcessors := CreateAssertionProcessors[M]()
	assertionPipeline := pipz.NewSequence[*AssertionContext]("assertion-validation",
		assertionProcessors[ProcessorVerifySignature],
		assertionProcessors[ProcessorCheckExpiration],
		checkNonceProcessor(result),
		assertionProcessors[ProcessorMatchFingerprint],
		assertionProcessors[ProcessorValidateClaims],
	)
	result.assertionPipeline = assertionPipeline

	// Start cache cleanup
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	cache.Start(shutdown, &wg)

	return result, nil
}

// PublicKey returns the public key for token verification
func (a *adminService[M]) PublicKey() crypto.PublicKey {
	return a.publicKey
}

// Algorithm returns the crypto algorithm in use
func (a *adminService[M]) Algorithm() CryptoAlgorithm {
	return a.signer.Algorithm()
}

// Cache operations for admin control

// RevokeByFingerprint removes a context from the cache
func (a *adminService[M]) RevokeByFingerprint(fingerprint string) error {
	// Get context info before deletion for audit
	ctx, exists := a.cache.Get(fingerprint)
	if exists && ctx != nil {
		cn := ctx.CertificateInfo.CommonName
		a.contextLogger.Emit(CONTEXT_REVOKED,
			fmt.Sprintf("Context manually revoked for %s", cn),
			ContextEvent[M]{
				Context:   ctx,
				Token:     "", // Token not available in revoke
				Operation: "revoked",
			},
		)
	}
	return a.cache.Delete(fingerprint)
}

// GetContext retrieves a context by fingerprint
func (a *adminService[M]) GetContext(fingerprint string) (*Context[M], bool) {
	return a.cache.Get(fingerprint)
}

// ActiveCount returns the number of active contexts
func (a *adminService[M]) ActiveCount() int {
	if counter, ok := a.cache.(interface{ Count() int }); ok {
		return counter.Count()
	}
	return -1 // Unknown
}

// RegisterProcessor registers a custom processor with the context factory
func (a *adminService[M]) RegisterProcessor(name string, guard ContextGuard[M]) {
	a.contextFactory.Add(pipz.Apply(pipz.Name(name), guard))
}

// SetCache replaces the context cache implementation
// This allows users to bring their own cache (Redis, Hazelcast, etc)
func (a *adminService[M]) SetCache(cache ContextCache[M]) error {
	if cache == nil {
		return errors.New("cache cannot be nil")
	}
	a.cache = cache
	return nil
}

// LoadContextSchema configures the context processing pipeline from a YAML schema
func (a *adminService[M]) LoadContextSchema(yamlStr string) error {
	pipeline, err := a.contextFactory.BuildFromYAML(yamlStr)
	if err != nil {
		return fmt.Errorf("failed to build context pipeline from schema: %w", err)
	}
	a.contextPipeline = pipeline
	return nil
}

// LoadContextSchemaFromFile loads a context schema from a file
func (a *adminService[M]) LoadContextSchemaFromFile(path string) error {
	pipeline, err := a.contextFactory.BuildFromFile(path)
	if err != nil {
		return fmt.Errorf("failed to build context pipeline from file %s: %w", path, err)
	}
	a.contextPipeline = pipeline
	return nil
}

// Generate creates a token for the given certificate and assertion
func (a *adminService[M]) Generate(cert *x509.Certificate, assertion SignedAssertion) (SignedToken, error) {
	if cert == nil {
		return "", errors.New("certificate is required")
	}

	// Validate assertion through fixed pipeline

	assertionCtx := &AssertionContext{
		Assertion:   assertion,
		Certificate: cert,
	}

	_, err := a.assertionPipeline.Process(context.Background(), assertionCtx)
	if err != nil {
		a.certificateLogger.Emit(CERTIFICATE_REJECTED,
			fmt.Sprintf("Certificate rejected due to invalid assertion: %s", cert.Subject.CommonName),
			CertificateEvent{
				CertificateInfo: extractCertificateInfo(cert),
				Reason:          "assertion validation failed",
				Error:           err,
			},
		)
		return "", fmt.Errorf("assertion validation failed: %w", err)
	}

	// Verify certificate against trusted CAs
	opts := x509.VerifyOptions{
		Roots:         a.certPool,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := cert.Verify(opts); err != nil {
		a.certificateLogger.Emit(CERTIFICATE_REJECTED,
			fmt.Sprintf("Certificate rejected: %s", cert.Subject.CommonName),
			CertificateEvent{
				CertificateInfo: extractCertificateInfo(cert),
				Reason:          "validation failed",
				Error:           err,
			},
		)
		return "", fmt.Errorf("certificate verification failed: %w", err)
	}

	// Check if already cached
	fingerprint := getFingerprint(cert)
	if cached, exists := a.cache.Get(fingerprint); exists {
		return a.createToken(cached)
	}

	// Create new context with certificate info
	ctx := &Context[M]{
		CertificateInfo:        extractCertificateInfo(cert),
		CertificateFingerprint: fingerprint,
		IssuedAt:               time.Now(),
	}

	// Run context enrichment pipeline
	if a.contextPipeline == nil {
		return "", errors.New("no context pipeline configured - use LoadContextSchema()")
	}

	// Run pipeline
	result, err := a.contextPipeline.Process(context.Background(), ctx)
	if err != nil {
		return "", err
	}
	ctx = result

	// Cache and return token
	a.cache.Store(fingerprint, ctx)
	token, err := a.createToken(ctx)
	if err != nil {
		return "", err
	}

	// Emit audit event
	a.contextLogger.Emit(TOKEN_GENERATED,
		fmt.Sprintf("Token generated for %s", ctx.CertificateInfo.CommonName),
		ContextEvent[M]{
			Context:   ctx,
			Token:     string(token),
			Operation: "generated",
		},
	)

	return token, nil
}

// OnContext registers hooks for context/token events
func (a *adminService[M]) OnContext(signal zlog.Signal, hooks ...func(context.Context, zlog.Event[ContextEvent[M]]) (zlog.Event[ContextEvent[M]], error)) {
	for _, hook := range hooks {
		wrapped := pipz.Apply[zlog.Event[ContextEvent[M]]]("user-hook", hook)
		a.contextLogger.Hook(signal, wrapped)
	}
}

// OnCertificate registers hooks for certificate events
func (a *adminService[M]) OnCertificate(signal zlog.Signal, hooks ...func(context.Context, zlog.Event[CertificateEvent]) (zlog.Event[CertificateEvent], error)) {
	for _, hook := range hooks {
		wrapped := pipz.Apply[zlog.Event[CertificateEvent]]("user-hook", hook)
		a.certificateLogger.Hook(signal, wrapped)
	}
}

// createToken creates a signed token from a context
func (a *adminService[M]) createToken(ctx *Context[M]) (SignedToken, error) {
	payload := &tokenPayload{
		Fingerprint: ctx.CertificateFingerprint,
		Expiry:      ctx.ExpiresAt,
		Nonce:       generateContextID(),
	}

	return encodeAndSign(payload, a.signer)
}

// decryptToken decrypts a token and returns the fingerprint
func (a *adminService[M]) decryptToken(token SignedToken) (string, error) {
	payload, err := verifyTokenPayload(token, a.publicKey)
	if err != nil {
		return "", err
	}
	return payload.Fingerprint, nil
}

// SetGuardCreationPermissions configures which permissions are required to create guards
func (a *adminService[M]) SetGuardCreationPermissions(perms []string) {
	a.guardCreationPermissions = perms
}

// CreateGuard creates a new guard that validates tokens for specific permissions
func (a *adminService[M]) CreateGuard(token SignedToken, requiredPerms ...string) (Guard, error) {
	// 1. Validate token and get context
	fingerprint, err := a.decryptToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	context, exists := a.cache.Get(fingerprint)
	if !exists {
		return nil, errors.New("context not found")
	}

	if context.IsExpired() {
		return nil, errors.New("token expired")
	}

	// 2. Check guard creation permissions
	if len(a.guardCreationPermissions) > 0 {
		for _, perm := range a.guardCreationPermissions {
			if !hasPermission(context.Permissions, perm) {
				return nil, fmt.Errorf("missing required permission to create guards: %s", perm)
			}
		}
	}

	// 3. Ensure guard can only check permissions the creator has
	for _, perm := range requiredPerms {
		if !hasPermission(context.Permissions, perm) {
			return nil, fmt.Errorf("cannot create guard for permission you don't have: %s", perm)
		}
	}

	// 4. Create guard closure
	guardID := generateGuardID()
	guard := &guardImpl{
		id:                  guardID,
		requiredPermissions: requiredPerms,
		validate: func(t SignedToken) error {
			// Decrypt and validate token
			fp, err := a.decryptToken(t)
			if err != nil {
				return fmt.Errorf("invalid token: %w", err)
			}

			// Get context and check permissions
			ctx, exists := a.cache.Get(fp)
			if !exists {
				return errors.New("context not found")
			}

			if ctx.IsExpired() {
				return errors.New("token expired")
			}

			// Check required permissions
			for _, perm := range requiredPerms {
				if !hasPermission(ctx.Permissions, perm) {
					return fmt.Errorf("missing permission: %s", perm)
				}
			}

			return nil
		},
	}

	// 5. Emit event
	a.contextLogger.Emit(GUARD_CREATED,
		fmt.Sprintf("Guard %s created by %s", guardID, context.CertificateInfo.CommonName),
		ContextEvent[M]{
			Context:   context,
			Token:     string(token),
			Operation: "guard_created",
		},
	)

	return guard, nil
}
