package sctx

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zoobz-io/capitan"
)

var (
	ErrInvalidKey          = errors.New("invalid private key")
	ErrAdminAlreadyCreated = errors.New("admin service already created - only one admin allowed per application instance")
	ErrNoPolicy            = errors.New("no context policy configured")
	adminOnce              sync.Once
	adminCreated           bool
)

// adminService is the security authority that creates and validates tokens.
type adminService[M any] struct {
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
	certPool   *x509.CertPool
	cache      ContextCache[M]
	signer     CryptoSigner

	// Policy function for transforming certificates into contexts
	policy   ContextPolicy[M]
	policyMu sync.RWMutex

	// Assertion validation using direct function calls (no pipz dependency)

	// Guard configuration
	guardCreationPermissions []string // Required permissions to create guards

	// Nonce tracking for replay protection
	nonceMu    sync.RWMutex
	nonceCache *boundedNonceCache
}

// createAdminService is the internal implementation of admin service creation.
func createAdminService[M any](privateKey crypto.PrivateKey, trustedCAs *x509.CertPool) (Admin[M], error) {
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

	result := &adminService[M]{
		privateKey: privateKey,
		publicKey:  signer.PublicKey(),
		certPool:   trustedCAs,
		cache:      cache,
		signer:     signer,
		nonceCache: newBoundedNonceCache(DefaultNonceOptions().MaxSize),
	}

	// Assertion validation now uses direct function calls - no pipeline setup needed

	// Start cache cleanup
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	cache.Start(shutdown, &wg)

	// Set default policy
	result.policy = DefaultContextPolicy[M]()

	return result, nil
}

// NewAdminService creates a new admin service instance - only one admin allowed per application instance.
func NewAdminService[M any](privateKey crypto.PrivateKey, trustedCAs *x509.CertPool) (Admin[M], error) {
	if adminCreated {
		return nil, ErrAdminAlreadyCreated
	}

	var admin Admin[M]
	var err error

	adminOnce.Do(func() {
		adminCreated = true
		admin, err = createAdminService[M](privateKey, trustedCAs)
	})

	return admin, err
}

// PublicKey returns the public key for token verification.
func (a *adminService[M]) PublicKey() crypto.PublicKey {
	return a.publicKey
}

// Algorithm returns the crypto algorithm in use.
func (a *adminService[M]) Algorithm() CryptoAlgorithm {
	return a.signer.Algorithm()
}

// cleanExpiredNonces removes expired nonces from the cache.
func (a *adminService[M]) cleanExpiredNonces() {
	a.nonceCache.CleanExpired()
}

// Cache operations for admin control

// RevokeByFingerprint removes a context from the cache.
func (a *adminService[M]) RevokeByFingerprint(ctx context.Context, fingerprint string) error {
	// Clean expired nonces during this write operation
	a.nonceMu.Lock()
	a.cleanExpiredNonces()
	a.nonceMu.Unlock()

	err := a.cache.Delete(ctx, fingerprint)
	if err == nil {
		capitan.Info(ctx, ContextRevoked, FingerprintKey.Field(fingerprint))
	}
	return err
}

// GetContext retrieves a context by fingerprint.
func (a *adminService[M]) GetContext(ctx context.Context, fingerprint string) (*Context[M], bool) {
	return a.cache.Get(ctx, fingerprint)
}

// ActiveCount returns the number of active contexts.
func (a *adminService[M]) ActiveCount() int {
	return a.cache.Count()
}

// SetPolicy sets the context policy function.
func (a *adminService[M]) SetPolicy(policy ContextPolicy[M]) error {
	a.policyMu.Lock()
	defer a.policyMu.Unlock()

	if policy == nil {
		return errors.New("policy cannot be nil")
	}

	a.policy = policy
	return nil
}

// This allows users to bring their own cache (Redis, Hazelcast, etc).
func (a *adminService[M]) SetCache(cache ContextCache[M]) error {
	if cache == nil {
		return errors.New("cache cannot be nil")
	}
	a.cache = cache
	return nil
}

// Generate creates a token for the given certificate and assertion.
func (a *adminService[M]) Generate(ctx context.Context, cert *x509.Certificate, assertion SignedAssertion) (SignedToken, error) {
	if cert == nil {
		return "", errors.New("certificate is required")
	}

	// Validate assertion using direct function calls
	err := ValidateAssertion(ctx, assertion, cert, a)
	if err != nil {
		return "", fmt.Errorf("assertion validation failed: %w", err)
	}

	// Verify certificate against trusted CAs
	opts := x509.VerifyOptions{
		Roots:         a.certPool,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, verifyErr := cert.Verify(opts); verifyErr != nil {
		capitan.Warn(ctx, CertificateRejected,
			CommonNameKey.Field(cert.Subject.CommonName),
			ErrorKey.Field(verifyErr.Error()),
		)
		return "", fmt.Errorf("certificate verification failed: %w", verifyErr)
	}

	// Check if already cached
	fingerprint := getFingerprint(cert)
	if cached, exists := a.cache.Get(ctx, fingerprint); exists {
		return a.createToken(cached)
	}

	// Apply policy to transform certificate into context
	a.policyMu.RLock()
	policy := a.policy
	a.policyMu.RUnlock()

	if policy == nil {
		return "", ErrNoPolicy
	}

	secCtx, err := policy(cert)
	if err != nil {
		return "", fmt.Errorf("policy failed: %w", err)
	}

	// Set certificate info and fingerprint (in case policy didn't)
	if secCtx.CertificateInfo.CommonName == "" {
		secCtx.CertificateInfo = extractCertificateInfo(cert)
	}
	if secCtx.CertificateFingerprint == "" {
		secCtx.CertificateFingerprint = fingerprint
	}
	if secCtx.IssuedAt.IsZero() {
		secCtx.IssuedAt = time.Now()
	}

	// Cache and return token
	a.cache.Store(ctx, fingerprint, secCtx)
	token, err := a.createToken(secCtx)
	if err != nil {
		return "", err
	}

	capitan.Info(ctx, TokenGenerated,
		FingerprintKey.Field(fingerprint),
		CommonNameKey.Field(cert.Subject.CommonName),
		PermissionsKey.Field(strings.Join(secCtx.Permissions, ",")),
	)

	return token, nil
}

// GenerateTrusted creates a token for an mTLS-verified certificate without assertion validation.
// The TLS handshake already proved private key possession, so we skip the assertion step.
func (a *adminService[M]) GenerateTrusted(ctx context.Context, cert *x509.Certificate) (SignedToken, error) {
	if cert == nil {
		return "", errors.New("certificate is required")
	}

	// Verify certificate against trusted CAs
	opts := x509.VerifyOptions{
		Roots:         a.certPool,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, verifyErr := cert.Verify(opts); verifyErr != nil {
		capitan.Warn(ctx, CertificateRejected,
			CommonNameKey.Field(cert.Subject.CommonName),
			ErrorKey.Field(verifyErr.Error()),
		)
		return "", fmt.Errorf("certificate verification failed: %w", verifyErr)
	}

	// Check if already cached
	fingerprint := getFingerprint(cert)
	if cached, exists := a.cache.Get(ctx, fingerprint); exists {
		return a.createToken(cached)
	}

	// Apply policy to transform certificate into context
	a.policyMu.RLock()
	policy := a.policy
	a.policyMu.RUnlock()

	if policy == nil {
		return "", ErrNoPolicy
	}

	secCtx, err := policy(cert)
	if err != nil {
		return "", fmt.Errorf("policy failed: %w", err)
	}

	// Set certificate info and fingerprint (in case policy didn't)
	if secCtx.CertificateInfo.CommonName == "" {
		secCtx.CertificateInfo = extractCertificateInfo(cert)
	}
	if secCtx.CertificateFingerprint == "" {
		secCtx.CertificateFingerprint = fingerprint
	}
	if secCtx.IssuedAt.IsZero() {
		secCtx.IssuedAt = time.Now()
	}

	// Cache and return token
	a.cache.Store(ctx, fingerprint, secCtx)
	token, err := a.createToken(secCtx)
	if err != nil {
		return "", err
	}

	capitan.Info(ctx, TrustedTokenGenerated,
		FingerprintKey.Field(fingerprint),
		CommonNameKey.Field(cert.Subject.CommonName),
		PermissionsKey.Field(strings.Join(secCtx.Permissions, ",")),
	)

	return token, nil
}

// createToken creates a signed token from a context.
func (a *adminService[M]) createToken(ctx *Context[M]) (SignedToken, error) {
	// Token expiry should not exceed certificate expiry
	tokenExpiry := ctx.ExpiresAt
	if ctx.CertificateInfo.NotAfter.Before(tokenExpiry) {
		tokenExpiry = ctx.CertificateInfo.NotAfter
	}

	payload := &tokenPayload{
		Fingerprint: ctx.CertificateFingerprint,
		IssuedAt:    time.Now(),
		Expiry:      tokenExpiry,
		Nonce:       generateContextID(),
	}

	return encodeAndSign(payload, a.signer)
}

// decryptToken decrypts a token and returns the fingerprint.
func (a *adminService[M]) decryptToken(ctx context.Context, token SignedToken) (string, error) {
	payload, err := verifyTokenPayload(token, a.publicKey)
	if err != nil {
		capitan.Warn(ctx, TokenRejected,
			ErrorKey.Field(err.Error()),
		)
		return "", err
	}
	capitan.Debug(ctx, TokenVerified,
		FingerprintKey.Field(payload.Fingerprint),
	)
	return payload.Fingerprint, nil
}

// SetGuardCreationPermissions configures which permissions are required to create guards.
func (a *adminService[M]) SetGuardCreationPermissions(perms []string) {
	a.guardCreationPermissions = perms
}

// CreateGuard creates a new guard that validates tokens for specific permissions.
func (a *adminService[M]) CreateGuard(ctx context.Context, token SignedToken, requiredPerms ...string) (Guard, error) {
	// Clean expired nonces during this write operation
	a.nonceMu.Lock()
	a.cleanExpiredNonces()
	a.nonceMu.Unlock()

	// 1. Validate token and get context
	fingerprint, err := a.decryptToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	secCtx, exists := a.cache.Get(ctx, fingerprint)
	if !exists {
		capitan.Warn(ctx, GuardRejected,
			FingerprintKey.Field(fingerprint),
			ErrorKey.Field("context not found"),
		)
		return nil, errors.New("context not found")
	}

	if secCtx.IsExpired() {
		capitan.Warn(ctx, GuardRejected,
			FingerprintKey.Field(fingerprint),
			ErrorKey.Field("token expired"),
		)
		return nil, errors.New("token expired")
	}

	// 2. Check guard creation permissions
	if len(a.guardCreationPermissions) > 0 {
		for _, perm := range a.guardCreationPermissions {
			if !hasPermission(secCtx.Permissions, perm) {
				err := fmt.Errorf("missing required permission to create guards: %s", perm)
				capitan.Warn(ctx, GuardRejected,
					FingerprintKey.Field(fingerprint),
					ErrorKey.Field(err.Error()),
				)
				return nil, err
			}
		}
	}

	// 3. Ensure guard can only check permissions the creator has
	for _, perm := range requiredPerms {
		if !hasPermission(secCtx.Permissions, perm) {
			err := fmt.Errorf("cannot create guard for permission you don't have: %s", perm)
			capitan.Warn(ctx, GuardRejected,
				FingerprintKey.Field(fingerprint),
				ErrorKey.Field(err.Error()),
			)
			return nil, err
		}
	}

	// 4. Create guard closure
	guardID := generateGuardID()
	creatorFingerprint := secCtx.CertificateFingerprint // Store creator's fingerprint
	guard := &guardImpl{
		id:                  guardID,
		creatorFingerprint:  creatorFingerprint,
		requiredPermissions: requiredPerms,
		validate: func(ctx context.Context, tokens ...SignedToken) error {
			// Require at least one token
			if len(tokens) == 0 {
				err := errors.New("at least one token required")
				capitan.Warn(ctx, GuardRejected,
					GuardIDKey.Field(guardID),
					ErrorKey.Field(err.Error()),
				)
				return err
			}

			// First token is the caller
			callerToken := tokens[0]

			// Validate caller token
			callerFp, err := a.decryptToken(ctx, callerToken)
			if err != nil {
				capitan.Warn(ctx, GuardRejected,
					GuardIDKey.Field(guardID),
					ErrorKey.Field(err.Error()),
				)
				return fmt.Errorf("invalid caller token: %w", err)
			}

			// CRITICAL: Verify caller is the guard creator
			if callerFp != creatorFingerprint {
				err := errors.New("guard can only be used by its creator")
				capitan.Warn(ctx, GuardRejected,
					GuardIDKey.Field(guardID),
					FingerprintKey.Field(callerFp),
					ErrorKey.Field(err.Error()),
				)
				return err
			}

			callerCtx, exists := a.cache.Get(ctx, callerFp)
			if !exists {
				err := errors.New("caller context not found")
				capitan.Warn(ctx, GuardRejected,
					GuardIDKey.Field(guardID),
					FingerprintKey.Field(callerFp),
					ErrorKey.Field(err.Error()),
				)
				return err
			}

			if callerCtx.IsExpired() {
				err := errors.New("caller token expired")
				capitan.Warn(ctx, GuardRejected,
					GuardIDKey.Field(guardID),
					FingerprintKey.Field(callerFp),
					ErrorKey.Field(err.Error()),
				)
				return err
			}

			// Determine which tokens to validate for required permissions
			var targetsToValidate []SignedToken
			if len(tokens) == 1 {
				// Self-validation: check if caller has required permissions
				targetsToValidate = []SignedToken{callerToken}
			} else {
				// Delegation: validate other tokens
				targetsToValidate = tokens[1:]
			}

			// Validate each target token
			for i, targetToken := range targetsToValidate {
				fp, err := a.decryptToken(ctx, targetToken)
				if err != nil {
					capitan.Warn(ctx, GuardRejected,
						GuardIDKey.Field(guardID),
						ErrorKey.Field(fmt.Sprintf("invalid token at position %d: %v", i+1, err)),
					)
					return fmt.Errorf("invalid token at position %d: %w", i+1, err)
				}

				sctx, exists := a.cache.Get(ctx, fp)
				if !exists {
					err := fmt.Errorf("context not found for token at position %d", i+1)
					capitan.Warn(ctx, GuardRejected,
						GuardIDKey.Field(guardID),
						FingerprintKey.Field(fp),
						ErrorKey.Field(err.Error()),
					)
					return err
				}

				if sctx.IsExpired() {
					err := fmt.Errorf("token at position %d expired", i+1)
					capitan.Warn(ctx, GuardRejected,
						GuardIDKey.Field(guardID),
						FingerprintKey.Field(fp),
						ErrorKey.Field(err.Error()),
					)
					return err
				}

				// Check required permissions
				for _, perm := range requiredPerms {
					if !hasPermission(sctx.Permissions, perm) {
						err := fmt.Errorf("token at position %d missing permission: %s", i+1, perm)
						capitan.Warn(ctx, GuardRejected,
							GuardIDKey.Field(guardID),
							FingerprintKey.Field(fp),
							ErrorKey.Field(err.Error()),
						)
						return err
					}
				}
			}

			capitan.Debug(ctx, GuardValidated,
				GuardIDKey.Field(guardID),
				FingerprintKey.Field(callerFp),
			)
			return nil
		},
	}

	capitan.Debug(ctx, GuardCreated,
		GuardIDKey.Field(guardID),
		FingerprintKey.Field(creatorFingerprint),
		RequiredPermsKey.Field(strings.Join(requiredPerms, ",")),
	)

	return guard, nil
}
