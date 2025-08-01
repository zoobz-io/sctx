package sctx

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zoobzio/pipz"
)

// Config defines the pipeline configurations
type Config struct {
	ContextPipeline PipelineConfig `yaml:"contextPipeline"`
}

// PipelineConfig defines a pipeline as a list of guard names
type PipelineConfig struct {
	Guards []string `yaml:"guards"`
}

var (
	ErrAlreadyInitialized = errors.New("admin service already initialized")
	ErrInvalidKey         = errors.New("invalid private key")
)

// AdminService is the security authority that creates and validates tokens
// Only one AdminService can exist per process (singleton)
type AdminService[M any] struct {
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
	certPool   *x509.CertPool
	cache      ContextCache[M]
	signer     CryptoSigner
	
	// Configuration
	guards map[string]ContextGuard[M]
	config     atomic.Pointer[Config]
	
	// Context enrichment pipeline - single pipeline for all certificates
	contextPipeline *pipz.Sequence[*Context[M]]
	
	// Issued guards tracking
	issuedGuards sync.Map // guardID -> *IssuedGuard[M]
}

// Global singleton enforcement
var (
	adminOnce     sync.Once
	adminInstance interface{}
	adminErr      error
)

// NewAdminService creates the singleton admin service
// Only one admin can exist globally to ensure security
func NewAdminService[M any](privateKey crypto.PrivateKey, trustedCAs *x509.CertPool) (*AdminService[M], error) {
	if privateKey == nil {
		return nil, ErrInvalidKey
	}
	if trustedCAs == nil {
		return nil, errors.New("trusted CAs required")
	}

	// Check if already created
	if adminInstance != nil {
		// Type assert to ensure same type
		if existing, ok := adminInstance.(*AdminService[M]); ok {
			return existing, nil
		}
		return nil, errors.New("admin service already exists with different type")
	}

	var result *AdminService[M]

	adminOnce.Do(func() {
		// Detect algorithm from key
		algorithm, err := DetectAlgorithmFromPrivateKey(privateKey)
		if err != nil {
			adminErr = err
			return
		}

		// Create signer
		signer, err := NewCryptoSigner(algorithm, privateKey)
		if err != nil {
			adminErr = err
			return
		}

		// Create cache with 5 minute cleanup
		cache := newMemoryContextCache[M](5 * time.Minute)

		result = &AdminService[M]{
			privateKey: privateKey,
			publicKey:  signer.PublicKey(),
			certPool:   trustedCAs,
			cache:      cache,
			signer:     signer,
			guards: make(map[string]ContextGuard[M]),
		}

		// Start cache cleanup
		shutdown := make(chan struct{})
		var wg sync.WaitGroup
		cache.Start(shutdown, &wg)

		adminInstance = result
	})

	if adminErr != nil {
		return nil, adminErr
	}

	return result, nil
}

// PublicKey returns the public key for token verification
func (a *AdminService[M]) PublicKey() crypto.PublicKey {
	return a.publicKey
}

// Algorithm returns the crypto algorithm in use
func (a *AdminService[M]) Algorithm() CryptoAlgorithm {
	return a.signer.Algorithm()
}

// Cache operations for admin control

// RevokeByFingerprint removes a context from the cache
func (a *AdminService[M]) RevokeByFingerprint(fingerprint string) error {
	return a.cache.Delete(fingerprint)
}

// GetContext retrieves a context by fingerprint
func (a *AdminService[M]) GetContext(fingerprint string) (*Context[M], bool) {
	return a.cache.Get(fingerprint)
}

// ActiveCount returns the number of active contexts
func (a *AdminService[M]) ActiveCount() int {
	if counter, ok := a.cache.(interface{ Count() int }); ok {
		return counter.Count()
	}
	return -1 // Unknown
}

// RegisterGuard registers a named guard for use in pipelines
func (a *AdminService[M]) RegisterGuard(name string, guard ContextGuard[M]) {
	a.guards[name] = guard
}

// SetCache replaces the context cache implementation
// This allows users to bring their own cache (Redis, Hazelcast, etc)
func (a *AdminService[M]) SetCache(cache ContextCache[M]) error {
	if cache == nil {
		return errors.New("cache cannot be nil")
	}
	a.cache = cache
	return nil
}

// ConfigureContextPipeline sets up the context enrichment pipeline
// This pipeline runs for ALL certificates to extract permissions and metadata
func (a *AdminService[M]) ConfigureContextPipeline(guards ...ContextGuard[M]) {
	pipeline := pipz.NewSequence[*Context[M]]("context-enrichment")
	for i, guard := range guards {
		processor := pipz.Apply(fmt.Sprintf("guard-%d", i), guard)
		pipeline.Register(processor)
	}
	a.contextPipeline = pipeline
}

// LoadConfig loads pipeline configuration
func (a *AdminService[M]) LoadConfig(config *Config) error {
	if config == nil {
		return errors.New("config cannot be nil")
	}
	a.config.Store(config)
	
	// Build context pipeline from config
	if len(config.ContextPipeline.Guards) > 0 {
		pipeline := pipz.NewSequence[*Context[M]]("context-enrichment")
		for _, guardName := range config.ContextPipeline.Guards {
			guard, exists := a.guards[guardName]
			if !exists {
				return fmt.Errorf("unknown guard: %s", guardName)
			}
			processor := pipz.Apply(guardName, guard)
			pipeline.Register(processor)
		}
		a.contextPipeline = pipeline
	}
	
	return nil
}

// Generate creates a token for the given certificate
func (a *AdminService[M]) Generate(cert *x509.Certificate) (SignedToken, error) {
	// Verify certificate against trusted CAs
	opts := x509.VerifyOptions{Roots: a.certPool}
	if _, err := cert.Verify(opts); err != nil {
		return "", fmt.Errorf("certificate verification failed: %w", err)
	}
	
	// Check if already cached
	fingerprint := getFingerprint(cert)
	if cached, exists := a.cache.Get(fingerprint); exists {
		return a.createToken(cached)
	}
	
	// Create new context with certificate
	ctx := &Context[M]{
		Certificate:            cert,
		CertificateFingerprint: fingerprint,
		IssuedAt:              time.Now(),
	}
	
	// Run context enrichment pipeline
	if a.contextPipeline == nil {
		return "", errors.New("no context pipeline configured")
	}
	
	// Run pipeline
	result, err := a.contextPipeline.Process(context.Background(), ctx)
	if err != nil {
		return "", err
	}
	ctx = result
	
	// Cache and return token
	a.cache.Store(fingerprint, ctx)
	return a.createToken(ctx)
}

// CreateGuard creates a guard that validates tokens based on permissions
func (a *AdminService[M]) CreateGuard(token SignedToken, permissions ...string) (Guard, error) {
	// Decrypt token to get fingerprint
	fingerprint, err := a.decryptToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	
	// Get context from cache
	ctx, exists := a.cache.Get(fingerprint)
	if !exists {
		return nil, errors.New("token not found or revoked")
	}
	
	// Check expiry
	if time.Now().After(ctx.ExpiresAt) {
		a.cache.Delete(fingerprint)
		return nil, errors.New("token expired")
	}
	
	// Verify token has all requested permissions
	for _, perm := range permissions {
		if !ctx.HasPermission(perm) {
			return nil, fmt.Errorf("token lacks permission: %s", perm)
		}
	}
	
	// Create guard
	guard := &IssuedGuard[M]{
		id:          generateContextID(),
		createdBy:   fingerprint,
		permissions: permissions,
		expiresAt:   ctx.ExpiresAt, // Inherit expiry from parent token
		admin:       a,
	}
	
	// Track the guard
	a.issuedGuards.Store(guard.id, guard)
	
	return guard, nil
}

// createToken creates a signed token from a context
func (a *AdminService[M]) createToken(ctx *Context[M]) (SignedToken, error) {
	payload := &tokenPayload{
		Fingerprint: ctx.CertificateFingerprint,
		Nonce:       generateContextID(),
	}
	
	return encodeAndSign(payload, a.signer)
}

// decryptToken decrypts a token and returns the fingerprint
func (a *AdminService[M]) decryptToken(token SignedToken) (string, error) {
	payload, err := verifyTokenPayload(token, a.publicKey)
	if err != nil {
		return "", err
	}
	return payload.Fingerprint, nil
}

// copyContext creates a deep copy of a context
func (a *AdminService[M]) copyContext(ctx *Context[M]) *Context[M] {
	permissions := make([]string, len(ctx.Permissions))
	copy(permissions, ctx.Permissions)
	
	return &Context[M]{
		Certificate:            ctx.Certificate,
		Permissions:            permissions,
		IssuedAt:              ctx.IssuedAt,
		ExpiresAt:             ctx.ExpiresAt,
		Issuer:                ctx.Issuer,
		CertificateFingerprint: ctx.CertificateFingerprint,
		Metadata:              ctx.Metadata,
	}
}

