package sctx

import (
	"context"
	"crypto/x509"
)

// ContextPolicy defines how to transform certificates into security contexts.
type ContextPolicy[M any] func(cert *x509.Certificate) (*Context[M], error)

// Admin is the interface for admin operations.
type Admin[M any] interface {
	// Generate creates a token for the given certificate and assertion
	Generate(ctx context.Context, cert *x509.Certificate, assertion SignedAssertion) (SignedToken, error)

	// CreateGuard creates a guard for validating tokens with required permissions
	CreateGuard(ctx context.Context, token SignedToken, requiredPermissions ...string) (Guard, error)

	// SetGuardCreationPermissions sets permissions required to create guards
	SetGuardCreationPermissions(perms []string)

	// SetPolicy sets the context policy function
	SetPolicy(policy ContextPolicy[M]) error

	// SetCache replaces the context cache implementation
	SetCache(cache ContextCache[M]) error

	// RevokeByFingerprint revokes a context by certificate fingerprint
	RevokeByFingerprint(ctx context.Context, fingerprint string) error

	// GetContext retrieves a context by fingerprint
	GetContext(ctx context.Context, fingerprint string) (*Context[M], bool)

	// ActiveCount returns the number of active contexts
	ActiveCount() int
}

// Guard validates tokens against required permissions.
type Guard interface {
	ID() string
	Validate(ctx context.Context, tokens ...SignedToken) error
	Permissions() []string
}

// Principal represents an authenticated in-process consumer with a defined role.
type Principal interface {
	// Token returns the principal's signed token.
	Token() SignedToken

	// Inject embeds the principal's token into a context.Context.
	Inject(ctx context.Context) context.Context

	// Guard creates a context-aware guard that extracts tokens from context.Context.
	Guard(ctx context.Context, requiredPermissions ...string) (Guard, error)
}
