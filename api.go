package sctx

import (
	"context"
	"crypto/x509"
)

// ContextPolicy defines how to transform certificates into security contexts
type ContextPolicy[M any] func(cert *x509.Certificate) (*Context[M], error)

// Admin is the interface for admin operations
type Admin[M any] interface {
	Generate(ctx context.Context, cert *x509.Certificate, assertion SignedAssertion) (SignedToken, error)
	CreateGuard(ctx context.Context, token SignedToken, requiredPermissions ...string) (Guard, error)
	SetGuardCreationPermissions(perms []string)
	SetPolicy(policy ContextPolicy[M]) error
}

// Guard validates tokens against required permissions
type Guard interface {
	ID() string
	Validate(ctx context.Context, tokens ...SignedToken) error
	Permissions() []string
}
