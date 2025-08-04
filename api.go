package sctx

import (
	"crypto/x509"
)

// Admin is the non-generic interface for admin operations
type Admin interface {
	Generate(cert *x509.Certificate, assertion SignedAssertion) (SignedToken, error)
	CreateGuard(token SignedToken, requiredPermissions ...string) (Guard, error)
	SetGuardCreationPermissions(perms []string)
	LoadContextSchema(yamlStr string) error
}

// Guard validates tokens against required permissions
type Guard interface {
	ID() string
	Validate(token SignedToken) error
	Permissions() []string
}
