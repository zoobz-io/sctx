package sctx

import (
	"crypto/x509"
	"sync/atomic"
	"errors"
)

// Admin is the non-generic interface for admin operations
type Admin interface {
	Generate(cert *x509.Certificate) (SignedToken, error)
	CreateGuard(token SignedToken, permissions ...string) (Guard, error)
	LoadConfig(config *Config) error
}

// Guard validates tokens based on required permissions
type Guard interface {
	Validate(token SignedToken) error
	ID() string
	Permissions() []string
}

// Global admin reference
var globalAdmin atomic.Pointer[Admin]

// SetAdmin sets the global admin instance
func SetAdmin(admin Admin) error {
	if admin == nil {
		return errors.New("admin cannot be nil")
	}
	globalAdmin.Store(&admin)
	return nil
}

// Generate creates a token using the global admin
func Generate(cert *x509.Certificate) (SignedToken, error) {
	adminPtr := globalAdmin.Load()
	if adminPtr == nil {
		return "", errors.New("no admin service configured")
	}
	return (*adminPtr).Generate(cert)
}

// CreateGuard creates a guard using the global admin
func CreateGuard(token SignedToken, permissions ...string) (Guard, error) {
	adminPtr := globalAdmin.Load()
	if adminPtr == nil {
		return nil, errors.New("no admin service configured")
	}
	return (*adminPtr).CreateGuard(token, permissions...)
}

// LoadConfig loads configuration using the global admin
func LoadConfig(config *Config) error {
	adminPtr := globalAdmin.Load()
	if adminPtr == nil {
		return errors.New("no admin service configured")
	}
	return (*adminPtr).LoadConfig(config)
}