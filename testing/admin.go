//go:build testing

package testing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/zoobz-io/sctx"
)

// Key type constants.
const (
	keyTypeECDSA   = "ecdsa"
	keyTypeEd25519 = "ed25519"
)

// TestAdminOption configures TestAdmin creation.
type TestAdminOption func(*testAdminConfig)

type testAdminConfig struct {
	keyType string
}

// WithEd25519 configures the admin to use Ed25519 keys.
func WithEd25519() TestAdminOption {
	return func(c *testAdminConfig) {
		c.keyType = keyTypeEd25519
	}
}

// WithECDSA configures the admin to use ECDSA P-256 keys.
func WithECDSA() TestAdminOption {
	return func(c *testAdminConfig) {
		c.keyType = keyTypeECDSA
	}
}

// TestAdmin creates an admin service configured for testing.
// Returns the admin and test certificates.
// Note: This uses the internal createAdminService to avoid singleton restrictions.
func TestAdmin[M any](tb testing.TB, opts ...TestAdminOption) (sctx.Admin[M], *TestCertificates) {
	tb.Helper()

	cfg := &testAdminConfig{keyType: keyTypeEd25519}
	for _, opt := range opts {
		opt(cfg)
	}

	// Generate test certificates
	testCerts := GenerateTestCertificates(tb)

	// Generate admin key (separate from client keys)
	var adminKey crypto.PrivateKey
	var err error
	switch cfg.keyType {
	case keyTypeECDSA:
		adminKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		_, adminKey, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		tb.Fatalf("failed to generate admin key: %v", err)
	}

	// Create admin service - must reset singleton for testing
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[M](adminKey, testCerts.CertPool)
	if err != nil {
		tb.Fatalf("failed to create admin service: %v", err)
	}

	return admin, testCerts
}
