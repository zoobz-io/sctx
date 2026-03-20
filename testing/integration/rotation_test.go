//go:build integration && testing

package integration

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/zoobz-io/sctx"
	"github.com/zoobz-io/sctx/testing/integration/ca"
)

// TestIntegration_Rotation_NewCertSameIdentity tests certificate rotation with same CN.
func TestIntegration_Rotation_NewCertSameIdentity(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue first certificate
	oldCert, oldKey, err := testCA.IssueCertificate("rotating-client")
	if err != nil {
		t.Fatalf("Failed to issue first certificate: %v", err)
	}

	// Create admin
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](oldKey, testCA.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Set policy
	_ = admin.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read", "write"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	// Generate token with old cert
	oldAssertion, _ := sctx.CreateAssertion(oldKey, oldCert)
	oldToken, err := admin.Generate(ctx, oldCert, oldAssertion)
	if err != nil {
		t.Fatalf("Failed to generate token with old cert: %v", err)
	}

	// Issue new certificate with same CN
	newCert, newKey, err := testCA.IssueCertificate("rotating-client")
	if err != nil {
		t.Fatalf("Failed to issue new certificate: %v", err)
	}

	// Generate token with new cert
	newAssertion, _ := sctx.CreateAssertion(newKey, newCert)
	newToken, err := admin.Generate(ctx, newCert, newAssertion)
	if err != nil {
		t.Fatalf("Failed to generate token with new cert: %v", err)
	}

	// Both contexts should exist (different fingerprints)
	if admin.ActiveCount() != 2 {
		t.Errorf("Expected 2 active contexts, got %d", admin.ActiveCount())
	}

	// Both tokens should work
	oldGuard, err := admin.CreateGuard(ctx, oldToken, "read")
	if err != nil {
		t.Fatalf("Failed to create guard with old token: %v", err)
	}

	newGuard, err := admin.CreateGuard(ctx, newToken, "read")
	if err != nil {
		t.Fatalf("Failed to create guard with new token: %v", err)
	}

	if err := oldGuard.Validate(ctx, oldToken); err != nil {
		t.Errorf("Old token validation failed: %v", err)
	}

	if err := newGuard.Validate(ctx, newToken); err != nil {
		t.Errorf("New token validation failed: %v", err)
	}
}

// TestIntegration_Rotation_RevokeOldCert tests revoking old cert after rotation.
func TestIntegration_Rotation_RevokeOldCert(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue first certificate
	oldCert, oldKey, err := testCA.IssueCertificate("revoke-test-client")
	if err != nil {
		t.Fatalf("Failed to issue first certificate: %v", err)
	}

	// Create admin
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](oldKey, testCA.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Set policy
	_ = admin.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	// Generate token and guard with old cert
	oldAssertion, _ := sctx.CreateAssertion(oldKey, oldCert)
	oldToken, err := admin.Generate(ctx, oldCert, oldAssertion)
	if err != nil {
		t.Fatalf("Failed to generate token with old cert: %v", err)
	}

	oldGuard, err := admin.CreateGuard(ctx, oldToken, "read")
	if err != nil {
		t.Fatalf("Failed to create guard with old token: %v", err)
	}

	// Issue new certificate
	newCert, newKey, err := testCA.IssueCertificate("revoke-test-client")
	if err != nil {
		t.Fatalf("Failed to issue new certificate: %v", err)
	}

	// Generate token with new cert
	newAssertion, _ := sctx.CreateAssertion(newKey, newCert)
	newToken, err := admin.Generate(ctx, newCert, newAssertion)
	if err != nil {
		t.Fatalf("Failed to generate token with new cert: %v", err)
	}

	newGuard, err := admin.CreateGuard(ctx, newToken, "read")
	if err != nil {
		t.Fatalf("Failed to create guard with new token: %v", err)
	}

	// Revoke old cert's context
	oldFingerprint := sctx.GetFingerprint(oldCert)
	err = admin.RevokeByFingerprint(ctx, oldFingerprint)
	if err != nil {
		t.Fatalf("Failed to revoke old context: %v", err)
	}

	// Old guard should fail
	err = oldGuard.Validate(ctx, oldToken)
	if err == nil {
		t.Error("Expected old guard validation to fail after revocation")
	}

	// New guard should still work
	err = newGuard.Validate(ctx, newToken)
	if err != nil {
		t.Errorf("New guard validation should succeed: %v", err)
	}

	// Active count should be 1
	if admin.ActiveCount() != 1 {
		t.Errorf("Expected 1 active context after revocation, got %d", admin.ActiveCount())
	}
}

// TestIntegration_Rotation_GracefulHandoff tests graceful certificate handoff.
func TestIntegration_Rotation_GracefulHandoff(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue certificate with short validity
	shortCert, shortKey, err := testCA.IssueShortLivedCertificate("short-lived-client", 2*time.Hour)
	if err != nil {
		t.Fatalf("Failed to issue short-lived certificate: %v", err)
	}

	// Create admin
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](shortKey, testCA.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Set policy with expiry matching cert
	_ = admin.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   cert.NotAfter, // Context expires when cert expires
		}, nil
	})

	// Generate token
	assertion, _ := sctx.CreateAssertion(shortKey, shortCert)
	token, err := admin.Generate(ctx, shortCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Create guard
	guard, err := admin.CreateGuard(ctx, token, "read")
	if err != nil {
		t.Fatalf("Failed to create guard: %v", err)
	}

	// Should work now
	if err := guard.Validate(ctx, token); err != nil {
		t.Errorf("Guard validation should succeed: %v", err)
	}

	// Issue new certificate before old one expires
	newCert, newKey, err := testCA.IssueCertificate("short-lived-client")
	if err != nil {
		t.Fatalf("Failed to issue new certificate: %v", err)
	}

	// Generate new token
	newAssertion, _ := sctx.CreateAssertion(newKey, newCert)
	newToken, err := admin.Generate(ctx, newCert, newAssertion)
	if err != nil {
		t.Fatalf("Failed to generate new token: %v", err)
	}

	// Create new guard
	newGuard, err := admin.CreateGuard(ctx, newToken, "read")
	if err != nil {
		t.Fatalf("Failed to create new guard: %v", err)
	}

	// Both should work during overlap
	if err := guard.Validate(ctx, token); err != nil {
		t.Errorf("Old guard should still work during overlap: %v", err)
	}

	if err := newGuard.Validate(ctx, newToken); err != nil {
		t.Errorf("New guard should work: %v", err)
	}
}

// TestIntegration_Rotation_DifferentPermissions tests rotation with different permissions.
func TestIntegration_Rotation_DifferentPermissions(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue certificates
	readOnlyCert, readOnlyKey, err := testCA.IssueCertificate("permission-client")
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create admin with policy based on cert attributes
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](readOnlyKey, testCA.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Track which cert is being processed
	permissionMap := make(map[string][]string)
	permissionMap[readOnlyCert.SerialNumber.String()] = []string{"read"}

	_ = admin.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[any], error) {
		perms := permissionMap[cert.SerialNumber.String()]
		if perms == nil {
			perms = []string{"read", "write"} // Default for new certs
		}
		return &sctx.Context[any]{
			Permissions: perms,
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	// Generate read-only token
	readAssertion, _ := sctx.CreateAssertion(readOnlyKey, readOnlyCert)
	readToken, err := admin.Generate(ctx, readOnlyCert, readAssertion)
	if err != nil {
		t.Fatalf("Failed to generate read token: %v", err)
	}

	// Issue new certificate with write permission
	writeCert, writeKey, err := testCA.IssueCertificate("permission-client")
	if err != nil {
		t.Fatalf("Failed to issue write certificate: %v", err)
	}

	// Generate write token
	writeAssertion, _ := sctx.CreateAssertion(writeKey, writeCert)
	writeToken, err := admin.Generate(ctx, writeCert, writeAssertion)
	if err != nil {
		t.Fatalf("Failed to generate write token: %v", err)
	}

	// Read-only token should not be able to create write guard
	_, err = admin.CreateGuard(ctx, readToken, "write")
	if err == nil {
		t.Error("Read-only token should not create write guard")
	}

	// Write token should be able to create write guard
	writeGuard, err := admin.CreateGuard(ctx, writeToken, "write")
	if err != nil {
		t.Fatalf("Write token should create write guard: %v", err)
	}

	if err := writeGuard.Validate(ctx, writeToken); err != nil {
		t.Errorf("Write guard validation failed: %v", err)
	}
}
