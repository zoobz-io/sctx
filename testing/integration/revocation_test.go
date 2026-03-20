//go:build integration && testing

package integration

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/zoobz-io/capitan"
	"github.com/zoobz-io/sctx"
	"github.com/zoobz-io/sctx/testing/integration/ca"
)

// TestIntegration_Revocation_ImmediateInvalidation tests immediate context invalidation.
func TestIntegration_Revocation_ImmediateInvalidation(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue certificate
	clientCert, clientKey, err := testCA.IssueCertificate("revocation-client")
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create admin
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](clientKey, testCA.CertPool)
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

	// Generate token
	assertion, _ := sctx.CreateAssertion(clientKey, clientCert)
	token, err := admin.Generate(ctx, clientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Create guard
	guard, err := admin.CreateGuard(ctx, token, "read")
	if err != nil {
		t.Fatalf("Failed to create guard: %v", err)
	}

	// Verify guard works
	if err := guard.Validate(ctx, token); err != nil {
		t.Fatalf("Guard validation should succeed before revocation: %v", err)
	}

	// Revoke context
	fingerprint := sctx.GetFingerprint(clientCert)
	err = admin.RevokeByFingerprint(ctx, fingerprint)
	if err != nil {
		t.Fatalf("Failed to revoke context: %v", err)
	}

	// Guard should immediately fail
	err = guard.Validate(ctx, token)
	if err == nil {
		t.Error("Guard validation should fail after revocation")
	}

	// Active count should be 0
	if admin.ActiveCount() != 0 {
		t.Errorf("Expected 0 active contexts after revocation, got %d", admin.ActiveCount())
	}
}

// TestIntegration_Revocation_GuardBehavior tests guard behavior after revocation.
func TestIntegration_Revocation_GuardBehavior(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue certificate
	clientCert, clientKey, err := testCA.IssueCertificate("guard-behavior-client")
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create admin
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](clientKey, testCA.CertPool)
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

	// Generate token
	assertion, _ := sctx.CreateAssertion(clientKey, clientCert)
	token, err := admin.Generate(ctx, clientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Create multiple guards
	readGuard, _ := admin.CreateGuard(ctx, token, "read")
	writeGuard, _ := admin.CreateGuard(ctx, token, "write")

	// Both guards should work
	if err := readGuard.Validate(ctx, token); err != nil {
		t.Fatalf("Read guard should work: %v", err)
	}
	if err := writeGuard.Validate(ctx, token); err != nil {
		t.Fatalf("Write guard should work: %v", err)
	}

	// Revoke context
	fingerprint := sctx.GetFingerprint(clientCert)
	_ = admin.RevokeByFingerprint(ctx, fingerprint)

	// Both guards should fail
	if readGuard.Validate(ctx, token) == nil {
		t.Error("Read guard should fail after revocation")
	}
	if writeGuard.Validate(ctx, token) == nil {
		t.Error("Write guard should fail after revocation")
	}
}

// TestIntegration_Revocation_EventEmission tests event emission during revocation.
func TestIntegration_Revocation_EventEmission(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue certificate
	clientCert, clientKey, err := testCA.IssueCertificate("event-emission-client")
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create admin
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](clientKey, testCA.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Generate token
	assertion, _ := sctx.CreateAssertion(clientKey, clientCert)
	_, _ = admin.Generate(ctx, clientCert, assertion)

	// Set up event capture for revocation
	var revokedFingerprint string
	listener := capitan.Hook(sctx.ContextRevoked, func(_ context.Context, e *capitan.Event) {
		revokedFingerprint, _ = sctx.FingerprintKey.From(e)
	})
	defer listener.Close()

	// Revoke context
	fingerprint := sctx.GetFingerprint(clientCert)
	_ = admin.RevokeByFingerprint(ctx, fingerprint)

	// Verify event was emitted with correct fingerprint
	if revokedFingerprint != fingerprint {
		t.Errorf("Expected revoked fingerprint %q, got %q", fingerprint, revokedFingerprint)
	}
}

// TestIntegration_Revocation_MultipleContexts tests revoking one of multiple contexts.
func TestIntegration_Revocation_MultipleContexts(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue multiple certificates
	client1Cert, client1Key, _ := testCA.IssueCertificate("multi-client-1")
	client2Cert, client2Key, _ := testCA.IssueCertificate("multi-client-2")
	client3Cert, client3Key, _ := testCA.IssueCertificate("multi-client-3")

	// Create admin
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](client1Key, testCA.CertPool)
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

	// Generate tokens for all clients
	assertion1, _ := sctx.CreateAssertion(client1Key, client1Cert)
	token1, _ := admin.Generate(ctx, client1Cert, assertion1)
	guard1, _ := admin.CreateGuard(ctx, token1, "read")

	assertion2, _ := sctx.CreateAssertion(client2Key, client2Cert)
	token2, _ := admin.Generate(ctx, client2Cert, assertion2)
	guard2, _ := admin.CreateGuard(ctx, token2, "read")

	assertion3, _ := sctx.CreateAssertion(client3Key, client3Cert)
	token3, _ := admin.Generate(ctx, client3Cert, assertion3)
	guard3, _ := admin.CreateGuard(ctx, token3, "read")

	// Verify all contexts exist
	if admin.ActiveCount() != 3 {
		t.Fatalf("Expected 3 active contexts, got %d", admin.ActiveCount())
	}

	// Revoke client2's context only
	_ = admin.RevokeByFingerprint(ctx, sctx.GetFingerprint(client2Cert))

	// Client1 and Client3 should still work
	if err := guard1.Validate(ctx, token1); err != nil {
		t.Errorf("Guard1 should still work: %v", err)
	}
	if err := guard3.Validate(ctx, token3); err != nil {
		t.Errorf("Guard3 should still work: %v", err)
	}

	// Client2 should fail
	if guard2.Validate(ctx, token2) == nil {
		t.Error("Guard2 should fail after revocation")
	}

	// Active count should be 2
	if admin.ActiveCount() != 2 {
		t.Errorf("Expected 2 active contexts, got %d", admin.ActiveCount())
	}
}

// TestIntegration_Revocation_RevokeNonexistent tests revoking a non-existent context.
func TestIntegration_Revocation_RevokeNonexistent(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue certificate but don't generate a token for it
	_, clientKey, err := testCA.IssueCertificate("nonexistent-client")
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create admin
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](clientKey, testCA.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Try to revoke a context that doesn't exist
	err = admin.RevokeByFingerprint(ctx, "nonexistent-fingerprint")
	// Should not error - just a no-op
	if err != nil {
		t.Errorf("Revoking non-existent context should not error: %v", err)
	}
}

// TestIntegration_Revocation_ReauthAfterRevoke tests re-authentication after revocation.
func TestIntegration_Revocation_ReauthAfterRevoke(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue certificate
	clientCert, clientKey, err := testCA.IssueCertificate("reauth-client")
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create admin
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](clientKey, testCA.CertPool)
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

	// Generate first token
	assertion1, _ := sctx.CreateAssertion(clientKey, clientCert)
	token1, _ := admin.Generate(ctx, clientCert, assertion1)
	guard1, _ := admin.CreateGuard(ctx, token1, "read")

	// Verify it works
	if err := guard1.Validate(ctx, token1); err != nil {
		t.Fatalf("Guard1 should work: %v", err)
	}

	// Revoke
	_ = admin.RevokeByFingerprint(ctx, sctx.GetFingerprint(clientCert))

	// Verify it fails
	if guard1.Validate(ctx, token1) == nil {
		t.Error("Guard1 should fail after revocation")
	}

	// Re-authenticate with same cert
	assertion2, _ := sctx.CreateAssertion(clientKey, clientCert)
	token2, err := admin.Generate(ctx, clientCert, assertion2)
	if err != nil {
		t.Fatalf("Re-authentication should succeed: %v", err)
	}

	// New guard with new token should work
	guard2, _ := admin.CreateGuard(ctx, token2, "read")
	if err := guard2.Validate(ctx, token2); err != nil {
		t.Errorf("Guard2 should work after re-authentication: %v", err)
	}

	// Old guard with new token should fail (guard bound to creator)
	if guard1.Validate(ctx, token2) == nil {
		t.Error("Old guard should not work with new token (different context)")
	}
}
