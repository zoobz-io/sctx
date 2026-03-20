//go:build integration && testing

package integration

import (
	"context"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/zoobz-io/capitan"
	"github.com/zoobz-io/sctx"
	"github.com/zoobz-io/sctx/testing/integration/ca"
)

func TestMain(m *testing.M) {
	capitan.Configure(capitan.WithSyncMode())
	os.Exit(m.Run())
}

// TestIntegration_mTLS_BasicHandshake tests the complete mTLS authentication flow.
func TestIntegration_mTLS_BasicHandshake(t *testing.T) {
	ctx := context.Background()

	// Create standalone CA (faster than container)
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue client certificate
	clientCert, clientKey, err := testCA.IssueCertificate("test-client")
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create sctx admin with CA's root cert
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](clientKey, testCA.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Client creates assertion
	assertion, err := sctx.CreateAssertion(clientKey, clientCert)
	if err != nil {
		t.Fatalf("Failed to create assertion: %v", err)
	}

	// Admin generates token
	token, err := admin.Generate(ctx, clientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}

	// Verify token works with guard
	_ = admin.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	// Generate new token after setting policy
	assertion2, _ := sctx.CreateAssertion(clientKey, clientCert)
	token2, err := admin.Generate(ctx, clientCert, assertion2)
	if err != nil {
		t.Fatalf("Failed to generate token with policy: %v", err)
	}

	guard, err := admin.CreateGuard(ctx, token2, "read")
	if err != nil {
		t.Fatalf("Failed to create guard: %v", err)
	}

	err = guard.Validate(ctx, token2)
	if err != nil {
		t.Errorf("Guard validation failed: %v", err)
	}
}

// TestIntegration_mTLS_UntrustedCA tests rejection when cert is from untrusted CA.
func TestIntegration_mTLS_UntrustedCA(t *testing.T) {
	ctx := context.Background()

	// Create two separate CAs
	trustedCA, err := ca.NewStandaloneCA("Trusted Root CA")
	if err != nil {
		t.Fatalf("Failed to create trusted CA: %v", err)
	}

	untrustedCA, err := ca.NewStandaloneCA("Untrusted Root CA")
	if err != nil {
		t.Fatalf("Failed to create untrusted CA: %v", err)
	}

	// Issue client certificate from UNTRUSTED CA
	clientCert, clientKey, err := untrustedCA.IssueCertificate("untrusted-client")
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create admin that only trusts the TRUSTED CA
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](clientKey, trustedCA.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Client creates assertion with untrusted cert
	assertion, err := sctx.CreateAssertion(clientKey, clientCert)
	if err != nil {
		t.Fatalf("Failed to create assertion: %v", err)
	}

	// Should fail - certificate not trusted
	_, err = admin.Generate(ctx, clientCert, assertion)
	if err == nil {
		t.Error("Expected error for untrusted certificate, got nil")
	}
}

// TestIntegration_mTLS_ExpiredCert tests rejection when cert has expired.
func TestIntegration_mTLS_ExpiredCert(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue expired certificate
	clientCert, clientKey, err := testCA.IssueExpiredCertificate("expired-client")
	if err != nil {
		t.Fatalf("Failed to issue expired certificate: %v", err)
	}

	// Create admin
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](clientKey, testCA.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Client creates assertion with expired cert
	assertion, err := sctx.CreateAssertion(clientKey, clientCert)
	if err != nil {
		t.Fatalf("Failed to create assertion: %v", err)
	}

	// Should fail - certificate expired
	_, err = admin.Generate(ctx, clientCert, assertion)
	if err == nil {
		t.Error("Expected error for expired certificate, got nil")
	}
}

// TestIntegration_mTLS_MultipleClients tests multiple clients authenticating.
func TestIntegration_mTLS_MultipleClients(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue certificates for multiple clients
	client1Cert, client1Key, err := testCA.IssueCertificate("client-1")
	if err != nil {
		t.Fatalf("Failed to issue certificate for client 1: %v", err)
	}

	client2Cert, client2Key, err := testCA.IssueCertificate("client-2")
	if err != nil {
		t.Fatalf("Failed to issue certificate for client 2: %v", err)
	}

	// Create admin (use client1Key as admin key)
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](client1Key, testCA.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Both clients should be able to generate tokens
	assertion1, _ := sctx.CreateAssertion(client1Key, client1Cert)
	token1, err := admin.Generate(ctx, client1Cert, assertion1)
	if err != nil {
		t.Fatalf("Failed to generate token for client 1: %v", err)
	}

	assertion2, _ := sctx.CreateAssertion(client2Key, client2Cert)
	token2, err := admin.Generate(ctx, client2Cert, assertion2)
	if err != nil {
		t.Fatalf("Failed to generate token for client 2: %v", err)
	}

	if token1 == token2 {
		t.Error("Tokens for different clients should be different")
	}

	// Verify active count
	if admin.ActiveCount() != 2 {
		t.Errorf("Expected 2 active contexts, got %d", admin.ActiveCount())
	}
}

// TestIntegration_mTLS_CertificateAttributes tests that certificate attributes are captured.
func TestIntegration_mTLS_CertificateAttributes(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue certificate with specific attributes
	clientCert, clientKey, err := testCA.IssueCertificate("attribute-test-client",
		ca.WithDNSNames("test.example.com", "api.example.com"),
	)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create admin with policy that extracts certificate info
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](clientKey, testCA.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Set policy that captures cert info
	var capturedCert *x509.Certificate
	_ = admin.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[any], error) {
		capturedCert = cert
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	// Generate token
	assertion, _ := sctx.CreateAssertion(clientKey, clientCert)
	_, err = admin.Generate(ctx, clientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Verify certificate attributes were captured
	if capturedCert == nil {
		t.Fatal("Certificate was not captured by policy")
	}

	if capturedCert.Subject.CommonName != "attribute-test-client" {
		t.Errorf("Expected CN 'attribute-test-client', got %q", capturedCert.Subject.CommonName)
	}

	if len(capturedCert.DNSNames) != 2 {
		t.Errorf("Expected 2 DNS names, got %d", len(capturedCert.DNSNames))
	}
}

// TestIntegration_mTLS_RepeatedAuth tests repeated authentication with same cert.
func TestIntegration_mTLS_RepeatedAuth(t *testing.T) {
	ctx := context.Background()

	// Create CA
	testCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Issue certificate
	clientCert, clientKey, err := testCA.IssueCertificate("repeat-client")
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create admin
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[any](clientKey, testCA.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Generate multiple tokens with same cert
	var tokens []sctx.SignedToken
	for i := 0; i < 5; i++ {
		assertion, _ := sctx.CreateAssertion(clientKey, clientCert)
		token, err := admin.Generate(ctx, clientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token %d: %v", i, err)
		}
		tokens = append(tokens, token)
	}

	// All tokens should work (cached context)
	if admin.ActiveCount() != 1 {
		t.Errorf("Expected 1 active context (cached), got %d", admin.ActiveCount())
	}
}
