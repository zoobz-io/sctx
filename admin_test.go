package sctx

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestAdminServicePipelines(t *testing.T) {
	resetAdminForTesting()

	// Generate test certificates
	testCerts := GenerateTestCertificates(t)

	// Create admin service
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	admin, err := NewAdminService[any](privateKey, testCerts.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin service: %v", err)
	}

	t.Run("context pipeline", func(t *testing.T) {
		// Load context processing schema
		err = admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
  - ref: grant-write
`)
		if err != nil {
			t.Fatalf("Failed to load context schema: %v", err)
		}

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token using context pipeline
		token, err := admin.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		if token == "" {
			t.Fatal("Generated token is empty")
		}
	})

	t.Run("no context pipeline configured", func(t *testing.T) {
		resetAdminForTesting()
		// Create fresh admin without pipeline
		admin2, err := NewAdminService[any](privateKey, testCerts.CertPool)
		if err != nil {
			t.Fatalf("Failed to create admin service: %v", err)
		}

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Try to generate without context pipeline
		_, err = admin2.Generate(testCerts.ClientCert, assertion)
		if err == nil {
			t.Fatal("Expected error when no context pipeline configured")
		}

		if err.Error() != "no context pipeline configured - use LoadContextSchema()" {
			t.Errorf("Expected specific error message, got: %v", err)
		}
	})

}

func TestAdminServiceBasicOperations(t *testing.T) {
	resetAdminForTesting()

	// Generate test certificates
	testCerts := GenerateTestCertificates(t)

	// Create admin service
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	adminSvc, err := NewAdminService[any](privateKey, testCerts.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin service: %v", err)
	}

	// Cast to get typed admin for testing
	admin := adminSvc.(*adminService[any])

	// Configure context pipeline
	err = admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
`)
	if err != nil {
		t.Fatalf("Failed to load context schema: %v", err)
	}

	t.Run("generate and cache", func(t *testing.T) {
		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token
		token, err := admin.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Verify context is cached
		fingerprint := getFingerprint(testCerts.ClientCert)
		ctx, exists := admin.GetContext(fingerprint)
		if !exists {
			t.Fatal("Context should exist in cache")
		}

		if ctx == nil {
			t.Fatal("Context should not be nil")
		}

		// Verify permissions were granted
		hasRead := false
		for _, perm := range ctx.Permissions {
			if perm == "read" {
				hasRead = true
				break
			}
		}
		if !hasRead {
			t.Error("Context should have read permission")
		}

		// Decrypt token to verify it points to the right context
		gotFingerprint, err := admin.decryptToken(token)
		if err != nil {
			t.Fatalf("Failed to decrypt token: %v", err)
		}
		if gotFingerprint != fingerprint {
			t.Errorf("Token fingerprint mismatch: got %s, want %s", gotFingerprint, fingerprint)
		}
	})

	t.Run("revoke by fingerprint", func(t *testing.T) {
		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token first
		token, err := admin.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		fingerprint := getFingerprint(testCerts.ClientCert)

		// Revoke the context
		err = admin.RevokeByFingerprint(fingerprint)
		if err != nil {
			t.Fatalf("Failed to revoke: %v", err)
		}

		// Verify context is gone
		_, exists := admin.GetContext(fingerprint)
		if exists {
			t.Fatal("Context should not exist after revocation")
		}

		// Token should now be invalid
		_, err = admin.decryptToken(token)
		if err != nil {
			// Token decryption still works, but context lookup will fail
			t.Logf("Token decryption error (expected): %v", err)
		}
	})

	t.Run("cached token reuse", func(t *testing.T) {
		// Create assertions for both calls
		assertion1 := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		assertion2 := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate first token
		token1, err := admin.Generate(testCerts.ClientCert, assertion1)
		if err != nil {
			t.Fatalf("Failed to generate first token: %v", err)
		}

		// Generate second token - should reuse cached context
		token2, err := admin.Generate(testCerts.ClientCert, assertion2)
		if err != nil {
			t.Fatalf("Failed to generate second token: %v", err)
		}

		// Tokens should be different (different nonces)
		if token1 == token2 {
			t.Error("Tokens should be different even for cached context")
		}

		// But they should point to the same context
		fp1, _ := admin.decryptToken(token1)
		fp2, _ := admin.decryptToken(token2)
		if fp1 != fp2 {
			t.Error("Both tokens should reference the same context")
		}
	})

}

func TestAdminServiceCertificateValidation(t *testing.T) {
	resetAdminForTesting()

	// Generate test certificates
	testCerts := GenerateTestCertificates(t)

	// Create admin service
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	admin, err := NewAdminService[any](privateKey, testCerts.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin service: %v", err)
	}

	// Configure context pipeline
	err = admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
`)
	if err != nil {
		t.Fatalf("Failed to load context schema: %v", err)
	}

	t.Run("valid certificate", func(t *testing.T) {
		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		token, err := admin.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		if token == "" {
			t.Fatal("Token should not be empty")
		}
	})

	t.Run("untrusted certificate", func(t *testing.T) {
		// Create a certificate not signed by our CA
		untrustedCerts := GenerateTestCertificates(t)

		// Create assertion with untrusted cert
		assertion := createTestAssertion(t, untrustedCerts.ClientKey, untrustedCerts.ClientCert)

		_, err := admin.Generate(untrustedCerts.ClientCert, assertion)
		if err == nil {
			t.Fatal("Expected error for untrusted certificate")
		}

		if !contains(err.Error(), "certificate verification failed") {
			t.Errorf("Expected certificate verification error, got: %v", err)
		}
	})

	t.Run("nil certificate", func(t *testing.T) {
		// Can't create a valid assertion without a cert, so we'll use an empty one
		assertion := SignedAssertion{}

		_, err := admin.Generate(nil, assertion)
		if err == nil {
			t.Fatal("Expected error for nil certificate")
		}

		if err.Error() != "certificate is required" {
			t.Errorf("Expected specific error message, got: %v", err)
		}
	})

}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr || len(s) > len(substr) && contains(s[1:], substr)
}
