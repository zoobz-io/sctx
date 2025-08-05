package sctx

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestFlumeIntegration(t *testing.T) {
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

	t.Run("basic schema loading", func(t *testing.T) {
		// Test basic schema loading with one processor
		err = admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
`)
		if err != nil {
			t.Fatalf("Failed to load basic context schema: %v", err)
		}

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token using schema pipeline
		token, err := admin.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		if token == "" {
			t.Fatal("Generated token is empty")
		}
	})

	t.Run("complex schema with permissions", func(t *testing.T) {
		resetAdminForTesting()
		// Create fresh admin for this test
		admin2, err := NewAdminService[any](privateKey, testCerts.CertPool)
		if err != nil {
			t.Fatalf("Failed to create admin service: %v", err)
		}

		// Test more complex schema with multiple processors
		err = admin2.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
  - ref: grant-write
  - ref: grant-create-guard
`)
		if err != nil {
			t.Fatalf("Failed to load complex context schema: %v", err)
		}

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token using complex pipeline
		token, err := admin2.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token with complex schema: %v", err)
		}

		if token == "" {
			t.Fatal("Generated token is empty")
		}

		// Check what permissions were actually granted
		fingerprint := getFingerprint(testCerts.ClientCert)
		adminSvc := admin2.(*adminService[any])
		ctx, exists := adminSvc.GetContext(fingerprint)
		if !exists {
			t.Fatal("Context should exist in cache")
		}

		t.Logf("Granted permissions: %v", ctx.Permissions)

		// Create a guard to test permissions were granted (should work since we granted create-guard)
		guard, err := admin2.CreateGuard(token, "read", "write")
		if err != nil {
			t.Fatalf("Failed to create guard: %v", err)
		}

		if guard == nil {
			t.Fatal("Guard is nil")
		}
	})

	t.Run("invalid schema", func(t *testing.T) {
		// Test invalid schema
		err = admin.LoadContextSchema(`
type: sequence
children:
  - ref: nonexistent-processor
`)
		if err == nil {
			t.Fatal("Expected error for invalid schema")
		}
	})

	t.Run("no pipeline configured", func(t *testing.T) {
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

	t.Run("fallback schema", func(t *testing.T) {
		// Test fallback pattern for graceful degradation
		err = admin.LoadContextSchema(`
type: fallback
children:
  - type: sequence
    children:
      - ref: set-expiry-1h
      - ref: grant-admin
  - type: sequence
    children:
      - ref: set-expiry-5m
      - ref: grant-read
`)
		if err != nil {
			t.Fatalf("Failed to load fallback context schema: %v", err)
		}

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token using fallback pipeline (should use first path)
		token, err := admin.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token with fallback schema: %v", err)
		}

		if token == "" {
			t.Fatal("Generated token is empty")
		}
	})
}

func TestProcessorConstants(t *testing.T) {
	// Test that all processor constants are defined and unique
	processors := []string{
		ProcessorSetExpiryOneHour,
		ProcessorSetExpiryFiveMinutes,
		ProcessorGrantRead,
		ProcessorGrantWrite,
		ProcessorGrantAdmin,
		ProcessorGrantCreateGuard,
	}

	// Check all constants are non-empty
	for _, proc := range processors {
		if proc == "" {
			t.Error("Processor constant is empty")
		}
	}

	// Check all constants are unique
	seen := make(map[string]bool)
	for _, proc := range processors {
		if seen[proc] {
			t.Errorf("Duplicate processor constant: %s", proc)
		}
		seen[proc] = true
	}
}
