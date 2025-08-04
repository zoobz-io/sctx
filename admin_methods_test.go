package sctx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"slices"
	"testing"
)

// TestAdminPublicKeyAndAlgorithm tests PublicKey and Algorithm methods
func TestAdminPublicKeyAndAlgorithm(t *testing.T) {
	testCerts := GenerateTestCertificates(t)

	t.Run("Ed25519", func(t *testing.T) {
		_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
		admin, err := NewAdminService[any](privateKey, testCerts.CertPool)
		if err != nil {
			t.Fatalf("Failed to create admin service: %v", err)
		}

		adminSvc := admin.(*adminService[any])

		// Test PublicKey
		pubKey := adminSvc.PublicKey()
		if pubKey == nil {
			t.Error("PublicKey() should not return nil")
		}

		// Verify it matches the signer's public key
		if !publicKeysEqual(pubKey, adminSvc.signer.PublicKey()) {
			t.Error("PublicKey() should return signer's public key")
		}

		// Test Algorithm
		algo := adminSvc.Algorithm()
		if algo != CryptoEd25519 {
			t.Errorf("Expected algorithm %s, got %s", CryptoEd25519, algo)
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		// Generate ECDSA key
		_, privateKey, _ := GenerateKeyPair(CryptoECDSAP256)
		admin, err := NewAdminService[any](privateKey, testCerts.CertPool)
		if err != nil {
			t.Fatalf("Failed to create admin service: %v", err)
		}

		adminSvc := admin.(*adminService[any])

		// Test Algorithm
		algo := adminSvc.Algorithm()
		if algo != CryptoECDSAP256 {
			t.Errorf("Expected algorithm %s, got %s", CryptoECDSAP256, algo)
		}
	})
}

// TestAdminActiveCount tests the ActiveCount method
func TestAdminActiveCount(t *testing.T) {
	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)

	adminSvc := admin.(*adminService[any])

	// Configure pipeline first
	err := admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
`)
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}

	// Test with default memory cache
	count := adminSvc.ActiveCount()
	if count != 0 {
		t.Errorf("Expected 0 active contexts, got %d", count)
	}

	// Generate a token to add context
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	_, err = admin.Generate(testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Check count increased
	count = adminSvc.ActiveCount()
	if count != 1 {
		t.Errorf("Expected 1 active context, got %d", count)
	}

	// Test with cache that doesn't implement Count
	type minimalCache struct {
		ContextCache[any]
	}
	mockCache := &minimalCache{adminSvc.cache}
	adminSvc.cache = mockCache

	count = adminSvc.ActiveCount()
	if count != -1 {
		t.Errorf("Expected -1 for unknown count, got %d", count)
	}
}

// TestAdminRegisterProcessor tests the RegisterProcessor method
func TestAdminRegisterProcessor(t *testing.T) {
	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)

	adminSvc := admin.(*adminService[any])

	// Register a custom processor
	customProcessorCalled := false
	customProcessor := func(ctx context.Context, c *Context[any]) (*Context[any], error) {
		customProcessorCalled = true
		c.Permissions = append(c.Permissions, "custom-permission")
		return c, nil
	}

	adminSvc.RegisterProcessor("custom-processor", customProcessor)

	// Use it in a schema
	err := admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: custom-processor
`)
	if err != nil {
		t.Fatalf("Failed to load schema with custom processor: %v", err)
	}

	// Generate token and verify custom processor was called
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	_, err = admin.Generate(testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if !customProcessorCalled {
		t.Error("Custom processor was not called")
	}

	// Verify the permission was added
	fingerprint := getFingerprint(testCerts.ClientCert)
	ctx, exists := adminSvc.cache.Get(fingerprint)
	if !exists {
		t.Fatal("Context not found in cache")
	}

	if !slices.Contains(ctx.Permissions, "custom-permission") {
		t.Error("Custom permission was not added")
	}
}

// TestAdminSetCache tests the SetCache method
func TestAdminSetCache(t *testing.T) {
	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)

	adminSvc := admin.(*adminService[any])

	// Test setting nil cache
	err := adminSvc.SetCache(nil)
	if err == nil {
		t.Error("Setting nil cache should return error")
	}

	// Create a custom cache implementation
	type customCache struct {
		ContextCache[any]
	}

	custom := &customCache{
		ContextCache: adminSvc.cache,
	}

	// Override Store method to track calls
	custom.ContextCache = &struct {
		ContextCache[any]
		parent *customCache
	}{
		ContextCache: adminSvc.cache,
		parent:       custom,
	}

	err = adminSvc.SetCache(custom)
	if err != nil {
		t.Errorf("Failed to set custom cache: %v", err)
	}

	// Verify cache was replaced
	if adminSvc.cache != custom {
		t.Error("Cache was not replaced")
	}
}

// TestAdminLoadContextSchemaFromFile tests loading schema from file
func TestAdminLoadContextSchemaFromFile(t *testing.T) {
	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)

	adminSvc := admin.(*adminService[any])

	// Create a temporary schema file
	schemaContent := `
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
  - ref: grant-write
`
	tmpFile, err := os.CreateTemp("", "schema-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(schemaContent); err != nil {
		t.Fatalf("Failed to write schema file: %v", err)
	}
	tmpFile.Close()

	// Test loading from file
	err = adminSvc.LoadContextSchemaFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load schema from file: %v", err)
	}

	// Verify pipeline works
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	token, err := admin.Generate(testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Error("Generated token is empty")
	}

	// Test loading from non-existent file
	err = adminSvc.LoadContextSchemaFromFile("/non/existent/file.yaml")
	if err == nil {
		t.Error("Loading from non-existent file should fail")
	}
}
