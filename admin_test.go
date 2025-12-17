package sctx

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
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
		// Set context processing policy
		err = admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
			return &Context[any]{
				CertificateInfo:        extractCertificateInfo(cert),
				CertificateFingerprint: getFingerprint(cert),
				IssuedAt:               time.Now(),
				ExpiresAt:              time.Now().Add(time.Hour),
				Permissions:            []string{"read", "write"},
			}, nil
		})
		if err != nil {
			t.Fatalf("Failed to set context policy: %v", err)
		}

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token using context pipeline
		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		if token == "" {
			t.Fatal("Generated token is empty")
		}
	})

	t.Run("default context pipeline configured", func(t *testing.T) {
		resetAdminForTesting()
		// Create fresh admin - now has default pipeline
		admin2, err := NewAdminService[any](privateKey, testCerts.CertPool)
		if err != nil {
			t.Fatalf("Failed to create admin service: %v", err)
		}

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Should work with default pipeline
		token, err := admin2.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Should work with default pipeline: %v", err)
		}

		if token == "" {
			t.Error("Token should not be empty")
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

	// Configure context policy
	err = admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(time.Hour),
			Permissions:            []string{"read"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set context policy: %v", err)
	}

	t.Run("generate and cache", func(t *testing.T) {
		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token
		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Verify context is cached
		fingerprint := getFingerprint(testCerts.ClientCert)
		ctx, exists := admin.GetContext(context.Background(), fingerprint)
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
		gotFingerprint, err := admin.decryptToken(context.Background(), token)
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
		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		fingerprint := getFingerprint(testCerts.ClientCert)

		// Revoke the context
		err = admin.RevokeByFingerprint(context.Background(), fingerprint)
		if err != nil {
			t.Fatalf("Failed to revoke: %v", err)
		}

		// Verify context is gone
		_, exists := admin.GetContext(context.Background(), fingerprint)
		if exists {
			t.Fatal("Context should not exist after revocation")
		}

		// Token should now be invalid
		_, err = admin.decryptToken(context.Background(), token)
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
		token1, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion1)
		if err != nil {
			t.Fatalf("Failed to generate first token: %v", err)
		}

		// Generate second token - should reuse cached context
		token2, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion2)
		if err != nil {
			t.Fatalf("Failed to generate second token: %v", err)
		}

		// Tokens should be different (different nonces)
		if token1 == token2 {
			t.Error("Tokens should be different even for cached context")
		}

		// But they should point to the same context
		fp1, _ := admin.decryptToken(context.Background(), token1)
		fp2, _ := admin.decryptToken(context.Background(), token2)
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

	// Configure context policy
	err = admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(time.Hour),
			Permissions:            []string{},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set context policy: %v", err)
	}

	t.Run("valid certificate", func(t *testing.T) {
		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
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

		_, err := admin.Generate(context.Background(), untrustedCerts.ClientCert, assertion)
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

		_, err := admin.Generate(context.Background(), nil, assertion)
		if err == nil {
			t.Fatal("Expected error for nil certificate")
		}

		if err.Error() != "certificate is required" {
			t.Errorf("Expected specific error message, got: %v", err)
		}
	})

}

// TestAdminPublicKeyAndAlgorithm tests PublicKey and Algorithm methods.
func TestAdminPublicKeyAndAlgorithm(t *testing.T) {
	resetAdminForTesting()
	testCerts := GenerateTestCertificates(t)

	t.Run("Ed25519", func(t *testing.T) {
		resetAdminForTesting()
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
		resetAdminForTesting()
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

// TestAdminActiveCount tests the ActiveCount method.
func TestAdminActiveCount(t *testing.T) {
	resetAdminForTesting()
	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)

	adminSvc := admin.(*adminService[any])

	// Configure policy first
	err := admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(time.Hour),
			Permissions:            []string{"read"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set policy: %v", err)
	}

	// Test with default memory cache
	count := adminSvc.ActiveCount()
	if count != 0 {
		t.Errorf("Expected 0 active contexts, got %d", count)
	}

	// Generate a token to add context
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	_, err = admin.Generate(context.Background(), testCerts.ClientCert, assertion)
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

// TestAdminCustomPolicy tests using a custom policy function.
func TestAdminCustomPolicy(t *testing.T) {
	resetAdminForTesting()
	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)

	adminSvc := admin.(*adminService[any])

	// Set a custom policy
	customPolicyCalled := false
	err := admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
		customPolicyCalled = true
		return &Context[any]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(time.Hour),
			Permissions:            []string{"custom-permission"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set custom policy: %v", err)
	}

	// Generate token and verify custom policy was called
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	_, err = admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if !customPolicyCalled {
		t.Error("Custom policy was not called")
	}

	// Verify the permission was added
	fingerprint := getFingerprint(testCerts.ClientCert)
	ctx, exists := adminSvc.cache.Get(context.Background(), fingerprint)
	if !exists {
		t.Fatal("Context not found in cache")
	}

	if !slices.Contains(ctx.Permissions, "custom-permission") {
		t.Error("Custom permission was not added")
	}
}

// TestAdminSetCache tests the SetCache method.
func TestAdminSetCache(t *testing.T) {
	resetAdminForTesting()
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

// TestAdminPolicyReturnsError tests when policy returns an error.
func TestAdminPolicyReturnsError(t *testing.T) {
	resetAdminForTesting()
	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)

	// Set a policy that returns an error
	err := admin.SetPolicy(func(_ *x509.Certificate) (*Context[any], error) {
		return nil, errors.New("policy error")
	})
	if err != nil {
		t.Fatalf("Failed to set policy: %v", err)
	}

	// Generate token should fail with policy error
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	_, err = admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err == nil {
		t.Error("Expected error from policy")
	}
	if !strings.Contains(err.Error(), "policy failed") {
		t.Errorf("Expected policy failed error, got: %v", err)
	}
}

func TestBasicPolicyFunction(t *testing.T) {
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

	// Set a custom policy
	err = admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(time.Hour),
			Permissions:            []string{"read", "write", "admin"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set policy: %v", err)
	}

	// Create assertion
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

	// Generate token
	token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Fatal("Generated token is empty")
	}

	// Verify the token works
	_, err = admin.CreateGuard(context.Background(), token, "read")
	if err != nil {
		t.Fatalf("Failed to create guard: %v", err)
	}
}

// TestCrossServiceTokenValidation tests how tokens and guards behave across different admin instances.
func TestCrossServiceTokenValidation(t *testing.T) {
	// This test explores whether tokens from one admin service can be validated by guards from another
	// This scenario could happen when different microservices each have their own admin instance

	t.Run("SingletonEnforcement", func(t *testing.T) {
		resetAdminForTesting()

		// Generate test certificates and keys
		testCerts := GenerateTestCertificates(t)
		_, privateKey1, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key1: %v", err)
		}

		// Create first admin service
		admin1, err := NewAdminService[any](privateKey1, testCerts.CertPool)
		if err != nil {
			t.Fatalf("Failed to create first admin service: %v", err)
		}

		// Try to create second admin service - should fail due to singleton
		_, privateKey2, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key2: %v", err)
		}

		admin2, err := NewAdminService[any](privateKey2, testCerts.CertPool)
		if !errors.Is(err, ErrAdminAlreadyCreated) {
			t.Errorf("Expected ErrAdminAlreadyCreated, got: %v", err)
		}
		if admin2 != nil {
			t.Error("Second admin instance should be nil")
		}

		// First admin should still work
		if admin1 == nil {
			t.Fatal("First admin should not be nil")
		}
	})

	t.Run("SimulatedCrossServiceScenario", func(t *testing.T) {
		// Simulate what would happen if services with different admin instances tried to interact
		// This requires testing cache isolation and token portability

		// Service A setup
		resetAdminForTesting()
		testCertsA := GenerateTestCertificates(t)
		_, privateKeyA, _ := ed25519.GenerateKey(rand.Reader)
		adminA, err := NewAdminService[any](privateKeyA, testCertsA.CertPool)
		if err != nil {
			t.Fatalf("Failed to create admin A: %v", err)
		}

		// Configure admin A
		err = adminA.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
			return &Context[any]{
				CertificateInfo:        extractCertificateInfo(cert),
				CertificateFingerprint: getFingerprint(cert),
				IssuedAt:               time.Now(),
				ExpiresAt:              time.Now().Add(time.Hour),
				Permissions:            []string{"read", "admin", "create-guard"},
			}, nil
		})
		if err != nil {
			t.Fatalf("Failed to set policy: %v", err)
		}

		// Generate token from admin A
		assertionA := createTestAssertion(t, testCertsA.ClientKey, testCertsA.ClientCert)
		tokenA, err := adminA.Generate(context.Background(), testCertsA.ClientCert, assertionA)
		if err != nil {
			t.Fatalf("Failed to generate token A: %v", err)
		}

		// Create guard from admin A
		adminA.SetGuardCreationPermissions([]string{"create-guard"})
		guardA, err := adminA.CreateGuard(context.Background(), tokenA, "read")
		if err != nil {
			t.Fatalf("Failed to create guard A: %v", err)
		}

		// Validate token with its own guard - should work
		if err := guardA.Validate(context.Background(), tokenA); err != nil {
			t.Errorf("Guard A should validate token A: %v", err)
		}

		// Now simulate Service B trying to use the same infrastructure
		// In real scenario, this would be a different process with its own admin
		// but due to singleton, we can't create another admin in same process

		// Instead, let's test what happens with different CA pools
		testCertsB := GenerateTestCertificatesWithDifferentCA(t)

		// Try to validate a token from a different certificate chain
		assertionB := createTestAssertion(t, testCertsB.ClientKey, testCertsB.ClientCert)
		_, err = adminA.Generate(context.Background(), testCertsB.ClientCert, assertionB)
		if err == nil {
			t.Error("Should not be able to generate token for certificate from different CA")
		}
	})

	t.Run("CacheIsolationBetweenAdmins", func(t *testing.T) {
		// Test that cache is tied to admin instance
		resetAdminForTesting()
		testCerts := GenerateTestCertificates(t)
		_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

		admin, err := NewAdminService[any](privateKey, testCerts.CertPool)
		if err != nil {
			t.Fatalf("Failed to create admin: %v", err)
		}

		// Cast to access internal methods
		adminImpl := admin.(*adminService[any])

		// Configure and generate token
		err = admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
			return &Context[any]{
				CertificateInfo:        extractCertificateInfo(cert),
				CertificateFingerprint: getFingerprint(cert),
				IssuedAt:               time.Now(),
				ExpiresAt:              time.Now().Add(time.Hour),
				Permissions:            []string{"read"},
			}, nil
		})
		if err != nil {
			t.Fatalf("Failed to set policy: %v", err)
		}

		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Check cache has the context
		fingerprint := getFingerprint(testCerts.ClientCert)
		ctx, exists := adminImpl.GetContext(context.Background(), fingerprint)
		if !exists || ctx == nil {
			t.Fatal("Context should exist in cache")
		}

		// Each admin has its own cache instance
		if adminImpl.ActiveCount() != 1 {
			t.Errorf("Expected 1 active context, got %d", adminImpl.ActiveCount())
		}

		// Token validation depends on cache lookup
		guard, err := admin.CreateGuard(context.Background(), token, "read")
		if err != nil {
			t.Fatalf("Failed to create guard: %v", err)
		}

		// Remove from cache
		adminImpl.RevokeByFingerprint(context.Background(), fingerprint)

		// Guard validation should now fail
		if err := guard.Validate(context.Background(), token); err == nil {
			t.Error("Guard should fail to validate token after context revoked")
		}
	})

	t.Run("TokenCryptoBinding", func(t *testing.T) {
		// Test that tokens are cryptographically bound to the admin that created them
		resetAdminForTesting()
		testCerts := GenerateTestCertificates(t)

		// Create admin with specific key
		_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
		admin, err := NewAdminService[any](privateKey, testCerts.CertPool)
		if err != nil {
			t.Fatalf("Failed to create admin: %v", err)
		}

		adminImpl := admin.(*adminService[any])

		// Configure admin
		err = admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
			return &Context[any]{
				CertificateInfo:        extractCertificateInfo(cert),
				CertificateFingerprint: getFingerprint(cert),
				IssuedAt:               time.Now(),
				ExpiresAt:              time.Now().Add(time.Hour),
				Permissions:            []string{"read"},
			}, nil
		})
		if err != nil {
			t.Fatalf("Failed to set policy: %v", err)
		}

		// Generate token
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Token can be decrypted by same admin
		fingerprint, err := adminImpl.decryptToken(context.Background(), token)
		if err != nil {
			t.Errorf("Should be able to decrypt own token: %v", err)
		}
		if fingerprint == "" {
			t.Error("Fingerprint should not be empty")
		}

		// Simulate trying to verify with different public key
		// This tests that tokens are bound to the admin's key pair
		_, differentPrivateKey, _ := ed25519.GenerateKey(rand.Reader)
		differentPublicKey := differentPrivateKey.Public()

		// Try to verify token with different public key
		_, err = verifyTokenPayload(token, differentPublicKey)
		if err == nil {
			t.Error("Should not be able to verify token with different public key")
		}
		if !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("Expected ErrInvalidSignature, got: %v", err)
		}
	})
}

// TestCertificates holds test PKI materials.
type TestCertificates struct {
	RootCA     *x509.Certificate
	RootCAKey  ed25519.PrivateKey
	ClientCert *x509.Certificate
	ClientKey  ed25519.PrivateKey
	CertPool   *x509.CertPool
}

// GenerateTestCertificates creates a complete test PKI with root CA and client cert.
func GenerateTestCertificates(t *testing.T) *TestCertificates {
	t.Helper()
	// Generate Root CA
	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPub, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		t.Fatalf("Failed to parse root certificate: %v", err)
	}

	// Generate Client Certificate
	clientPub, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:       []string{"Test Client"},
			OrganizationalUnit: []string{"Engineering", "Security"},
			CommonName:         "test-client",
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"San Francisco"},
			StreetAddress:      []string{"123 Test St"},
			PostalCode:         []string{"94102"},
		},
		NotBefore:      time.Now().Add(-24 * time.Hour),
		NotAfter:       time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
		DNSNames:       []string{"test.example.com", "*.test.example.com"},
		EmailAddresses: []string{"test@example.com", "admin@example.com"},
		IPAddresses:    []net.IP{net.IPv4(192, 168, 1, 1), net.IPv4(10, 0, 0, 1)},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, rootCert, clientPub, rootKey)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		t.Fatalf("Failed to parse client certificate: %v", err)
	}

	// Create certificate pool with root CA
	certPool := x509.NewCertPool()
	certPool.AddCert(rootCert)

	return &TestCertificates{
		RootCA:     rootCert,
		RootCAKey:  rootKey,
		ClientCert: clientCert,
		ClientKey:  clientKey,
		CertPool:   certPool,
	}
}

// GenerateAdditionalClientCert generates an additional client certificate signed by the provided CA.
func GenerateAdditionalClientCert(t *testing.T, testCerts *TestCertificates, commonName string) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()

	// Generate Client Key
	clientPub, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	// Create unique serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Test Client"},
			OrganizationalUnit: []string{"Engineering"},
			CommonName:         commonName,
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, testCerts.RootCA, clientPub, testCerts.RootCAKey)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		t.Fatalf("Failed to parse client certificate: %v", err)
	}

	return clientCert, clientKey
}

// createTestAssertion is a test helper to create assertions.
func createTestAssertion(t *testing.T, privateKey crypto.PrivateKey, cert *x509.Certificate) SignedAssertion {
	assertion, err := CreateAssertion(privateKey, cert)
	if err != nil {
		t.Fatalf("Failed to create assertion: %v", err)
	}
	return assertion
}

// GenerateTestCertificatesWithDifferentCA generates test certificates with a different CA.
func GenerateTestCertificatesWithDifferentCA(t *testing.T) *TestCertificates {
	// This is a simplified version - in real tests you'd generate a completely different CA chain
	certs := GenerateTestCertificates(t)

	// Create a new CA pool without the original CA
	newPool := x509.NewCertPool()
	// Don't add the original CA cert

	return &TestCertificates{
		RootCA:     certs.RootCA,
		RootCAKey:  certs.RootCAKey,
		ClientCert: certs.ClientCert,
		ClientKey:  certs.ClientKey,
		CertPool:   newPool, // Empty pool that won't validate the certs
	}
}

func TestNonceCleanupOnWriteOperations(t *testing.T) {
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

	// Configure pipeline
	err = admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(time.Hour),
			Permissions:            []string{"read", "write"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set policy: %v", err)
	}

	adminSvc := admin.(*adminService[any])

	t.Run("nonce cleanup on Generate", func(t *testing.T) {
		// Create an assertion that will add a nonce
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		_, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Verify nonce was added
		adminSvc.nonceMu.Lock()
		initialCount := len(adminSvc.nonceCache)
		adminSvc.nonceMu.Unlock()

		if initialCount == 0 {
			t.Error("Expected nonce to be cached after Generate")
		}

		// Manually add an expired nonce
		adminSvc.nonceMu.Lock()
		adminSvc.nonceCache["expired-nonce"] = time.Now().Add(-10 * time.Minute)
		beforeCleanup := len(adminSvc.nonceCache)
		adminSvc.nonceMu.Unlock()

		// Generate another token (should trigger cleanup)
		assertion2 := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		_, err = admin.Generate(context.Background(), testCerts.ClientCert, assertion2)
		if err != nil {
			t.Fatalf("Failed to generate second token: %v", err)
		}

		// Verify expired nonce was cleaned
		adminSvc.nonceMu.Lock()
		afterCleanup := len(adminSvc.nonceCache)
		_, hasExpired := adminSvc.nonceCache["expired-nonce"]
		adminSvc.nonceMu.Unlock()

		if hasExpired {
			t.Error("Expired nonce should have been cleaned up")
		}
		// We expect: initial nonce + new nonce - expired nonce = same count as initial + 1
		expectedCount := initialCount + 1
		if afterCleanup != expectedCount {
			t.Errorf("Expected nonce count to be %d, got %d (before cleanup: %d)", expectedCount, afterCleanup, beforeCleanup)
		}
	})

	t.Run("nonce cleanup on CreateGuard", func(t *testing.T) {
		// Generate a token
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Manually add expired nonces
		adminSvc.nonceMu.Lock()
		adminSvc.nonceCache["expired-guard-1"] = time.Now().Add(-5 * time.Minute)
		adminSvc.nonceCache["expired-guard-2"] = time.Now().Add(-10 * time.Minute)
		beforeCleanup := len(adminSvc.nonceCache)
		adminSvc.nonceMu.Unlock()

		// Create guard (should trigger cleanup)
		_, err = admin.CreateGuard(context.Background(), token, "read")
		if err != nil {
			t.Fatalf("Failed to create guard: %v", err)
		}

		// Verify expired nonces were cleaned
		adminSvc.nonceMu.Lock()
		afterCleanup := len(adminSvc.nonceCache)
		_, hasExpired1 := adminSvc.nonceCache["expired-guard-1"]
		_, hasExpired2 := adminSvc.nonceCache["expired-guard-2"]
		adminSvc.nonceMu.Unlock()

		if hasExpired1 || hasExpired2 {
			t.Error("Expired nonces should have been cleaned up during CreateGuard")
		}
		if afterCleanup >= beforeCleanup {
			t.Errorf("Expected nonce count to decrease, got before=%d after=%d", beforeCleanup, afterCleanup)
		}
	})

	t.Run("nonce cleanup on RevokeByFingerprint", func(t *testing.T) {
		// Generate a token
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		_, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Manually add expired nonces
		adminSvc.nonceMu.Lock()
		adminSvc.nonceCache["expired-revoke-1"] = time.Now().Add(-1 * time.Hour)
		beforeCleanup := len(adminSvc.nonceCache)
		adminSvc.nonceMu.Unlock()

		// Revoke a context (should trigger cleanup)
		fingerprint := getFingerprint(testCerts.ClientCert)
		err = adminSvc.RevokeByFingerprint(context.Background(), fingerprint)
		if err != nil {
			t.Fatalf("Failed to revoke: %v", err)
		}

		// Verify expired nonce was cleaned
		adminSvc.nonceMu.Lock()
		afterCleanup := len(adminSvc.nonceCache)
		_, hasExpired := adminSvc.nonceCache["expired-revoke-1"]
		adminSvc.nonceMu.Unlock()

		if hasExpired {
			t.Error("Expired nonce should have been cleaned up during RevokeByFingerprint")
		}
		if afterCleanup >= beforeCleanup {
			t.Errorf("Expected nonce count to decrease, got before=%d after=%d", beforeCleanup, afterCleanup)
		}
	})

	t.Run("no cleanup on read operations", func(t *testing.T) {
		// Generate token and guard
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		guard, err := admin.CreateGuard(context.Background(), token, "read")
		if err != nil {
			t.Fatalf("Failed to create guard: %v", err)
		}

		// Add an expired nonce
		adminSvc.nonceMu.Lock()
		adminSvc.nonceCache["expired-read-test"] = time.Now().Add(-1 * time.Hour)
		adminSvc.nonceMu.Unlock()

		// Perform read operations (should NOT trigger cleanup)
		_ = guard.Validate(context.Background(), token)
		_, _ = adminSvc.GetContext(context.Background(), getFingerprint(testCerts.ClientCert))

		// Verify expired nonce is still there
		adminSvc.nonceMu.Lock()
		_, hasExpired := adminSvc.nonceCache["expired-read-test"]
		adminSvc.nonceMu.Unlock()

		if !hasExpired {
			t.Error("Read operations should not trigger nonce cleanup")
		}
	})
}

func TestNonceExpiryTiming(t *testing.T) {
	resetAdminForTesting()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)
	err := admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(5 * time.Minute),
			Permissions:            []string{"read"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set policy: %v", err)
	}

	adminSvc := admin.(*adminService[any])

	// Generate assertion with known claims
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	_, err = admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Check that nonce expiry is set to assertion expiry + 5 minutes
	adminSvc.nonceMu.Lock()
	defer adminSvc.nonceMu.Unlock()

	if len(adminSvc.nonceCache) != 1 {
		t.Fatalf("Expected exactly one nonce in cache, got %d", len(adminSvc.nonceCache))
	}

	for nonce, expiry := range adminSvc.nonceCache {
		// Assertion expires in ~1 minute, nonce should expire in ~6 minutes
		untilExpiry := time.Until(expiry)
		if untilExpiry < 5*time.Minute || untilExpiry > 7*time.Minute {
			t.Errorf("Nonce %s has unexpected expiry time: %v from now", nonce, untilExpiry)
		}
	}
}

func TestTokenIssuedAt(t *testing.T) {
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

	// Configure pipeline
	err = admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(time.Hour),
			Permissions:            []string{"read"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set policy: %v", err)
	}

	t.Run("new tokens include IssuedAt", func(t *testing.T) {
		beforeGeneration := time.Now()

		// Generate token
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		afterGeneration := time.Now()

		// Decode token to check IssuedAt
		payload := extractTokenPayload(t, token)

		if payload.IssuedAt.IsZero() {
			t.Error("IssuedAt should not be zero")
		}

		if payload.IssuedAt.Before(beforeGeneration) || payload.IssuedAt.After(afterGeneration) {
			t.Errorf("IssuedAt %v should be between %v and %v",
				payload.IssuedAt, beforeGeneration, afterGeneration)
		}

		// Verify IssuedAt is before Expiry
		if !payload.IssuedAt.Before(payload.Expiry) {
			t.Errorf("IssuedAt %v should be before Expiry %v",
				payload.IssuedAt, payload.Expiry)
		}
	})

	t.Run("backward compatibility with old tokens", func(t *testing.T) {
		// Create admin service to get signer
		adminSvc := admin.(*adminService[any])

		// Create an old-style token without IssuedAt
		oldPayload := &tokenPayload{
			Fingerprint: "test-fingerprint",
			Expiry:      time.Now().Add(1 * time.Hour),
			Nonce:       "test-nonce",
			// IssuedAt intentionally omitted
		}

		oldToken, err := encodeAndSign(oldPayload, adminSvc.signer)
		if err != nil {
			t.Fatalf("Failed to create old token: %v", err)
		}

		// Verify old token can still be parsed
		verifiedPayload, err := verifyTokenPayload(oldToken, adminSvc.publicKey)
		if err != nil {
			t.Fatalf("Failed to verify old token: %v", err)
		}

		// Old tokens should have zero IssuedAt
		if !verifiedPayload.IssuedAt.IsZero() {
			t.Errorf("Old token should have zero IssuedAt, got %v", verifiedPayload.IssuedAt)
		}

		// Other fields should still work
		if verifiedPayload.Fingerprint != "test-fingerprint" {
			t.Errorf("Fingerprint mismatch: got %s", verifiedPayload.Fingerprint)
		}
	})

	t.Run("IssuedAt serialization", func(t *testing.T) {
		// Generate token
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Extract and decode the JSON payload
		parts := strings.Split(string(token), ":")
		if len(parts) != 2 {
			t.Fatalf("Invalid token format")
		}

		payloadBytes, err := base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("Failed to decode payload: %v", err)
		}

		// Check JSON structure
		var jsonMap map[string]interface{}
		if err := json.Unmarshal(payloadBytes, &jsonMap); err != nil {
			t.Fatalf("Failed to unmarshal JSON: %v", err)
		}

		// Verify IssuedAt field exists in JSON
		if _, exists := jsonMap["i"]; !exists {
			t.Error("IssuedAt field 'i' should exist in JSON")
		}

		// Verify all expected fields
		expectedFields := []string{"f", "i", "e", "n"}
		for _, field := range expectedFields {
			if _, exists := jsonMap[field]; !exists {
				t.Errorf("Expected field '%s' not found in token payload", field)
			}
		}
	})

	t.Run("token age calculation", func(t *testing.T) {
		// Generate token
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Sleep briefly to ensure token has age
		time.Sleep(100 * time.Millisecond)

		// Verify token and check age
		adminSvc := admin.(*adminService[any])
		payload, err := verifyTokenPayload(token, adminSvc.publicKey)
		if err != nil {
			t.Fatalf("Failed to verify token: %v", err)
		}

		tokenAge := time.Since(payload.IssuedAt)
		if tokenAge < 100*time.Millisecond {
			t.Errorf("Token age %v should be at least 100ms", tokenAge)
		}

		// Token age should be less than expiry duration
		expiryDuration := payload.Expiry.Sub(payload.IssuedAt)
		if tokenAge >= expiryDuration {
			t.Errorf("Token age %v should be less than expiry duration %v",
				tokenAge, expiryDuration)
		}
	})
}

// Helper function to extract token payload for testing.
func extractTokenPayload(t *testing.T, token SignedToken) *tokenPayload {
	t.Helper()

	parts := strings.Split(string(token), ":")
	if len(parts) != 2 {
		t.Fatalf("Invalid token format")
	}

	payloadBytes, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	var payload tokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	return &payload
}

func TestTokenIssuedAtAuditability(t *testing.T) {
	resetAdminForTesting()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)
	err := admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(5 * time.Minute),
			Permissions:            []string{"read"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set policy: %v", err)
	}

	// Track token generation times
	var tokens []SignedToken
	var generationTimes []time.Time

	// Generate multiple tokens over time
	for i := 0; i < 3; i++ {
		generationTimes = append(generationTimes, time.Now())

		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		token, errGen := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if errGen != nil {
			t.Fatalf("Failed to generate token %d: %v", i, errGen)
		}
		tokens = append(tokens, token)

		time.Sleep(50 * time.Millisecond)
	}

	// Verify we can audit when each token was created
	adminSvc := admin.(*adminService[any])
	for i, token := range tokens {
		payload, err := verifyTokenPayload(token, adminSvc.publicKey)
		if err != nil {
			t.Fatalf("Failed to verify token %d: %v", i, err)
		}

		// Each token should have been issued around its generation time
		timeDiff := payload.IssuedAt.Sub(generationTimes[i]).Abs()
		if timeDiff > 10*time.Millisecond {
			t.Errorf("Token %d IssuedAt differs from generation time by %v", i, timeDiff)
		}

		// Tokens should have increasing IssuedAt times
		if i > 0 {
			prevPayload, _ := verifyTokenPayload(tokens[i-1], adminSvc.publicKey)
			if !payload.IssuedAt.After(prevPayload.IssuedAt) {
				t.Errorf("Token %d IssuedAt should be after token %d", i, i-1)
			}
		}
	}
}

// UserMetadata represents custom user information.
type UserMetadata struct {
	UserID   string
	Email    string
	Roles    []string
	TenantID string
}

func TestTypedMetadataPolicy(t *testing.T) {
	resetAdminForTesting()

	// Generate test certificates
	testCerts := GenerateTestCertificates(t)

	// Create admin service with custom metadata type
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	admin, err := NewAdminService[UserMetadata](privateKey, testCerts.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin service: %v", err)
	}

	// Set a policy that extracts user info from certificate
	err = admin.SetPolicy(func(cert *x509.Certificate) (*Context[UserMetadata], error) {
		// Extract user information from certificate
		metadata := UserMetadata{
			UserID:   cert.Subject.CommonName,
			Email:    "",               // Could extract from cert.EmailAddresses if available
			Roles:    []string{"user"}, // Could derive from cert organization
			TenantID: "default",
		}

		// Check if this is an admin user based on certificate
		if cert.Subject.CommonName == "admin" {
			metadata.Roles = append(metadata.Roles, "admin")
		}

		return &Context[UserMetadata]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(time.Hour),
			Metadata:               metadata,
			Permissions:            []string{"read", "write"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set policy: %v", err)
	}

	// Create assertion
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

	// Generate token
	token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Fatal("Generated token is empty")
	}

	// Access the typed admin service to check metadata
	adminSvc := admin.(*adminService[UserMetadata])
	fingerprint := getFingerprint(testCerts.ClientCert)
	ctx, exists := adminSvc.GetContext(context.Background(), fingerprint)
	if !exists {
		t.Fatal("Context not found")
	}

	// Verify the metadata is properly typed and populated
	if ctx.Metadata.UserID == "" {
		t.Error("UserID should not be empty")
	}
	if len(ctx.Metadata.Roles) == 0 {
		t.Error("Roles should not be empty")
	}
	if ctx.Metadata.TenantID != "default" {
		t.Errorf("Expected TenantID 'default', got %s", ctx.Metadata.TenantID)
	}
}

// Helper function.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr || len(s) > len(substr) && contains(s[1:], substr)
}
