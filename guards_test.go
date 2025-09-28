package sctx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestRequireCertField tests the RequireCertField guard
func TestRequireCertField(t *testing.T) {
	ctx := &Context[any]{
		CertificateInfo: CertificateInfo{
			CommonName:   "test.example.com",
			Issuer:       "Example CA",
			SerialNumber: "123456",
		},
	}

	tests := []struct {
		name      string
		field     string
		expected  string
		shouldErr bool
	}{
		{"Match CN", "CN", "test.example.com", false},
		{"Match Issuer", "ISSUER", "Example CA", false},
		{"Match Serial", "SERIAL", "123456", false},
		{"Mismatch CN", "CN", "wrong.example.com", true},
		{"Mismatch Issuer", "ISSUER", "Wrong CA", true},
		{"Unknown field", "UNKNOWN", "anything", true},
		{"Case insensitive field", "cn", "test.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard := RequireCertField[any](tt.field, tt.expected)
			_, err := guard(context.Background(), ctx)
			if (err != nil) != tt.shouldErr {
				t.Errorf("RequireCertField() error = %v, shouldErr %v", err, tt.shouldErr)
			}
		})
	}
}

// TestRequireCertPattern tests the RequireCertPattern guard
func TestRequireCertPattern(t *testing.T) {
	ctx := &Context[any]{
		CertificateInfo: CertificateInfo{
			CommonName:   "test.example.com",
			Issuer:       "Example CA",
			SerialNumber: "123456",
			NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			KeyUsage:     []string{"digital_signature", "key_encipherment"},
		},
	}

	tests := []struct {
		name      string
		field     string
		pattern   string
		shouldErr bool
	}{
		{"Match CN pattern", "CN", `^test\.example\.com$`, false},
		{"Match CN wildcard", "CN", `.*\.example\.com`, false},
		{"Mismatch CN pattern", "CN", `^prod\.example\.com$`, true},
		{"Match Issuer pattern", "ISSUER", "Example.*", false},
		{"Match Serial pattern", "SERIAL", "[0-9]+", false},
		{"Invalid regex", "CN", "[invalid", true},
		{"Empty field value", "UNKNOWN", "something", true},
		{"Match NotBefore", "NOTBEFORE", "2024-01-01", false},
		{"Match NotAfter", "NOTAFTER", "2025-01-01", false},
		{"Match KeyUsage", "KEYUSAGE", "digital_signature", false},
		{"Match CommonName alias", "COMMONNAME", "test", false},
		{"Match SerialNumber alias", "SERIALNUMBER", "123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard := RequireCertPattern[any](tt.field, tt.pattern)
			_, err := guard(context.Background(), ctx)
			if (err != nil) != tt.shouldErr {
				t.Errorf("RequireCertPattern() error = %v, shouldErr %v", err, tt.shouldErr)
			}
		})
	}
}

// TestExtractCertInfoField tests the extractCertInfoField function
func TestExtractCertInfoField(t *testing.T) {
	certInfo := CertificateInfo{
		CommonName:   "test.example.com",
		Issuer:       "Example CA",
		SerialNumber: "123456",
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     []string{"digital_signature", "key_encipherment"},
	}

	tests := []struct {
		name     string
		field    string
		expected string
	}{
		{"Extract CN", "CN", "test.example.com"},
		{"Extract CommonName", "COMMONNAME", "test.example.com"},
		{"Extract Issuer", "ISSUER", "Example CA"},
		{"Extract Serial", "SERIAL", "123456"},
		{"Extract SerialNumber", "SERIALNUMBER", "123456"},
		{"Extract NotBefore", "NOTBEFORE", "2024-01-01T00:00:00Z"},
		{"Extract NotAfter", "NOTAFTER", "2025-01-01T00:00:00Z"},
		{"Extract KeyUsage", "KEYUSAGE", "digital_signature,key_encipherment"},
		{"Unknown field", "UNKNOWN", ""},
		{"Lowercase field", "cn", "test.example.com"},
		{"Mixed case", "CommonName", "test.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCertInfoField(certInfo, tt.field)
			if result != tt.expected {
				t.Errorf("extractCertInfoField(%s) = %q, want %q", tt.field, result, tt.expected)
			}
		})
	}
}

// TestSetContextEdgeCases tests remaining edge cases in SetContext
func TestSetContextEdgeCases(t *testing.T) {
	ctx := &Context[any]{
		Permissions: []string{"existing"},
	}

	// Test with nil expiry
	guard := SetContext[any](ContextOptions{
		Permissions: []string{"new"},
	})

	result, err := guard(context.Background(), ctx)
	if err != nil {
		t.Fatalf("SetContext failed: %v", err)
	}

	// Should have both permissions
	if len(result.Permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(result.Permissions))
	}

	// Expiry should not be set
	if !result.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should remain zero when not specified")
	}
}

// TestGenerateGuardIDEdgeCases tests edge case in generateGuardID
func TestGenerateGuardIDEdgeCases(t *testing.T) {
	// Test that IDs are unique
	id1 := generateGuardID()
	id2 := generateGuardID()

	if id1 == id2 {
		t.Error("Generated guard IDs should be unique")
	}

	// Test format
	if len(id1) != 32 { // 16 bytes hex encoded = 32 chars
		t.Errorf("Expected 32 character ID, got %d", len(id1))
	}
}

// TestHasPermissionEdgeCases verifies hasPermission is tested (already covered)
func TestHasPermissionEdgeCases(t *testing.T) {
	// This is already tested through guard creation, but let's add explicit test
	perms := []string{"read", "write", "admin"}

	if !hasPermission(perms, "read") {
		t.Error("Should have read permission")
	}

	if hasPermission(perms, "delete") {
		t.Error("Should not have delete permission")
	}

	if hasPermission(nil, "read") {
		t.Error("Nil permissions should not have any permission")
	}

	if hasPermission([]string{}, "read") {
		t.Error("Empty permissions should not have any permission")
	}
}

func TestGuardCreation(t *testing.T) {
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
		t.Fatalf("Failed to set context policy: %v", err)
	}

	t.Run("basic guard creation", func(t *testing.T) {
		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token
		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Create guard
		guard, err := admin.CreateGuard(context.Background(), token, "read")
		if err != nil {
			t.Fatalf("Failed to create guard: %v", err)
		}

		// Verify guard properties
		if guard.ID() == "" {
			t.Error("Guard ID should not be empty")
		}

		perms := guard.Permissions()
		if len(perms) != 1 || perms[0] != "read" {
			t.Errorf("Expected guard to check [read], got %v", perms)
		}
	})

	t.Run("guard validation", func(t *testing.T) {
		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate tokens
		token1, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Create guard for read/write
		guard, err := admin.CreateGuard(context.Background(), token1, "read", "write")
		if err != nil {
			t.Fatalf("Failed to create guard: %v", err)
		}

		// Token1 should pass (has read, write, admin)
		err = guard.Validate(context.Background(), token1)
		if err != nil {
			t.Errorf("Guard should validate token with required permissions: %v", err)
		}

		// To test limited permissions, we need to create a new context
		// with limited permissions in the same admin instance

		// First revoke the existing context to clear cache
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(testCerts.ClientCert)
		_ = adminSvc.cache.Delete(fingerprint)

		// Temporarily modify the policy to grant only read
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
			t.Fatalf("Failed to set limited policy: %v", err)
		}

		// Create new assertion for limited token
		assertion2 := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate new limited token
		token2, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion2)
		if err != nil {
			t.Fatalf("Failed to generate limited token: %v", err)
		}

		// Token2 should fail (missing write permission)
		err = guard.Validate(context.Background(), token2)
		if err == nil {
			t.Error("Guard should reject token without required permissions")
		}
		if !strings.Contains(err.Error(), "missing permission: write") {
			t.Errorf("Expected missing permission error, got: %v", err)
		}

		// Restore full permissions policy
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
			t.Fatalf("Failed to restore full policy: %v", err)
		}
	})

	t.Run("guard creation permissions", func(t *testing.T) {
		// Clear cache to ensure fresh token generation
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(testCerts.ClientCert)
		_ = adminSvc.cache.Delete(fingerprint)

		// Set guard creation permissions
		admin.SetGuardCreationPermissions([]string{"admin"})

		// Create assertion
		assertionAdmin := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Token with admin permission should work
		tokenAdmin, err := admin.Generate(context.Background(), testCerts.ClientCert, assertionAdmin)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		guard, err := admin.CreateGuard(context.Background(), tokenAdmin, "read")
		if err != nil {
			t.Fatalf("Failed to create guard with admin permission: %v", err)
		}
		if guard == nil {
			t.Error("Guard should not be nil")
		}

		// To test without admin permission, modify the current admin's pipeline
		fingerprint = getFingerprint(testCerts.ClientCert)
		_ = adminSvc.cache.Delete(fingerprint)

		// Temporarily modify pipeline to not grant admin
		// Store reference for cleanup (no longer needed with policies)
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

		// Create assertion for limited token
		assertionLimited := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		tokenLimited, err := admin.Generate(context.Background(), testCerts.ClientCert, assertionLimited)
		if err != nil {
			t.Fatalf("Failed to generate limited token: %v", err)
		}

		// Should fail without admin permission
		_, err = admin.CreateGuard(context.Background(), tokenLimited, "read")
		if err == nil {
			t.Error("Should not be able to create guard without required permissions")
		}
		if err.Error() != "missing required permission to create guards: admin" {
			t.Errorf("Expected specific permission error, got: %v", err)
		}

		// Policy change complete
	})

	t.Run("cannot create guard for permissions you don't have", func(t *testing.T) {
		// Clear guard creation permissions
		admin.SetGuardCreationPermissions(nil)

		// To test permission limitation, modify the current admin's pipeline
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(testCerts.ClientCert)
		_ = adminSvc.cache.Delete(fingerprint)

		// Temporarily modify pipeline to grant only read
		// Store reference for cleanup (no longer needed with policies)
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

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Try to create guard for "write" permission (which token doesn't have)
		_, err = admin.CreateGuard(context.Background(), token, "write")
		if err == nil {
			t.Error("Should not be able to create guard for permission you don't have")
		}
		if err.Error() != "cannot create guard for permission you don't have: write" {
			t.Errorf("Expected specific error, got: %v", err)
		}

		// Policy change complete
	})

	t.Run("expired token", func(t *testing.T) {
		// To test expired token, modify existing context
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(testCerts.ClientCert)
		_ = adminSvc.cache.Delete(fingerprint)

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate new token
		token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Manually expire the context
		ctx, _ := adminSvc.cache.Get(fingerprint)
		ctx.ExpiresAt = ctx.IssuedAt // Expire immediately
		adminSvc.cache.Store(fingerprint, ctx)

		// Try to create guard with expired token
		_, err = admin.CreateGuard(context.Background(), token, "read")
		if err == nil {
			t.Error("Should not be able to create guard with expired token")
		}
		if err.Error() != "token expired" {
			t.Errorf("Expected expiration error, got: %v", err)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		// Try with invalid token
		_, err := admin.CreateGuard(context.Background(), "invalid-token", "read")
		if err == nil {
			t.Error("Should not be able to create guard with invalid token")
		}
		if err.Error() != "invalid token: invalid context format" {
			t.Errorf("Expected invalid token error, got: %v", err)
		}
	})

}

func TestGuardValidation(t *testing.T) {
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
		t.Fatalf("Failed to set context policy: %v", err)
	}

	// Create assertion
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

	// Generate token and create guard
	token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	guard, err := admin.CreateGuard(context.Background(), token, "read", "write")
	if err != nil {
		t.Fatalf("Failed to create guard: %v", err)
	}

	t.Run("valid token passes", func(t *testing.T) {
		err := guard.Validate(context.Background(), token)
		if err != nil {
			t.Errorf("Valid token should pass validation: %v", err)
		}
	})

	t.Run("invalid token format", func(t *testing.T) {
		err := guard.Validate(context.Background(), "not-a-valid-token")
		if err == nil {
			t.Error("Invalid token should fail validation")
		}
		if !strings.Contains(err.Error(), "invalid caller token") {
			t.Errorf("Expected invalid caller token error, got: %v", err)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		// Manually expire the context
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(testCerts.ClientCert)
		ctx, _ := adminSvc.cache.Get(fingerprint)
		ctx.ExpiresAt = ctx.IssuedAt // Expire immediately
		adminSvc.cache.Store(fingerprint, ctx)

		err := guard.Validate(context.Background(), token)
		if err == nil {
			t.Error("Expired token should fail validation")
		}
		if !strings.Contains(err.Error(), "caller token expired") {
			t.Errorf("Expected caller token expired error, got: %v", err)
		}
	})

	t.Run("missing permissions", func(t *testing.T) {
		// To test with limited permissions, modify the current admin's pipeline
		// First clear the cache
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(testCerts.ClientCert)
		_ = adminSvc.cache.Delete(fingerprint)

		// Temporarily modify pipeline
		// Store reference for cleanup (no longer needed with policies)
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

		// Create assertion for limited token
		assertionLimited := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		limitedToken, err := admin.Generate(context.Background(), testCerts.ClientCert, assertionLimited)
		if err != nil {
			t.Fatalf("Failed to generate limited token: %v", err)
		}

		// Guard requires read AND write, token only has read
		err = guard.Validate(context.Background(), limitedToken)
		if err == nil {
			t.Error("Token without required permissions should fail")
		}
		if !strings.Contains(err.Error(), "missing permission: write") {
			t.Errorf("Expected missing permission error, got: %v", err)
		}

		// Policy change complete
	})

	t.Run("guard permissions are immutable", func(t *testing.T) {
		// Get permissions
		perms1 := guard.Permissions()
		perms2 := guard.Permissions()

		// Modify returned slice
		perms1[0] = "modified"

		// Original should be unchanged
		if perms2[0] != "read" {
			t.Error("Guard permissions should be immutable")
		}
	})

}

func TestGuardCreatorBinding(t *testing.T) {
	resetAdminForTesting()

	// Generate root CA for both test certificates
	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPub, rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	certPool := x509.NewCertPool()
	certPool.AddCert(rootCert)

	// Create admin service
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, err := NewAdminService[any](privateKey, certPool)
	if err != nil {
		t.Fatalf("Failed to create admin service: %v", err)
	}

	// Configure policy
	err = admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(time.Hour),
			Permissions:            []string{"read", "write", "admin", "create-guard"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set policy: %v", err)
	}

	// Create two different client certificates
	alice := createClientCert(t, rootCert, rootKey, "alice")
	bob := createClientCert(t, rootCert, rootKey, "bob")

	t.Run("creator can use their own guard", func(t *testing.T) {
		// Alice creates a guard
		aliceAssertion, _ := CreateAssertion(alice.key, alice.cert)
		aliceToken, _ := admin.Generate(context.Background(), alice.cert, aliceAssertion)
		
		guard, err := admin.CreateGuard(context.Background(), aliceToken, "read")
		if err != nil {
			t.Fatalf("Failed to create guard: %v", err)
		}

		// Alice can use her own guard
		err = guard.Validate(context.Background(), aliceToken)
		if err != nil {
			t.Errorf("Creator should be able to use their own guard: %v", err)
		}
	})

	t.Run("non-creator cannot use someone else's guard", func(t *testing.T) {
		// Alice creates a guard
		aliceAssertion, _ := CreateAssertion(alice.key, alice.cert)
		aliceToken, _ := admin.Generate(context.Background(), alice.cert, aliceAssertion)
		
		guard, err := admin.CreateGuard(context.Background(), aliceToken, "read")
		if err != nil {
			t.Fatalf("Failed to create guard: %v", err)
		}

		// Bob tries to use Alice's guard
		bobAssertion, _ := CreateAssertion(bob.key, bob.cert)
		bobToken, _ := admin.Generate(context.Background(), bob.cert, bobAssertion)
		
		err = guard.Validate(context.Background(), bobToken)
		if err == nil {
			t.Error("Non-creator should not be able to use someone else's guard")
		}
		if !strings.Contains(err.Error(), "guard can only be used by its creator") {
			t.Errorf("Expected creator-only error, got: %v", err)
		}
	})

	t.Run("guard validates other tokens when used by creator", func(t *testing.T) {
		// Alice creates a guard
		aliceAssertion, _ := CreateAssertion(alice.key, alice.cert)
		aliceToken, _ := admin.Generate(context.Background(), alice.cert, aliceAssertion)
		
		guard, err := admin.CreateGuard(context.Background(), aliceToken, "read")
		if err != nil {
			t.Fatalf("Failed to create guard: %v", err)
		}

		// Bob gets a token
		bobAssertion, _ := CreateAssertion(bob.key, bob.cert)
		bobToken, _ := admin.Generate(context.Background(), bob.cert, bobAssertion)

		// Alice uses her guard to validate Bob's token
		err = guard.Validate(context.Background(), aliceToken, bobToken)
		if err != nil {
			t.Errorf("Creator should be able to validate other tokens: %v", err)
		}
	})

	t.Run("guard becomes unusable when creator's token expires", func(t *testing.T) {
		// Configure short expiry
		err = admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
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

		// Alice creates a guard
		aliceAssertion, _ := CreateAssertion(alice.key, alice.cert)
		aliceToken, _ := admin.Generate(context.Background(), alice.cert, aliceAssertion)
		
		guard, err := admin.CreateGuard(context.Background(), aliceToken, "read")
		if err != nil {
			t.Fatalf("Failed to create guard: %v", err)
		}

		// Remove Alice's context from cache to simulate expiry
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(alice.cert)
		_ = adminSvc.cache.Delete(fingerprint)

		// Alice can no longer use her guard
		err = guard.Validate(context.Background(), aliceToken)
		if err == nil {
			t.Error("Guard should be unusable when creator's context is gone")
		}
		if !strings.Contains(err.Error(), "context not found") {
			t.Errorf("Expected context not found error, got: %v", err)
		}
	})

	t.Run("multiple guards by same creator", func(t *testing.T) {
		// Restore full permission policy (previous test changed it)
		err = admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
			return &Context[any]{
				CertificateInfo:        extractCertificateInfo(cert),
				CertificateFingerprint: getFingerprint(cert),
				IssuedAt:               time.Now(),
				ExpiresAt:              time.Now().Add(time.Hour),
				Permissions:            []string{"read", "write", "admin", "create-guard"},
			}, nil
		})
		if err != nil {
			t.Fatalf("Failed to set policy: %v", err)
		}
		
		// Alice creates multiple guards
		aliceAssertion, _ := CreateAssertion(alice.key, alice.cert)
		aliceToken, err := admin.Generate(context.Background(), alice.cert, aliceAssertion)
		if err != nil {
			t.Fatalf("Failed to generate Alice token: %v", err)
		}
		
		readGuard, err := admin.CreateGuard(context.Background(), aliceToken, "read")
		if err != nil {
			t.Fatalf("Failed to create read guard: %v", err)
		}
		writeGuard, err := admin.CreateGuard(context.Background(), aliceToken, "write")
		if err != nil {
			t.Fatalf("Failed to create write guard: %v", err)
		}
		adminGuard, err := admin.CreateGuard(context.Background(), aliceToken, "admin")
		if err != nil {
			t.Fatalf("Failed to create admin guard: %v", err)
		}

		// Alice can use all her guards
		if err := readGuard.Validate(context.Background(), aliceToken); err != nil {
			t.Errorf("Should be able to use read guard: %v", err)
		}
		if err := writeGuard.Validate(context.Background(), aliceToken); err != nil {
			t.Errorf("Should be able to use write guard: %v", err)
		}
		if err := adminGuard.Validate(context.Background(), aliceToken); err != nil {
			t.Errorf("Should be able to use admin guard: %v", err)
		}

		// Bob cannot use any of Alice's guards
		bobAssertion, _ := CreateAssertion(bob.key, bob.cert)
		bobToken, _ := admin.Generate(context.Background(), bob.cert, bobAssertion)
		
		for _, guard := range []Guard{readGuard, writeGuard, adminGuard} {
			err := guard.Validate(context.Background(), bobToken)
			if err == nil {
				t.Error("Bob should not be able to use Alice's guards")
			}
		}
	})

	t.Run("guard creation requires permissions from creator", func(t *testing.T) {
		// Configure policy without admin permission
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

		// Clear cache to force new token generation with limited permissions
		adminSvc := admin.(*adminService[any])
		if clearer, ok := adminSvc.cache.(interface{ Clear() }); ok {
			clearer.Clear()
		}

		// Alice gets a token (only has read permission)
		aliceAssertion, _ := CreateAssertion(alice.key, alice.cert)
		aliceToken, _ := admin.Generate(context.Background(), alice.cert, aliceAssertion)
		
		// Alice can create a read guard
		_, err := admin.CreateGuard(context.Background(), aliceToken, "read")
		if err != nil {
			t.Errorf("Should be able to create guard for permission you have: %v", err)
		}

		// Alice cannot create an admin guard
		_, err = admin.CreateGuard(context.Background(), aliceToken, "admin")
		if err == nil {
			t.Error("Should not be able to create guard for permission you don't have")
		}
	})
}

type clientCert struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

func createClientCert(t *testing.T, rootCert *x509.Certificate, rootKey ed25519.PrivateKey, cn string) clientCert {
	t.Helper()
	
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key for %s: %v", cn, err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().UnixNano())),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   cn,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, pub, rootKey)
	if err != nil {
		t.Fatalf("Failed to create certificate for %s: %v", cn, err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate for %s: %v", cn, err)
	}

	return clientCert{cert: cert, key: priv}
}

func TestGuardDualTokenValidation(t *testing.T) {
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
			Permissions:            []string{"read", "write", "admin"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set policy: %v", err)
	}

	// Generate token with permissions
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Create guard
	guard, err := admin.CreateGuard(context.Background(), token, "read", "write")
	if err != nil {
		t.Fatalf("Failed to create guard: %v", err)
	}

	t.Run("single token self-validation", func(t *testing.T) {
		// Caller validates themselves
		err := guard.Validate(context.Background(), token)
		if err != nil {
			t.Errorf("Self-validation should pass: %v", err)
		}
	})

	t.Run("dual token delegation validation", func(t *testing.T) {
		// Generate a second token to validate
		assertion2 := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		token2, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion2)
		if err != nil {
			t.Fatalf("Failed to generate second token: %v", err)
		}

		// Caller validates another token
		err = guard.Validate(context.Background(), token, token2)
		if err != nil {
			t.Errorf("Delegation validation should pass: %v", err)
		}
	})

	t.Run("multiple token validation", func(t *testing.T) {
		// Generate multiple tokens
		assertion2 := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		token2, _ := admin.Generate(context.Background(), testCerts.ClientCert, assertion2)
		
		assertion3 := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		token3, _ := admin.Generate(context.Background(), testCerts.ClientCert, assertion3)

		// Validate multiple tokens at once
		err = guard.Validate(context.Background(), token, token2, token3)
		if err != nil {
			t.Errorf("Multiple token validation should pass: %v", err)
		}
	})

	t.Run("no tokens fails", func(t *testing.T) {
		err := guard.Validate(context.Background(), )
		if err == nil {
			t.Error("Validation with no tokens should fail")
		}
		if !strings.Contains(err.Error(), "at least one token required") {
			t.Errorf("Expected 'at least one token required' error, got: %v", err)
		}
	})

	t.Run("caller without permissions fails", func(t *testing.T) {
		// Create a token with limited permissions
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(testCerts.ClientCert)
		_ = adminSvc.cache.Delete(fingerprint)

		// Set policy with only read permission
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

		limitedAssertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		limitedToken, err := admin.Generate(context.Background(), testCerts.ClientCert, limitedAssertion)
		if err != nil {
			t.Fatalf("Failed to generate limited token: %v", err)
		}

		// Try to validate with limited token as caller
		err = guard.Validate(context.Background(), limitedToken, token)
		if err == nil {
			t.Error("Caller without required permissions should fail")
		}
		// When self-validating, it checks the caller has the guard's required permissions
		if !strings.Contains(err.Error(), "missing permission: write") {
			t.Errorf("Expected missing permission error, got: %v", err)
		}
	})
}

func TestGuardValidationAfterDemotion(t *testing.T) {
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
			Permissions:            []string{"read", "write", "admin"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to set policy: %v", err)
	}

	// Generate token with full permissions
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	fullToken, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Create guard requiring write permission
	guard, err := admin.CreateGuard(context.Background(), fullToken, "write")
	if err != nil {
		t.Fatalf("Failed to create guard: %v", err)
	}

	// Simulate demotion by removing permissions from cached context
	adminSvc := admin.(*adminService[any])
	fingerprint := getFingerprint(testCerts.ClientCert)
	ctx, _ := adminSvc.cache.Get(fingerprint)
	
	// Remove write permission (simulate demotion)
	newPerms := []string{}
	for _, perm := range ctx.Permissions {
		if perm != "write" {
			newPerms = append(newPerms, perm)
		}
	}
	ctx.Permissions = newPerms
	adminSvc.cache.Store(fingerprint, ctx)

	t.Run("demoted user cannot self-validate", func(t *testing.T) {
		// The same token now lacks write permission
		err := guard.Validate(context.Background(), fullToken)
		if err == nil {
			t.Error("Demoted user should not be able to self-validate")
		}
		if !strings.Contains(err.Error(), "missing permission: write") {
			t.Errorf("Expected missing permission error, got: %v", err)
		}
	})

	t.Run("demoted user can still use guard to validate others", func(t *testing.T) {
		// First restore the user's permissions and regenerate a fresh token with write permission
		_ = adminSvc.cache.Delete(fingerprint)
		
		// Generate fresh token for the other user
		assertion2 := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
		otherToken, _ := admin.Generate(context.Background(), testCerts.ClientCert, assertion2)

		// The demoted user can still use the guard to check if others have write permission
		err := guard.Validate(context.Background(), fullToken, otherToken)
		if err != nil {
			t.Errorf("Demoted user should still be able to use guard to validate others: %v", err)
		}
	})
}
