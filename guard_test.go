package sctx

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

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
	err = admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
  - ref: grant-write
  - ref: grant-admin
`)
	if err != nil {
		t.Fatalf("Failed to load context schema: %v", err)
	}

	t.Run("basic guard creation", func(t *testing.T) {
		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token
		token, err := admin.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Create guard
		guard, err := admin.CreateGuard(token, "read")
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
		token1, err := admin.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Create guard for read/write
		guard, err := admin.CreateGuard(token1, "read", "write")
		if err != nil {
			t.Fatalf("Failed to create guard: %v", err)
		}

		// Token1 should pass (has read, write, admin)
		err = guard.Validate(token1)
		if err != nil {
			t.Errorf("Guard should validate token with required permissions: %v", err)
		}

		// To test limited permissions, we need to create a new context
		// with limited permissions in the same admin instance

		// First revoke the existing context to clear cache
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(testCerts.ClientCert)
		_ = adminSvc.cache.Delete(fingerprint)

		// Temporarily modify the pipeline to grant only read
		originalPipeline := adminSvc.contextPipeline
		err = admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
`)
		if err != nil {
			t.Fatalf("Failed to load limited schema: %v", err)
		}

		// Create new assertion for limited token
		assertion2 := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate new limited token
		token2, err := admin.Generate(testCerts.ClientCert, assertion2)
		if err != nil {
			t.Fatalf("Failed to generate limited token: %v", err)
		}

		// Token2 should fail (missing write permission)
		err = guard.Validate(token2)
		if err == nil {
			t.Error("Guard should reject token without required permissions")
		}
		if err.Error() != "missing permission: write" {
			t.Errorf("Expected specific permission error, got: %v", err)
		}

		// Restore original pipeline
		adminSvc.contextPipeline = originalPipeline
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
		tokenAdmin, err := admin.Generate(testCerts.ClientCert, assertionAdmin)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		guard, err := admin.CreateGuard(tokenAdmin, "read")
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
		originalPipeline := adminSvc.contextPipeline
		err = admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
`)
		if err != nil {
			t.Fatalf("Failed to load schema: %v", err)
		}

		// Create assertion for limited token
		assertionLimited := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		tokenLimited, err := admin.Generate(testCerts.ClientCert, assertionLimited)
		if err != nil {
			t.Fatalf("Failed to generate limited token: %v", err)
		}

		// Should fail without admin permission
		_, err = admin.CreateGuard(tokenLimited, "read")
		if err == nil {
			t.Error("Should not be able to create guard without required permissions")
		}
		if err.Error() != "missing required permission to create guards: admin" {
			t.Errorf("Expected specific permission error, got: %v", err)
		}

		// Restore original pipeline
		adminSvc.contextPipeline = originalPipeline
	})

	t.Run("cannot create guard for permissions you don't have", func(t *testing.T) {
		// Clear guard creation permissions
		admin.SetGuardCreationPermissions(nil)

		// To test permission limitation, modify the current admin's pipeline
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(testCerts.ClientCert)
		_ = adminSvc.cache.Delete(fingerprint)

		// Temporarily modify pipeline to grant only read
		originalPipeline := adminSvc.contextPipeline
		err = admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
`)
		if err != nil {
			t.Fatalf("Failed to load schema: %v", err)
		}

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		token, err := admin.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Try to create guard for "write" permission (which token doesn't have)
		_, err = admin.CreateGuard(token, "write")
		if err == nil {
			t.Error("Should not be able to create guard for permission you don't have")
		}
		if err.Error() != "cannot create guard for permission you don't have: write" {
			t.Errorf("Expected specific error, got: %v", err)
		}

		// Restore original pipeline
		adminSvc.contextPipeline = originalPipeline
	})

	t.Run("expired token", func(t *testing.T) {
		// To test expired token, modify existing context
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(testCerts.ClientCert)
		_ = adminSvc.cache.Delete(fingerprint)

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate new token
		token, err := admin.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Manually expire the context
		ctx, _ := adminSvc.cache.Get(fingerprint)
		ctx.ExpiresAt = ctx.IssuedAt // Expire immediately
		adminSvc.cache.Store(fingerprint, ctx)

		// Try to create guard with expired token
		_, err = admin.CreateGuard(token, "read")
		if err == nil {
			t.Error("Should not be able to create guard with expired token")
		}
		if err.Error() != "token expired" {
			t.Errorf("Expected expiration error, got: %v", err)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		// Try with invalid token
		_, err := admin.CreateGuard("invalid-token", "read")
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
	err = admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
  - ref: grant-write
  - ref: grant-admin
`)
	if err != nil {
		t.Fatalf("Failed to load context schema: %v", err)
	}

	// Create assertion
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

	// Generate token and create guard
	token, err := admin.Generate(testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	guard, err := admin.CreateGuard(token, "read", "write")
	if err != nil {
		t.Fatalf("Failed to create guard: %v", err)
	}

	t.Run("valid token passes", func(t *testing.T) {
		err := guard.Validate(token)
		if err != nil {
			t.Errorf("Valid token should pass validation: %v", err)
		}
	})

	t.Run("invalid token format", func(t *testing.T) {
		err := guard.Validate("not-a-valid-token")
		if err == nil {
			t.Error("Invalid token should fail validation")
		}
		if err.Error() != "invalid token: invalid context format" {
			t.Errorf("Expected invalid token error, got: %v", err)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		// Manually expire the context
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(testCerts.ClientCert)
		ctx, _ := adminSvc.cache.Get(fingerprint)
		ctx.ExpiresAt = ctx.IssuedAt // Expire immediately
		adminSvc.cache.Store(fingerprint, ctx)

		err := guard.Validate(token)
		if err == nil {
			t.Error("Expired token should fail validation")
		}
		if err.Error() != "token expired" {
			t.Errorf("Expected expiration error, got: %v", err)
		}
	})

	t.Run("missing permissions", func(t *testing.T) {
		// To test with limited permissions, modify the current admin's pipeline
		// First clear the cache
		adminSvc := admin.(*adminService[any])
		fingerprint := getFingerprint(testCerts.ClientCert)
		_ = adminSvc.cache.Delete(fingerprint)

		// Temporarily modify pipeline
		originalPipeline := adminSvc.contextPipeline
		err = admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
`)
		if err != nil {
			t.Fatalf("Failed to load schema: %v", err)
		}

		// Create assertion for limited token
		assertionLimited := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		limitedToken, err := admin.Generate(testCerts.ClientCert, assertionLimited)
		if err != nil {
			t.Fatalf("Failed to generate limited token: %v", err)
		}

		// Guard requires read AND write, token only has read
		err = guard.Validate(limitedToken)
		if err == nil {
			t.Error("Token without required permissions should fail")
		}
		if err.Error() != "missing permission: write" {
			t.Errorf("Expected missing permission error, got: %v", err)
		}

		// Restore original pipeline
		adminSvc.contextPipeline = originalPipeline
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
