package sctx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/zoobzio/capitan"
)

// TestMain sets up capitan in sync mode for all tests.
func TestMain(m *testing.M) {
	capitan.Configure(capitan.WithSyncMode())
	os.Exit(m.Run())
}

func TestEvents_TokenGenerated(t *testing.T) {
	resetAdminForTesting()

	var received bool
	var fingerprint, commonName string

	listener := capitan.Hook(TokenGenerated, func(_ context.Context, e *capitan.Event) {
		received = true
		fingerprint, _ = FingerprintKey.From(e)
		commonName, _ = CommonNameKey.From(e)
	})
	defer listener.Close()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)

	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	_, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if !received {
		t.Error("TokenGenerated not emitted")
	}
	if fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}
	if commonName != testCerts.ClientCert.Subject.CommonName {
		t.Errorf("expected commonName %q, got %q", testCerts.ClientCert.Subject.CommonName, commonName)
	}
}

func TestEvents_TokenRejected(t *testing.T) {
	resetAdminForTesting()

	var received bool
	var errorMsg string

	listener := capitan.Hook(TokenRejected, func(_ context.Context, e *capitan.Event) {
		received = true
		errorMsg, _ = ErrorKey.From(e)
	})
	defer listener.Close()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)
	adminSvc := admin.(*adminService[any])

	// Try to decrypt an invalid token
	_, _ = adminSvc.decryptToken(context.Background(), "invalid:token")

	if !received {
		t.Error("TokenRejected not emitted")
	}
	if errorMsg == "" {
		t.Error("error message should not be empty")
	}
}

func TestEvents_GuardCreated(t *testing.T) {
	resetAdminForTesting()

	var received bool
	var guardID, fingerprint string

	listener := capitan.Hook(GuardCreated, func(_ context.Context, e *capitan.Event) {
		received = true
		guardID, _ = GuardIDKey.From(e)
		fingerprint, _ = FingerprintKey.From(e)
	})
	defer listener.Close()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)

	// Set policy that grants read permission
	_ = admin.SetPolicy(func(_ *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	token, _ := admin.Generate(context.Background(), testCerts.ClientCert, assertion)

	_, err := admin.CreateGuard(context.Background(), token, "read")
	if err != nil {
		t.Fatalf("CreateGuard failed: %v", err)
	}

	if !received {
		t.Error("GuardCreated not emitted")
	}
	if guardID == "" {
		t.Error("guardID should not be empty")
	}
	if fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}
}

func TestEvents_GuardValidated(t *testing.T) {
	resetAdminForTesting()

	var received bool
	var guardID string

	listener := capitan.Hook(GuardValidated, func(_ context.Context, e *capitan.Event) {
		received = true
		guardID, _ = GuardIDKey.From(e)
	})
	defer listener.Close()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)

	// Set policy that grants read permission
	_ = admin.SetPolicy(func(_ *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	token, _ := admin.Generate(context.Background(), testCerts.ClientCert, assertion)

	guard, err := admin.CreateGuard(context.Background(), token, "read")
	if err != nil {
		t.Fatalf("CreateGuard failed: %v", err)
	}

	err = guard.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if !received {
		t.Error("GuardValidated not emitted")
	}
	if guardID == "" {
		t.Error("guardID should not be empty")
	}
}

func TestEvents_GuardRejected(t *testing.T) {
	resetAdminForTesting()

	var received bool
	var guardID, errorMsg string

	listener := capitan.Hook(GuardRejected, func(_ context.Context, e *capitan.Event) {
		received = true
		guardID, _ = GuardIDKey.From(e)
		errorMsg, _ = ErrorKey.From(e)
	})
	defer listener.Close()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)

	// Set policy that grants read permission
	_ = admin.SetPolicy(func(_ *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	token, _ := admin.Generate(context.Background(), testCerts.ClientCert, assertion)

	guard, err := admin.CreateGuard(context.Background(), token, "read")
	if err != nil {
		t.Fatalf("CreateGuard failed: %v", err)
	}

	// Validate with no tokens (should fail)
	_ = guard.Validate(context.Background())

	if !received {
		t.Error("GuardRejected not emitted")
	}
	if guardID == "" {
		t.Error("guardID should not be empty")
	}
	if errorMsg == "" {
		t.Error("error message should not be empty")
	}
}

func TestEvents_AssertionValidated(t *testing.T) {
	resetAdminForTesting()

	var received bool
	var fingerprint string

	listener := capitan.Hook(AssertionValidated, func(_ context.Context, e *capitan.Event) {
		received = true
		fingerprint, _ = FingerprintKey.From(e)
	})
	defer listener.Close()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)

	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	_, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if !received {
		t.Error("AssertionValidated not emitted")
	}
	if fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}
}

func TestEvents_AssertionRejected(t *testing.T) {
	resetAdminForTesting()

	var received bool
	var errorMsg string

	listener := capitan.Hook(AssertionRejected, func(_ context.Context, e *capitan.Event) {
		received = true
		errorMsg, _ = ErrorKey.From(e)
	})
	defer listener.Close()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)
	adminSvc := admin.(*adminService[any])

	// Create assertion with wrong fingerprint
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	assertion.Claims.Fingerprint = "wrong-fingerprint"

	// Re-sign with modified claims
	assertion, _ = signAssertion(assertion.Claims, testCerts.ClientKey)

	// This will fail fingerprint validation
	_ = ValidateAssertion(context.Background(), assertion, testCerts.ClientCert, adminSvc)

	if !received {
		t.Error("AssertionRejected not emitted")
	}
	if errorMsg == "" {
		t.Error("error message should not be empty")
	}
}

func TestEvents_CertificateRejected(t *testing.T) {
	resetAdminForTesting()

	var received bool
	var errorMsg string

	listener := capitan.Hook(CertificateRejected, func(_ context.Context, e *capitan.Event) {
		received = true
		errorMsg, _ = ErrorKey.From(e)
	})
	defer listener.Close()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	// Create admin with empty cert pool so certificate verification fails
	emptyCertPool := testCerts.CertPool // Use the pool but the cert will be self-signed differently
	admin, _ := NewAdminService[any](privateKey, emptyCertPool)

	// Generate a separate self-signed cert that's not in the pool
	untrustedCerts := GenerateTestCertificates(t)

	assertion := createTestAssertion(t, untrustedCerts.ClientKey, untrustedCerts.ClientCert)
	_, _ = admin.Generate(context.Background(), untrustedCerts.ClientCert, assertion)

	if !received {
		t.Error("CertificateRejected not emitted")
	}
	if errorMsg == "" {
		t.Error("error message should not be empty")
	}
}

func TestEvents_ContextRevoked(t *testing.T) {
	resetAdminForTesting()

	var received bool
	var fingerprint string

	listener := capitan.Hook(ContextRevoked, func(_ context.Context, e *capitan.Event) {
		received = true
		fingerprint, _ = FingerprintKey.From(e)
	})
	defer listener.Close()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)
	adminSvc := admin.(*adminService[any])

	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	_, _ = admin.Generate(context.Background(), testCerts.ClientCert, assertion)

	fp := getFingerprint(testCerts.ClientCert)
	_ = adminSvc.RevokeByFingerprint(context.Background(), fp)

	if !received {
		t.Error("ContextRevoked not emitted")
	}
	if fingerprint != fp {
		t.Errorf("expected fingerprint %q, got %q", fp, fingerprint)
	}
}

func TestEvents_CacheOperations(t *testing.T) {
	resetAdminForTesting()

	var storedReceived, hitReceived, missReceived, deletedReceived bool

	storeListener := capitan.Hook(CacheStored, func(_ context.Context, _ *capitan.Event) {
		storedReceived = true
	})
	defer storeListener.Close()

	hitListener := capitan.Hook(CacheHit, func(_ context.Context, _ *capitan.Event) {
		hitReceived = true
	})
	defer hitListener.Close()

	missListener := capitan.Hook(CacheMiss, func(_ context.Context, _ *capitan.Event) {
		missReceived = true
	})
	defer missListener.Close()

	deleteListener := capitan.Hook(CacheDeleted, func(_ context.Context, _ *capitan.Event) {
		deletedReceived = true
	})
	defer deleteListener.Close()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)
	adminSvc := admin.(*adminService[any])

	// Generate triggers store
	assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)
	_, _ = admin.Generate(context.Background(), testCerts.ClientCert, assertion)

	if !storedReceived {
		t.Error("CacheStored not emitted")
	}

	// GetContext triggers hit
	fp := getFingerprint(testCerts.ClientCert)
	_, _ = adminSvc.GetContext(context.Background(), fp)

	if !hitReceived {
		t.Error("CacheHit not emitted")
	}

	// GetContext with unknown fingerprint triggers miss
	_, _ = adminSvc.GetContext(context.Background(), "unknown-fingerprint")

	if !missReceived {
		t.Error("CacheMiss not emitted")
	}

	// RevokeByFingerprint triggers delete
	_ = adminSvc.RevokeByFingerprint(context.Background(), fp)

	if !deletedReceived {
		t.Error("CacheDeleted not emitted")
	}
}
