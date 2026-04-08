package sctx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestGenerateTrusted(t *testing.T) {
	resetAdminForTesting()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	admin, err := NewAdminService[any](privateKey, testCerts.CertPool)
	if err != nil {
		t.Fatalf("failed to create admin service: %v", err)
	}

	t.Run("generates token from trusted cert", func(t *testing.T) {
		token, err := admin.GenerateTrusted(context.Background(), testCerts.ClientCert)
		if err != nil {
			t.Fatalf("GenerateTrusted failed: %v", err)
		}
		if token == "" {
			t.Fatal("expected non-empty token")
		}
	})

	t.Run("nil cert returns error", func(t *testing.T) {
		_, err := admin.GenerateTrusted(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil cert")
		}
	})

	t.Run("untrusted cert returns error", func(t *testing.T) {
		// Generate a cert signed by a different CA
		otherPub, otherKey, _ := ed25519.GenerateKey(rand.Reader)
		otherCATemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(100),
			Subject:               pkix.Name{Organization: []string{"Other CA"}},
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		otherCADER, _ := x509.CreateCertificate(rand.Reader, otherCATemplate, otherCATemplate, otherPub, otherKey)
		otherCA, _ := x509.ParseCertificate(otherCADER)

		clientPub, _, _ := ed25519.GenerateKey(rand.Reader)
		clientTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(101),
			Subject:      pkix.Name{CommonName: "untrusted-client"},
			NotBefore:    time.Now().Add(-24 * time.Hour),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
		}
		clientDER, _ := x509.CreateCertificate(rand.Reader, clientTemplate, otherCA, clientPub, otherKey)
		clientCert, _ := x509.ParseCertificate(clientDER)

		_, err := admin.GenerateTrusted(context.Background(), clientCert)
		if err == nil {
			t.Fatal("expected error for untrusted cert")
		}
	})

	t.Run("applies policy", func(t *testing.T) {
		resetAdminForTesting()

		_, pk, _ := ed25519.GenerateKey(rand.Reader)
		a, _ := NewAdminService[any](pk, testCerts.CertPool)
		_ = a.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
			return &Context[any]{
				CertificateInfo:        extractCertificateInfo(cert),
				CertificateFingerprint: getFingerprint(cert),
				IssuedAt:               time.Now(),
				ExpiresAt:              time.Now().Add(time.Hour),
				Permissions:            []string{"trusted:read", "trusted:write"},
			}, nil
		})

		token, err := a.GenerateTrusted(context.Background(), testCerts.ClientCert)
		if err != nil {
			t.Fatalf("GenerateTrusted failed: %v", err)
		}

		// Verify the context was cached with correct permissions
		fp := getFingerprint(testCerts.ClientCert)
		sctx, exists := a.GetContext(context.Background(), fp)
		if !exists {
			t.Fatal("expected context to be cached")
		}
		if !sctx.HasPermission("trusted:read") || !sctx.HasPermission("trusted:write") {
			t.Fatalf("expected trusted permissions, got %v", sctx.Permissions)
		}

		// Verify the token is valid (usable with guards)
		guard, err := a.CreateGuard(context.Background(), token, "trusted:read")
		if err != nil {
			t.Fatalf("failed to create guard from trusted token: %v", err)
		}
		if err := guard.Validate(context.Background(), token); err != nil {
			t.Fatalf("guard validation failed for trusted token: %v", err)
		}
	})

	t.Run("returns cached token", func(t *testing.T) {
		resetAdminForTesting()

		_, pk, _ := ed25519.GenerateKey(rand.Reader)
		a, _ := NewAdminService[any](pk, testCerts.CertPool)

		token1, err := a.GenerateTrusted(context.Background(), testCerts.ClientCert)
		if err != nil {
			t.Fatalf("first GenerateTrusted failed: %v", err)
		}

		token2, err := a.GenerateTrusted(context.Background(), testCerts.ClientCert)
		if err != nil {
			t.Fatalf("second GenerateTrusted failed: %v", err)
		}

		// Both should succeed (second uses cache), but tokens may differ (new nonce each time)
		if token1 == "" || token2 == "" {
			t.Fatal("expected non-empty tokens")
		}
	})

	t.Run("no policy returns error", func(t *testing.T) {
		resetAdminForTesting()

		_, pk, _ := ed25519.GenerateKey(rand.Reader)
		a, _ := NewAdminService[any](pk, testCerts.CertPool)
		_ = a.SetPolicy(nil) // This should fail, but let's test the ErrNoPolicy path

		// The default policy is set during creation, so we need to nil it out
		adminSvc := a.(*adminService[any])
		adminSvc.policyMu.Lock()
		adminSvc.policy = nil
		adminSvc.policyMu.Unlock()

		// Use a fresh cert so there's no cache hit
		freshCert, _ := GenerateAdditionalClientCert(t, testCerts, "fresh-client")
		_, err := a.GenerateTrusted(context.Background(), freshCert)
		if err == nil {
			t.Fatal("expected ErrNoPolicy")
		}
	})
}

func TestInjectToken(t *testing.T) {
	t.Run("inject and extract", func(t *testing.T) {
		token := SignedToken("test-token-value")
		ctx := InjectToken(context.Background(), token)

		extracted, ok := TokenFromContext(ctx)
		if !ok {
			t.Fatal("expected token in context")
		}
		if extracted != token {
			t.Fatalf("expected %q, got %q", token, extracted)
		}
	})

	t.Run("overwrites existing token", func(t *testing.T) {
		token1 := SignedToken("token-1")
		token2 := SignedToken("token-2")

		ctx := InjectToken(context.Background(), token1)
		ctx = InjectToken(ctx, token2)

		extracted, ok := TokenFromContext(ctx)
		if !ok {
			t.Fatal("expected token in context")
		}
		if extracted != token2 {
			t.Fatalf("expected %q, got %q", token2, extracted)
		}
	})
}

func TestGenerateTrustedWithInjectToken(t *testing.T) {
	resetAdminForTesting()

	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)
	_ = admin.SetPolicy(func(cert *x509.Certificate) (*Context[any], error) {
		return &Context[any]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(time.Hour),
			Permissions:            []string{"read", "write"},
		}, nil
	})

	// Server-side flow: mTLS cert -> token -> inject into context
	token, err := admin.GenerateTrusted(context.Background(), testCerts.ClientCert)
	if err != nil {
		t.Fatalf("GenerateTrusted failed: %v", err)
	}

	ctx := InjectToken(context.Background(), token)

	// Downstream handler extracts token
	extracted, ok := TokenFromContext(ctx)
	if !ok {
		t.Fatal("expected token in context")
	}
	if extracted != token {
		t.Fatal("extracted token does not match")
	}

	// Guard can validate the extracted token
	guard, err := admin.CreateGuard(context.Background(), token, "read")
	if err != nil {
		t.Fatalf("failed to create guard: %v", err)
	}
	if err := guard.Validate(context.Background(), extracted); err != nil {
		t.Fatalf("guard validation failed: %v", err)
	}
}
