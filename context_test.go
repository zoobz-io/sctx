package sctx

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"
)

// Test helper keys for context tests.
var (
	contextTestPublicKey, contextTestPrivateKey, _ = GenerateKeyPair(CryptoEd25519)
)

// TestContextHasPermission tests the HasPermission method.
func TestContextHasPermission(t *testing.T) {
	ctx := &Context[any]{
		Permissions: []string{"read", "write", "admin"},
	}

	tests := []struct {
		name       string
		permission string
		expected   bool
	}{
		{"Has read", "read", true},
		{"Has write", "write", true},
		{"Has admin", "admin", true},
		{"Doesn't have delete", "delete", false},
		{"Empty permission", "", false},
		{"Case sensitive", "READ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ctx.HasPermission(tt.permission); got != tt.expected {
				t.Errorf("HasPermission(%q) = %v, want %v", tt.permission, got, tt.expected)
			}
		})
	}

	// Test with nil permissions
	emptyCtx := &Context[any]{}
	if emptyCtx.HasPermission("read") {
		t.Error("Context with nil permissions should not have any permission")
	}
}

// TestContextIsExpired tests the IsExpired method.
func TestContextIsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{"Not expired (future)", time.Now().Add(time.Hour), false},
		{"Expired (past)", time.Now().Add(-time.Hour), true},
		{"Just expired (1 second ago)", time.Now().Add(-time.Second), true},
		{"About to expire (1 second from now)", time.Now().Add(time.Second), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &Context[any]{
				ExpiresAt: tt.expiresAt,
			}
			if got := ctx.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestContextClone tests the Clone method.
func TestContextClone(t *testing.T) {
	t.Run("Clone nil context", func(t *testing.T) {
		var nilCtx *Context[any]
		cloned := nilCtx.Clone()
		if cloned != nil {
			t.Error("Cloning nil context should return nil")
		}
	})

	t.Run("Clone with all fields", func(t *testing.T) {
		original := &Context[any]{
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(time.Hour),
			CertificateFingerprint: "test-fingerprint",
			Permissions:            []string{"read", "write"},
			CertificateInfo: CertificateInfo{
				CommonName:         "test-cn",
				Organization:       []string{"org1", "org2"},
				OrganizationalUnit: []string{"ou1"},
				Country:            "US",
				Province:           "CA",
				Locality:           "SF",
				StreetAddress:      []string{"123 Main St"},
				PostalCode:         []string{"12345"},
				SerialNumber:       "123",
				NotBefore:          time.Now(),
				NotAfter:           time.Now().Add(time.Hour),
				Issuer:             "issuer-cn",
				IssuerOrganization: []string{"issuer-org"},
				KeyUsage:           []string{"digital_signature"},
				DNSNames:           []string{"example.com"},
				EmailAddresses:     []string{"test@example.com"},
				URIs:               []string{"https://example.com"},
				IPAddresses:        []string{"192.168.1.1"},
			},
		}

		cloned := original.Clone()

		// Verify values match
		if cloned.CertificateFingerprint != original.CertificateFingerprint {
			t.Error("Fingerprint mismatch")
		}
		if len(cloned.Permissions) != len(original.Permissions) {
			t.Error("Permissions length mismatch")
		}
		if cloned.CertificateInfo.CommonName != original.CertificateInfo.CommonName {
			t.Error("CommonName mismatch")
		}

		// Verify deep copy (modifying clone shouldn't affect original)
		cloned.Permissions[0] = "modified"
		if original.Permissions[0] == "modified" {
			t.Error("Clone should be a deep copy - modifying clone affected original")
		}

		cloned.CertificateInfo.Organization[0] = "modified"
		if original.CertificateInfo.Organization[0] == "modified" {
			t.Error("Clone should deep copy CertificateInfo.Organization")
		}
	})
}

// TestEncodeAndSign tests token encoding and signing.
func TestEncodeAndSign(t *testing.T) {
	resetAdminForTesting()
	testCerts := GenerateTestCertificates(t)

	t.Run("Ed25519 signer", func(t *testing.T) {
		resetAdminForTesting()
		_, ed25519Key, _ := GenerateKeyPair(CryptoEd25519)
		admin, _ := NewAdminService[any](ed25519Key, testCerts.CertPool)
		adminSvc := admin.(*adminService[any])

		ctx := &Context[any]{
			CertificateFingerprint: "test-fingerprint",
			ExpiresAt:              time.Now().Add(time.Hour),
		}

		token, err := adminSvc.createToken(ctx)
		if err != nil {
			t.Errorf("Failed to create token: %v", err)
		}
		if token == "" {
			t.Error("Token should not be empty")
		}
	})

	t.Run("ECDSA signer", func(t *testing.T) {
		resetAdminForTesting()
		_, ecdsaKey, _ := GenerateKeyPair(CryptoECDSAP256)
		admin, _ := NewAdminService[any](ecdsaKey, testCerts.CertPool)
		adminSvc := admin.(*adminService[any])

		ctx := &Context[any]{
			CertificateFingerprint: "test-fingerprint",
			ExpiresAt:              time.Now().Add(time.Hour),
		}

		token, err := adminSvc.createToken(ctx)
		if err != nil {
			t.Errorf("Failed to create token: %v", err)
		}
		if token == "" {
			t.Error("Token should not be empty")
		}
	})
}

// TestVerifyTokenPayload tests token verification.
func TestVerifyTokenPayload(t *testing.T) {
	// Test with malformed tokens
	tests := []struct {
		name  string
		token SignedToken
	}{
		{"Empty token", ""},
		{"No colon", "noColon"},
		{"Multiple colons", "part1:part2:part3"},
		{"Invalid base64 payload", "!invalid!:signature"},
		{"Invalid base64 signature", "payload:!invalid!"},
		{"Valid base64 but invalid JSON", "aW52YWxpZA==:signature"},
	}

	// Generate a key for testing
	_, pubKey, _ := GenerateKeyPair(CryptoEd25519)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifyTokenPayload(tt.token, pubKey)
			if err == nil {
				t.Error("Should fail with malformed token")
			}
		})
	}

	// Test with unsupported public key type
	t.Run("Unsupported key type", func(t *testing.T) {
		type unsupportedKey struct{}
		_, err := verifyTokenPayload("payload:signature", unsupportedKey{})
		if err == nil {
			t.Error("Should fail with unsupported key type")
		}
	})
}

// TestVerifyTokenPayloadExpired tests expired token verification.
func TestVerifyTokenPayloadExpired(t *testing.T) {
	resetAdminForTesting()
	testCerts := GenerateTestCertificates(t)

	_, privateKey, _ := GenerateKeyPair(CryptoEd25519)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)
	adminSvc := admin.(*adminService[any])

	// Create an expired token
	expiredPayload := &tokenPayload{
		Fingerprint: "test-fingerprint",
		IssuedAt:    time.Now().Add(-2 * time.Hour),
		Expiry:      time.Now().Add(-time.Hour), // Expired
		Nonce:       generateContextID(),
	}

	token, err := encodeAndSign(expiredPayload, adminSvc.signer)
	if err != nil {
		t.Fatalf("Failed to encode token: %v", err)
	}

	_, err = verifyTokenPayload(token, adminSvc.publicKey)
	if !errors.Is(err, ErrExpiredContext) {
		t.Errorf("Expected ErrExpiredContext, got %v", err)
	}
}

// TestGetFingerprint tests fingerprint calculation.
func TestGetFingerprint(t *testing.T) {
	t.Run("Nil certificate", func(t *testing.T) {
		fingerprint := GetFingerprint(nil)
		if fingerprint != "" {
			t.Error("Fingerprint of nil certificate should be empty")
		}
	})

	t.Run("Valid certificate", func(t *testing.T) {
		testCerts := GenerateTestCertificates(t)
		fingerprint := GetFingerprint(testCerts.ClientCert)
		if fingerprint == "" {
			t.Error("Fingerprint should not be empty")
		}

		// Fingerprint should be deterministic
		fingerprint2 := GetFingerprint(testCerts.ClientCert)
		if fingerprint != fingerprint2 {
			t.Error("Fingerprint should be deterministic")
		}
	})

	t.Run("Different certificates have different fingerprints", func(t *testing.T) {
		testCerts := GenerateTestCertificates(t)
		fp1 := GetFingerprint(testCerts.ClientCert)
		fp2 := GetFingerprint(testCerts.RootCA)
		if fp1 == fp2 {
			t.Error("Different certificates should have different fingerprints")
		}
	})
}

// TestExtractCertificateInfo tests certificate info extraction.
func TestExtractCertificateInfo(t *testing.T) {
	t.Run("Nil certificate", func(t *testing.T) {
		info := extractCertificateInfo(nil)
		if info.CommonName != "" {
			t.Error("Info from nil certificate should be empty")
		}
	})

	t.Run("Certificate with all key usages", func(t *testing.T) {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "Test Cert",
			},
			Issuer: pkix.Name{
				CommonName: "Test Issuer",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature |
				x509.KeyUsageKeyEncipherment |
				x509.KeyUsageDataEncipherment |
				x509.KeyUsageCertSign,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageCodeSigning,
				x509.ExtKeyUsageEmailProtection,
			},
		}

		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, contextTestPublicKey, contextTestPrivateKey)
		cert, _ := x509.ParseCertificate(certDER)

		info := extractCertificateInfo(cert)

		expectedUsages := []string{
			"digital_signature",
			"key_encipherment",
			"data_encipherment",
			"cert_sign",
			"client_auth",
			"server_auth",
			"code_signing",
			"email_protection",
		}

		for _, usage := range expectedUsages {
			found := false
			for _, ku := range info.KeyUsage {
				if ku == usage {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected key usage %s not found", usage)
			}
		}
	})

	t.Run("Certificate with extensions", func(t *testing.T) {
		testCerts := GenerateTestCertificates(t)
		info := extractCertificateInfo(testCerts.ClientCert)

		if info.CommonName != testCerts.ClientCert.Subject.CommonName {
			t.Errorf("CommonName mismatch: got %q, want %q", info.CommonName, testCerts.ClientCert.Subject.CommonName)
		}

		if len(info.DNSNames) != len(testCerts.ClientCert.DNSNames) {
			t.Errorf("DNSNames count mismatch: got %d, want %d", len(info.DNSNames), len(testCerts.ClientCert.DNSNames))
		}
	})
}

// TestGenerateContextID tests context ID generation.
func TestGenerateContextID(t *testing.T) {
	t.Run("Non-empty", func(t *testing.T) {
		id := generateContextID()
		if id == "" {
			t.Error("Generated ID should not be empty")
		}
	})

	t.Run("Unique IDs", func(t *testing.T) {
		id1 := generateContextID()
		id2 := generateContextID()
		if id1 == id2 {
			t.Error("Generated IDs should be unique")
		}
	})

	t.Run("Valid base64", func(t *testing.T) {
		id := generateContextID()
		decoded, err := base64.URLEncoding.DecodeString(id)
		if err != nil {
			t.Errorf("Generated ID should be valid base64: %v", err)
		}
		if len(decoded) != 16 {
			t.Errorf("Decoded ID should be 16 bytes, got %d", len(decoded))
		}
	})
}

// TestDefaultContextPolicy tests the default policy function.
func TestDefaultContextPolicy(t *testing.T) {
	policy := DefaultContextPolicy[any]()

	t.Run("Nil certificate", func(t *testing.T) {
		_, err := policy(nil)
		if err == nil {
			t.Error("Policy should error on nil certificate")
		}
	})

	t.Run("Valid certificate", func(t *testing.T) {
		testCerts := GenerateTestCertificates(t)
		ctx, err := policy(testCerts.ClientCert)
		if err != nil {
			t.Errorf("Policy failed: %v", err)
		}

		if ctx == nil {
			t.Fatal("Context should not be nil")
		}

		// Check that fingerprint is set
		if ctx.CertificateFingerprint == "" {
			t.Error("Fingerprint should be set")
		}

		// Check that IssuedAt is set
		if ctx.IssuedAt.IsZero() {
			t.Error("IssuedAt should be set")
		}

		// Check that ExpiresAt is about 1 hour from now
		expectedExpiry := time.Now().Add(time.Hour)
		if ctx.ExpiresAt.Before(expectedExpiry.Add(-time.Minute)) || ctx.ExpiresAt.After(expectedExpiry.Add(time.Minute)) {
			t.Error("ExpiresAt should be approximately 1 hour from now")
		}

		// Check that permissions are empty by default
		if len(ctx.Permissions) != 0 {
			t.Error("Default policy should not grant any permissions")
		}

		// Check certificate info is populated
		if ctx.CertificateInfo.CommonName != testCerts.ClientCert.Subject.CommonName {
			t.Errorf("CommonName mismatch: got %q, want %q",
				ctx.CertificateInfo.CommonName, testCerts.ClientCert.Subject.CommonName)
		}
	})
}

// TestSignedTokenType tests the SignedToken type.
func TestSignedTokenType(t *testing.T) {
	// SignedToken is just a string alias, but verify it works as expected
	token := SignedToken("test:token")
	if string(token) != "test:token" {
		t.Error("SignedToken should be convertible to string")
	}
}

// TestCertificateInfoSerialization tests that CertificateInfo serializes correctly.
func TestCertificateInfoSerialization(t *testing.T) {
	testCerts := GenerateTestCertificates(t)
	info := extractCertificateInfo(testCerts.ClientCert)

	// Check that all fields are populated appropriately
	if info.SerialNumber == "" {
		t.Error("SerialNumber should be populated")
	}
	if info.NotBefore.IsZero() {
		t.Error("NotBefore should be populated")
	}
	if info.NotAfter.IsZero() {
		t.Error("NotAfter should be populated")
	}
	// IssuerOrganization should be populated from the root CA
	if len(info.IssuerOrganization) == 0 {
		t.Error("IssuerOrganization should be populated")
	}
}
