package sctx

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"sync"
	"testing"
	"time"
)

// TestCacheCleanup tests the cache cleanup functionality
func TestCacheCleanup(t *testing.T) {
	// Create cache with very short cleanup interval
	cache := newMemoryContextCache[any](100 * time.Millisecond)

	// Create contexts with different expiry times
	ctx1 := &Context[any]{
		ExpiresAt: time.Now().Add(-time.Hour), // Already expired
		CertificateInfo: CertificateInfo{
			CommonName: "expired-context",
		},
	}

	ctx2 := &Context[any]{
		ExpiresAt: time.Now().Add(time.Hour), // Still valid
		CertificateInfo: CertificateInfo{
			CommonName: "valid-context",
		},
	}

	// Store contexts
	cache.Store("expired", ctx1)
	cache.Store("valid", ctx2)

	// Verify both exist
	memCache := cache.(*memoryContextCache[any])
	if memCache.Count() != 2 {
		t.Errorf("Expected 2 contexts, got %d", memCache.Count())
	}

	// Start cleanup
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	cache.Start(shutdown, &wg)

	// Wait for cleanup to run at least once
	time.Sleep(200 * time.Millisecond)

	// Check that expired context was removed
	if _, exists := cache.Get("expired"); exists {
		t.Error("Expired context should have been cleaned up")
	}

	// Check that valid context still exists
	if _, exists := cache.Get("valid"); !exists {
		t.Error("Valid context should still exist")
	}

	// Test shutdown
	close(shutdown)
	wg.Wait()
}

// TestNewMemoryContextCacheDefaultInterval tests default cleanup interval
func TestNewMemoryContextCacheDefaultInterval(t *testing.T) {
	// Create cache with zero interval (should use default)
	cache := newMemoryContextCache[any](0)

	// Verify it's created (can't easily test the interval value)
	if cache == nil {
		t.Error("Cache should be created with default interval")
	}

	memCache := cache.(*memoryContextCache[any])
	if memCache.cleanupInterval == 0 {
		t.Error("Cleanup interval should not be zero")
	}
}

// TestContextHasPermission tests the HasPermission method
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

// TestContextCloneEdgeCases tests remaining edge cases in Clone
func TestContextCloneEdgeCases(t *testing.T) {
	// Test cloning nil context
	var nilCtx *Context[any]
	cloned := nilCtx.Clone()
	if cloned != nil {
		t.Error("Cloning nil context should return nil")
	}
}

// TestEncodeAndSignEdgeCases tests edge cases in encodeAndSign
func TestEncodeAndSignEdgeCases(t *testing.T) {
	resetAdminForTesting()
	// This function is internal but we can test it through the admin service
	testCerts := GenerateTestCertificates(t)

	// Test with ECDSA signer
	_, ecdsaKey, _ := GenerateKeyPair(CryptoECDSAP256)
	admin, _ := NewAdminService[any](ecdsaKey, testCerts.CertPool)
	adminSvc := admin.(*adminService[any])

	// Create a context
	ctx := &Context[any]{
		CertificateFingerprint: "test-fingerprint",
		ExpiresAt:              time.Now().Add(time.Hour),
	}

	// Test token creation
	token, err := adminSvc.createToken(ctx)
	if err != nil {
		t.Errorf("Failed to create token: %v", err)
	}
	if token == "" {
		t.Error("Token should not be empty")
	}
}

// TestVerifyTokenPayloadEdgeCases tests edge cases in verifyTokenPayload
func TestVerifyTokenPayloadEdgeCases(t *testing.T) {
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
	type unsupportedKey struct{}
	_, err := verifyTokenPayload("payload:signature", unsupportedKey{})
	if err == nil {
		t.Error("Should fail with unsupported key type")
	}
}

// TestGetFingerprintEdgeCases tests edge cases
func TestGetFingerprintEdgeCases(t *testing.T) {
	// Test with nil certificate
	fingerprint := getFingerprint(nil)
	if fingerprint != "" {
		t.Error("Fingerprint of nil certificate should be empty")
	}
}

// TestExtractCertificateInfoEdgeCases tests edge cases
func TestExtractCertificateInfoEdgeCases(t *testing.T) {
	// Test with nil certificate
	info := extractCertificateInfo(nil)
	if info.CommonName != "" {
		t.Error("Info from nil certificate should be empty")
	}

	// Test with certificate having various key usages
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

	// Self-sign the certificate
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, testPublicKey, testPrivateKey)
	cert, _ := x509.ParseCertificate(certDER)

	info = extractCertificateInfo(cert)

	// Check all key usages were extracted
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
}

// TestGenerateContextID tests context ID generation
func TestGenerateContextID(t *testing.T) {
	// Test normal operation
	id1 := generateContextID()
	if id1 == "" {
		t.Error("Generated ID should not be empty")
	}

	// Generate another ID and ensure they're different
	id2 := generateContextID()
	if id1 == id2 {
		t.Error("Generated IDs should be unique")
	}

	// Test that IDs are valid base64
	decoded, err := base64.URLEncoding.DecodeString(id1)
	if err != nil {
		t.Errorf("Generated ID should be valid base64: %v", err)
	}
	if len(decoded) != 16 {
		t.Errorf("Decoded ID should be 16 bytes, got %d", len(decoded))
	}
}

// Test helper keys
var (
	testPublicKey, testPrivateKey, _ = GenerateKeyPair(CryptoEd25519)
)
