package sctx

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"
)

// TestAssertionContextClone tests the Clone method
func TestAssertionContextClone(t *testing.T) {
	// Create test certificate
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	// Create assertion
	assertion := SignedAssertion{
		Claims: AssertionClaims{
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(time.Minute),
			Nonce:       "test-nonce",
			Purpose:     "token-generation",
			Fingerprint: "test-fingerprint",
		},
		Signature: []byte("test-signature"),
	}

	// Create assertion context
	ac := &AssertionContext{
		Assertion:   assertion,
		Certificate: cert,
	}

	// Clone it
	cloned := ac.Clone()

	// Verify clone is a new instance
	if cloned == ac {
		t.Error("Clone should return a new instance")
	}

	// Verify fields are copied
	if cloned.Assertion.Claims.Nonce != ac.Assertion.Claims.Nonce {
		t.Error("Claims should be copied")
	}

	// Verify signature is a separate slice
	if len(cloned.Assertion.Signature) != len(ac.Assertion.Signature) {
		t.Error("Signature length should match")
	}

	// Modify original signature to ensure it's a copy
	originalSig := make([]byte, len(ac.Assertion.Signature))
	copy(originalSig, ac.Assertion.Signature)
	ac.Assertion.Signature[0] = 0xFF

	if cloned.Assertion.Signature[0] == 0xFF {
		t.Error("Signature should be a deep copy")
	}

	// Certificate should be the same reference (not cloned)
	if cloned.Certificate != ac.Certificate {
		t.Error("Certificate should be the same reference")
	}
}

// TestSignAssertionECDSA tests ECDSA path in signAssertion
func TestSignAssertionECDSA(t *testing.T) {
	// Generate ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	claims := AssertionClaims{
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Minute),
		Nonce:       "test-nonce",
		Purpose:     "token-generation",
		Fingerprint: "test-fingerprint",
	}

	// Sign with ECDSA
	assertion, err := signAssertion(claims, ecdsaKey)
	if err != nil {
		t.Fatalf("Failed to sign assertion with ECDSA: %v", err)
	}

	if len(assertion.Signature) == 0 {
		t.Error("ECDSA signature should not be empty")
	}

	// Verify claims were preserved
	if assertion.Claims.Nonce != claims.Nonce {
		t.Error("Claims should be preserved")
	}
}

// TestSignAssertionRSA tests RSA path in signAssertion
func TestSignAssertionRSA(t *testing.T) {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	claims := AssertionClaims{
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Minute),
		Nonce:       "test-nonce",
		Purpose:     "token-generation",
		Fingerprint: "test-fingerprint",
	}

	// Sign with RSA
	assertion, err := signAssertion(claims, rsaKey)
	if err != nil {
		t.Fatalf("Failed to sign assertion with RSA: %v", err)
	}

	if len(assertion.Signature) == 0 {
		t.Error("RSA signature should not be empty")
	}
}

// TestSignAssertionInvalidKey tests signAssertion with invalid key
func TestSignAssertionInvalidKey(t *testing.T) {
	claims := AssertionClaims{
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Minute),
		Nonce:       "test-nonce",
		Purpose:     "token-generation",
		Fingerprint: "test-fingerprint",
	}

	// Test with non-signer key type
	type invalidKey struct{}
	_, err := signAssertion(claims, invalidKey{})
	if err == nil {
		t.Error("Should fail with invalid key type")
	}
}

// TestSignAssertionSignerError tests signAssertion when Sign fails
func TestSignAssertionSignerError(t *testing.T) {
	claims := AssertionClaims{
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Minute),
		Nonce:       "test-nonce",
		Purpose:     "token-generation",
		Fingerprint: "test-fingerprint",
	}

	// Create a mock signer that returns an error
	mockSigner := &mockErrorSigner{}

	_, err := signAssertion(claims, mockSigner)
	if err == nil {
		t.Error("Should fail when signer returns error")
	}
}

// mockErrorSigner implements crypto.Signer but always returns an error
type mockErrorSigner struct{}

func (m *mockErrorSigner) Public() crypto.PublicKey {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return pub
}

func (m *mockErrorSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("mock sign error")
}

// TestCreateAssertionEdgeCases tests edge cases in CreateAssertion
func TestCreateAssertionEdgeCases(t *testing.T) {
	// Generate keys and cert
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	wrongPrivKey, _, _ := ed25519.GenerateKey(rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, privKey.Public(), privKey)
	cert, _ := x509.ParseCertificate(certDER)

	t.Run("Mismatched key and cert", func(t *testing.T) {
		_, err := CreateAssertion(wrongPrivKey, cert)
		if err == nil {
			t.Error("Should fail when private key doesn't match certificate")
		}
	})
}

// TestVerifyAssertionEdgeCases tests edge cases in verifyAssertion
func TestVerifyAssertionEdgeCases(t *testing.T) {
	// Create test certificate with Ed25519
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, privKey.Public(), privKey)
	cert, _ := x509.ParseCertificate(certDER)

	// Create a valid assertion
	assertion, _ := CreateAssertion(privKey, cert)

	t.Run("Invalid signature for Ed25519", func(t *testing.T) {
		// Corrupt the signature
		badAssertion := assertion
		badAssertion.Signature = []byte("invalid")

		err := verifyAssertion(badAssertion, cert)
		if err == nil {
			t.Error("Should fail with invalid signature")
		}
	})

	t.Run("Verify with ECDSA signature", func(t *testing.T) {
		// Create ECDSA cert
		ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ecdsaCertDER, _ := x509.CreateCertificate(rand.Reader, template, template, &ecdsaKey.PublicKey, ecdsaKey)
		ecdsaCert, _ := x509.ParseCertificate(ecdsaCertDER)

		// Create assertion with ECDSA
		ecdsaAssertion, _ := CreateAssertion(ecdsaKey, ecdsaCert)

		// Verify should work
		err := verifyAssertion(ecdsaAssertion, ecdsaCert)
		if err != nil {
			t.Errorf("Should verify ECDSA assertion: %v", err)
		}

		// Test with corrupted ECDSA signature
		badECDSA := ecdsaAssertion
		badECDSA.Signature = []byte("invalid")
		err = verifyAssertion(badECDSA, ecdsaCert)
		if err == nil {
			t.Error("Should fail with invalid ECDSA signature")
		}
	})
}

// TestCertificateMatchesKeyEdgeCases tests edge cases
func TestCertificateMatchesKeyEdgeCases(t *testing.T) {
	// Create certificate
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	// Test with key that doesn't implement Public() method
	type badKey struct{}
	if certificateMatchesKey(cert, badKey{}) {
		t.Error("Should return false for key without Public() method")
	}
}

// TestCheckNonceProcessorEdgeCases tests nonce processor edge cases
func TestCheckNonceProcessorEdgeCases(t *testing.T) {
	resetAdminForTesting()
	testCerts := GenerateTestCertificates(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	admin, _ := NewAdminService[any](privateKey, testCerts.CertPool)
	adminSvc := admin.(*adminService[any])

	processor := checkNonceProcessor(adminSvc)

	// Test with empty nonce
	ac := &AssertionContext{
		Assertion: SignedAssertion{
			Claims: AssertionClaims{
				Nonce: "",
			},
		},
	}

	_, err := processor.Process(context.Background(), ac)
	if err == nil {
		t.Error("Should fail with empty nonce")
	}

	// Test nonce cleanup by adding expired nonces
	adminSvc.nonceMu.Lock()
	// Add some expired nonces
	adminSvc.nonceCache["expired1"] = time.Now().Add(-time.Hour)
	adminSvc.nonceCache["expired2"] = time.Now().Add(-time.Hour)
	adminSvc.nonceCache["valid"] = time.Now().Add(time.Hour)
	adminSvc.nonceMu.Unlock()

	// Process a new nonce - should trigger cleanup
	ac2 := &AssertionContext{
		Assertion: SignedAssertion{
			Claims: AssertionClaims{
				Nonce:     "new-nonce",
				ExpiresAt: time.Now().Add(time.Minute),
			},
		},
	}

	_, err = processor.Process(context.Background(), ac2)
	if err != nil {
		t.Errorf("Should process valid nonce: %v", err)
	}

	// Check that expired nonces were cleaned up
	adminSvc.nonceMu.RLock()
	_, exists1 := adminSvc.nonceCache["expired1"]
	_, exists2 := adminSvc.nonceCache["expired2"]
	_, existsValid := adminSvc.nonceCache["valid"]
	adminSvc.nonceMu.RUnlock()

	if exists1 || exists2 {
		t.Error("Expired nonces should be cleaned up")
	}
	if !existsValid {
		t.Error("Valid nonce should still exist")
	}
}
