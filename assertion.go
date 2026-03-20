package sctx

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zoobz-io/capitan"
)

// SignedAssertion represents a signed claim proving private key possession.
type SignedAssertion struct {
	Claims    AssertionClaims
	Signature []byte
}

// AssertionClaims contains the claims within an assertion.
type AssertionClaims struct {
	IssuedAt    time.Time `json:"iat"`
	ExpiresAt   time.Time `json:"exp"`
	Nonce       string    `json:"nonce"`
	Purpose     string    `json:"purpose"`
	Fingerprint string    `json:"fingerprint"` // Must match certificate
}

// AssertionContext is used for validation processing.
type AssertionContext struct {
	Assertion   SignedAssertion
	Certificate *x509.Certificate
}

// CreateAssertion helps clients create properly signed assertions.
func CreateAssertion(privateKey crypto.PrivateKey, cert *x509.Certificate) (SignedAssertion, error) {
	if privateKey == nil || cert == nil {
		return SignedAssertion{}, errors.New("private key and certificate required")
	}

	// Verify key matches certificate
	if !certificateMatchesKey(cert, privateKey) {
		return SignedAssertion{}, errors.New("private key does not match certificate")
	}

	// Create claims
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return SignedAssertion{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	claims := AssertionClaims{
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(1 * time.Minute),
		Nonce:       base64.RawURLEncoding.EncodeToString(nonce),
		Purpose:     "token-generation",
		Fingerprint: getFingerprint(cert),
	}

	// Sign claims
	return signAssertion(claims, privateKey)
}

// signAssertion signs the claims with the private key.
func signAssertion(claims AssertionClaims, privateKey crypto.PrivateKey) (SignedAssertion, error) {
	// Serialize claims
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return SignedAssertion{}, fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Sign based on key type
	var signature []byte
	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		// Ed25519 signs the data directly (no hashing)
		signature = ed25519.Sign(key, claimsJSON)
	case crypto.Signer:
		// For other algorithms, hash first
		hash := crypto.SHA256
		hasher := hash.New()
		hasher.Write(claimsJSON)
		digest := hasher.Sum(nil)

		signature, err = key.Sign(rand.Reader, digest, hash)
		if err != nil {
			return SignedAssertion{}, fmt.Errorf("failed to sign assertion: %w", err)
		}
	default:
		return SignedAssertion{}, errors.New("private key must implement crypto.Signer")
	}

	return SignedAssertion{
		Claims:    claims,
		Signature: signature,
	}, nil
}

// verifyAssertion verifies the assertion signature using the certificate's public key.
func verifyAssertion(assertion SignedAssertion, cert *x509.Certificate) error {
	// Serialize claims
	claimsJSON, err := json.Marshal(assertion.Claims)
	if err != nil {
		return fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Detect algorithm from certificate's public key
	algorithm, err := DetectAlgorithmFromPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}

	// Create a temporary signer to use its Verify method
	var verified bool
	switch algorithm {
	case CryptoEd25519:
		signer := &ed25519Signer{}
		verified = signer.Verify(claimsJSON, assertion.Signature, cert.PublicKey)
	case CryptoECDSAP256:
		signer := &ecdsaP256Signer{}
		// Pass claimsJSON, not digest - the signer handles hashing internally
		verified = signer.Verify(claimsJSON, assertion.Signature, cert.PublicKey)
	default:
		return fmt.Errorf("unsupported algorithm: %v", algorithm)
	}

	if !verified {
		return errors.New("invalid signature")
	}
	return nil
}

// certificateMatchesKey verifies that a private key matches a certificate.
func certificateMatchesKey(cert *x509.Certificate, privateKey crypto.PrivateKey) bool {
	// Get public key from private key
	var pubKey crypto.PublicKey
	switch k := privateKey.(type) {
	case interface{ Public() crypto.PublicKey }:
		pubKey = k.Public()
	default:
		return false
	}

	// Compare with certificate's public key
	return publicKeysEqual(cert.PublicKey, pubKey)
}

// publicKeysEqual compares two public keys for equality.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	switch ka := a.(type) {
	case ed25519.PublicKey:
		kb, ok := b.(ed25519.PublicKey)
		return ok && string(ka) == string(kb)
	case *ecdsa.PublicKey:
		kb, ok := b.(*ecdsa.PublicKey)
		return ok && ka.Equal(kb)
	case *rsa.PublicKey:
		kb, ok := b.(*rsa.PublicKey)
		return ok && ka.Equal(kb)
	default:
		return false
	}
}

// ValidateAssertion performs complete assertion validation using direct function calls.
func ValidateAssertion[M any](ctx context.Context, assertion SignedAssertion, cert *x509.Certificate, admin *adminService[M]) error {
	ac := &AssertionContext{
		Assertion:   assertion,
		Certificate: cert,
	}

	// Step 1: Verify signature
	if err := verifySignatureStep(ctx, ac); err != nil {
		return err
	}

	// Step 2: Check expiration
	if err := checkExpirationStep(ctx, ac); err != nil {
		return err
	}

	// Step 3: Check nonce (requires admin service for nonce cache)
	if err := checkNonceStep(ctx, ac, admin); err != nil {
		return err
	}

	// Step 4: Match fingerprint
	if err := matchFingerprintStep(ctx, ac); err != nil {
		return err
	}

	// Step 5: Validate claims
	if err := validateClaimsStep(ctx, ac); err != nil {
		return err
	}

	capitan.Debug(ctx, AssertionValidated,
		FingerprintKey.Field(ac.Assertion.Claims.Fingerprint),
	)

	return nil
}

// verifySignatureStep verifies the assertion signature matches the certificate.
func verifySignatureStep(ctx context.Context, ac *AssertionContext) error {
	if err := verifyAssertion(ac.Assertion, ac.Certificate); err != nil {
		capitan.Warn(ctx, AssertionRejected,
			FingerprintKey.Field(ac.Assertion.Claims.Fingerprint),
			ErrorKey.Field("signature verification failed: "+err.Error()),
		)
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// checkExpirationStep ensures the assertion hasn't expired.
func checkExpirationStep(ctx context.Context, ac *AssertionContext) error {
	now := time.Now()
	fp := ac.Assertion.Claims.Fingerprint

	// Check not expired
	if now.After(ac.Assertion.Claims.ExpiresAt) {
		capitan.Warn(ctx, AssertionRejected,
			FingerprintKey.Field(fp),
			ErrorKey.Field("assertion expired"),
		)
		return errors.New("assertion expired")
	}

	// Check not issued in future (with 10s clock skew)
	if ac.Assertion.Claims.IssuedAt.After(now.Add(10 * time.Second)) {
		capitan.Warn(ctx, AssertionRejected,
			FingerprintKey.Field(fp),
			ErrorKey.Field("assertion issued in future"),
		)
		return errors.New("assertion issued in future")
	}

	// Check reasonable lifetime (max 5 minutes)
	lifetime := ac.Assertion.Claims.ExpiresAt.Sub(ac.Assertion.Claims.IssuedAt)
	if lifetime > 5*time.Minute {
		err := fmt.Errorf("assertion lifetime too long: %v", lifetime)
		capitan.Warn(ctx, AssertionRejected,
			FingerprintKey.Field(fp),
			ErrorKey.Field(err.Error()),
		)
		return err
	}

	return nil
}

// checkNonceStep prevents replay attacks.
func checkNonceStep[M any](ctx context.Context, ac *AssertionContext, admin *adminService[M]) error {
	nonce := ac.Assertion.Claims.Nonce
	fp := ac.Assertion.Claims.Fingerprint

	if nonce == "" {
		capitan.Warn(ctx, AssertionRejected,
			FingerprintKey.Field(fp),
			ErrorKey.Field("assertion missing nonce"),
		)
		return errors.New("assertion missing nonce")
	}

	admin.nonceMu.Lock()
	defer admin.nonceMu.Unlock()

	// Clean expired nonces
	admin.cleanExpiredNonces()

	// Check if nonce was already used
	if admin.nonceCache.Contains(nonce) {
		capitan.Warn(ctx, AssertionRejected,
			FingerprintKey.Field(fp),
			ErrorKey.Field("nonce already used"),
		)
		return errors.New("nonce already used")
	}

	// Store nonce with expiration
	admin.nonceCache.Add(nonce, ac.Assertion.Claims.ExpiresAt.Add(5*time.Minute))

	return nil
}

// matchFingerprintStep ensures assertion matches certificate.
func matchFingerprintStep(ctx context.Context, ac *AssertionContext) error {
	certFingerprint := getFingerprint(ac.Certificate)
	if ac.Assertion.Claims.Fingerprint != certFingerprint {
		err := fmt.Errorf("fingerprint mismatch: assertion has %s, certificate has %s",
			ac.Assertion.Claims.Fingerprint, certFingerprint)
		capitan.Warn(ctx, AssertionRejected,
			FingerprintKey.Field(ac.Assertion.Claims.Fingerprint),
			ErrorKey.Field(err.Error()),
		)
		return err
	}
	return nil
}

// validateClaimsStep ensures required claims are present.
func validateClaimsStep(ctx context.Context, ac *AssertionContext) error {
	claims := ac.Assertion.Claims

	// Validate purpose
	if claims.Purpose != "token-generation" {
		err := fmt.Errorf("invalid purpose: %s", claims.Purpose)
		capitan.Warn(ctx, AssertionRejected,
			FingerprintKey.Field(claims.Fingerprint),
			ErrorKey.Field(err.Error()),
		)
		return err
	}

	// All validations passed
	return nil
}
