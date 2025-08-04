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

	"github.com/zoobzio/pipz"
)

// SignedAssertion represents a signed claim proving private key possession
type SignedAssertion struct {
	Claims    AssertionClaims
	Signature []byte
}

// AssertionClaims contains the claims within an assertion
type AssertionClaims struct {
	IssuedAt    time.Time `json:"iat"`
	ExpiresAt   time.Time `json:"exp"`
	Nonce       string    `json:"nonce"`
	Purpose     string    `json:"purpose"`
	Fingerprint string    `json:"fingerprint"` // Must match certificate
}

// AssertionContext is used for pipeline processing
type AssertionContext struct {
	Assertion   SignedAssertion
	Certificate *x509.Certificate
}

// Clone implements pipz.Cloner interface
func (ac *AssertionContext) Clone() *AssertionContext {
	return &AssertionContext{
		Assertion: SignedAssertion{
			Claims:    ac.Assertion.Claims,
			Signature: append([]byte(nil), ac.Assertion.Signature...),
		},
		Certificate: ac.Certificate,
	}
}

// CreateAssertion helps clients create properly signed assertions
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

// signAssertion signs the claims with the private key
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

// verifyAssertion verifies the assertion signature using the certificate's public key
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

// certificateMatchesKey verifies that a private key matches a certificate
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

// publicKeysEqual compares two public keys for equality
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

// Processor names for assertion validation
const (
	ProcessorVerifySignature  = "verify-signature"
	ProcessorCheckExpiration  = "check-expiration"
	ProcessorCheckNonce       = "check-nonce"
	ProcessorValidateClaims   = "validate-claims"
	ProcessorMatchFingerprint = "match-fingerprint"
)

// CreateAssertionProcessors creates processors for assertion validation
func CreateAssertionProcessors[M any]() map[string]pipz.Chainable[*AssertionContext] {
	processors := map[string]pipz.Chainable[*AssertionContext]{
		ProcessorVerifySignature:  verifySignatureProcessor(),
		ProcessorCheckExpiration:  checkExpirationProcessor(),
		ProcessorMatchFingerprint: matchFingerprintProcessor(),
	}

	// Add claim validators
	processors[ProcessorValidateClaims] = validateClaimsProcessor()

	return processors
}

// verifySignatureProcessor verifies the assertion signature matches the certificate
var verifySignatureProcessor = func() pipz.Chainable[*AssertionContext] {
	return pipz.Apply[*AssertionContext](ProcessorVerifySignature,
		func(ctx context.Context, ac *AssertionContext) (*AssertionContext, error) {
			if err := verifyAssertion(ac.Assertion, ac.Certificate); err != nil {
				return nil, fmt.Errorf("signature verification failed: %w", err)
			}
			return ac, nil
		})
}

// checkExpirationProcessor ensures the assertion hasn't expired
var checkExpirationProcessor = func() pipz.Chainable[*AssertionContext] {
	return pipz.Apply[*AssertionContext](ProcessorCheckExpiration,
		func(ctx context.Context, ac *AssertionContext) (*AssertionContext, error) {
			now := time.Now()

			// Check not expired
			if now.After(ac.Assertion.Claims.ExpiresAt) {
				return nil, errors.New("assertion expired")
			}

			// Check not issued in future (with 10s clock skew)
			if ac.Assertion.Claims.IssuedAt.After(now.Add(10 * time.Second)) {
				return nil, errors.New("assertion issued in future")
			}

			// Check reasonable lifetime (max 5 minutes)
			lifetime := ac.Assertion.Claims.ExpiresAt.Sub(ac.Assertion.Claims.IssuedAt)
			if lifetime > 5*time.Minute {
				return nil, fmt.Errorf("assertion lifetime too long: %v", lifetime)
			}

			return ac, nil
		})
}

// checkNonceProcessor prevents replay attacks
func checkNonceProcessor[M any](admin *adminService[M]) pipz.Chainable[*AssertionContext] {
	return pipz.Apply[*AssertionContext](ProcessorCheckNonce,
		func(ctx context.Context, ac *AssertionContext) (*AssertionContext, error) {
			nonce := ac.Assertion.Claims.Nonce
			if nonce == "" {
				return nil, errors.New("assertion missing nonce")
			}

			admin.nonceMu.Lock()
			defer admin.nonceMu.Unlock()

			// Clean expired nonces
			now := time.Now()
			for n, expiry := range admin.nonceCache {
				if now.After(expiry) {
					delete(admin.nonceCache, n)
				}
			}

			// Check if nonce was already used
			if _, exists := admin.nonceCache[nonce]; exists {
				return nil, errors.New("nonce already used")
			}

			// Store nonce with expiration
			admin.nonceCache[nonce] = ac.Assertion.Claims.ExpiresAt.Add(5 * time.Minute)

			return ac, nil
		})
}

// matchFingerprintProcessor ensures assertion matches certificate
var matchFingerprintProcessor = func() pipz.Chainable[*AssertionContext] {
	return pipz.Apply[*AssertionContext](ProcessorMatchFingerprint,
		func(ctx context.Context, ac *AssertionContext) (*AssertionContext, error) {
			certFingerprint := getFingerprint(ac.Certificate)
			if ac.Assertion.Claims.Fingerprint != certFingerprint {
				return nil, fmt.Errorf("fingerprint mismatch: assertion has %s, certificate has %s",
					ac.Assertion.Claims.Fingerprint, certFingerprint)
			}
			return ac, nil
		})
}

// validateClaimsProcessor ensures required claims are present
var validateClaimsProcessor = func() pipz.Chainable[*AssertionContext] {
	return pipz.Apply[*AssertionContext](ProcessorValidateClaims,
		func(ctx context.Context, ac *AssertionContext) (*AssertionContext, error) {
			claims := ac.Assertion.Claims

			// Validate purpose
			if claims.Purpose != "token-generation" {
				return nil, fmt.Errorf("invalid purpose: %s", claims.Purpose)
			}

			// All validations passed
			return ac, nil
		})
}
