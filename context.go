package sctx

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrExpiredContext   = errors.New("context has expired")
	ErrInvalidContext   = errors.New("invalid context format")
)

// SignedToken is an opaque, tamper-proof security token.
// It contains a signed reference to a cached context.
// Tokens can only be created by the ContextService and must be verified before use.
type SignedToken string

// Context contains the security context information
type Context[M any] struct {
	Certificate            *x509.Certificate
	Permissions            []string
	IssuedAt               time.Time
	ExpiresAt              time.Time
	Issuer                 string // Which generator created this
	CertificateFingerprint string // Cache key
	Metadata               M      // User-defined data
}

// HasPermission checks if the context data includes a specific permission scope
func (c *Context[M]) HasPermission(scope string) bool {
	return slices.Contains(c.Permissions, scope)
}

// IsExpired checks if the context data has expired
func (c *Context[M]) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// tokenPayload represents the wire format of a session token
type tokenPayload struct {
	Fingerprint string    `json:"f"` // Certificate fingerprint
	Expiry      time.Time `json:"e"` // Token expiry
	Nonce       string    `json:"n"` // Random nonce for uniqueness
}

// encodeAndSign creates a signed session token from a payload
func encodeAndSign(payload *tokenPayload, signer CryptoSigner) (SignedToken, error) {
	// Serialize the payload
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token payload: %w", err)
	}

	// Sign the payload
	signatureBytes, err := signer.Sign(payloadBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Combine payload and signature
	// Format: base64(payload):base64(signature)
	token := fmt.Sprintf("%s:%s",
		base64.URLEncoding.EncodeToString(payloadBytes),
		base64.URLEncoding.EncodeToString(signatureBytes),
	)

	return SignedToken(token), nil
}

// verifyTokenPayload verifies a token and returns the payload
func verifyTokenPayload(token SignedToken, publicKey crypto.PublicKey) (*tokenPayload, error) {
	// Split token into payload and signature
	parts := strings.Split(string(token), ":")
	if len(parts) != 2 {
		return nil, ErrInvalidContext
	}

	// Decode payload and signature
	payloadBytes, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidContext
	}

	signatureBytes, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidContext
	}

	// Detect algorithm from public key
	algorithm, err := DetectAlgorithmFromPublicKey(publicKey)
	if err != nil {
		return nil, ErrInvalidSignature
	}

	// Create verifier
	var signer CryptoSigner
	switch algorithm {
	case CryptoEd25519:
		signer = &ed25519Signer{}
	case CryptoECDSAP256:
		signer = &ecdsaP256Signer{}
	default:
		return nil, ErrInvalidSignature
	}

	// Verify signature
	if !signer.Verify(payloadBytes, signatureBytes, publicKey) {
		return nil, ErrInvalidSignature
	}

	// Unmarshal payload
	var payload tokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, ErrInvalidContext
	}

	// Check expiration
	if time.Now().After(payload.Expiry) {
		return nil, ErrExpiredContext
	}

	return &payload, nil
}

// decodeAndVerify is deprecated - tokens no longer contain context data
// This is kept for backward compatibility but will panic
func decodeAndVerify[M any](token SignedToken, publicKey crypto.PublicKey) (*Context[M], error) {
	panic("decodeAndVerify is deprecated - use verifyTokenPayload and lookup context in cache")
}

// CheckCompatibility is deprecated - tokens no longer contain permission data
// Use the cache to lookup and compare contexts instead

// getFingerprint calculates the SHA256 fingerprint of a certificate
func getFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	hash := sha256.Sum256(cert.Raw)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// generateContextID creates a unique context identifier
func generateContextID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // This should never happen
	}
	return base64.URLEncoding.EncodeToString(b)
}
