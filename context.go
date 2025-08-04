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

	"github.com/zoobzio/zlog"
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

// CertificateInfo contains extracted certificate information
// This replaces storing the full x509.Certificate for better serialization
type CertificateInfo struct {
	CommonName   string    // Subject common name for audit logs
	SerialNumber string    // Certificate serial number for identification
	NotBefore    time.Time // Certificate validity start
	NotAfter     time.Time // Certificate validity end
	Issuer       string    // Certificate issuer for audit/compliance
	KeyUsage     []string  // Key usage extensions for validation
}

// Context contains the security context information
type Context[M any] struct {
	IssuedAt               time.Time
	ExpiresAt              time.Time
	Metadata               M
	CertificateInfo        CertificateInfo
	CertificateFingerprint string
	Permissions            []string
}

// HasPermission checks if the context data includes a specific permission scope
func (c *Context[M]) HasPermission(scope string) bool {
	return slices.Contains(c.Permissions, scope)
}

// IsExpired checks if the context data has expired
func (c *Context[M]) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// Clone creates a deep copy of the context for parallel processing
func (c *Context[M]) Clone() *Context[M] {
	if c == nil {
		return nil
	}

	clone := &Context[M]{
		IssuedAt:               c.IssuedAt,
		ExpiresAt:              c.ExpiresAt,
		Metadata:               c.Metadata, // M is any, shallow copy should be fine
		CertificateFingerprint: c.CertificateFingerprint,
	}

	// Deep copy CertificateInfo
	clone.CertificateInfo = CertificateInfo{
		CommonName:   c.CertificateInfo.CommonName,
		SerialNumber: c.CertificateInfo.SerialNumber,
		NotBefore:    c.CertificateInfo.NotBefore,
		NotAfter:     c.CertificateInfo.NotAfter,
		Issuer:       c.CertificateInfo.Issuer,
	}

	// Deep copy KeyUsage slice
	if c.CertificateInfo.KeyUsage != nil {
		clone.CertificateInfo.KeyUsage = make([]string, len(c.CertificateInfo.KeyUsage))
		copy(clone.CertificateInfo.KeyUsage, c.CertificateInfo.KeyUsage)
	}

	// Deep copy permissions slice
	if c.Permissions != nil {
		clone.Permissions = make([]string, len(c.Permissions))
		copy(clone.Permissions, c.Permissions)
	}

	return clone
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
		zlog.Emit(TOKEN_REJECTED, "Token verification failed - invalid format",
			zlog.String("reason", "malformed_token"),
		)
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
		zlog.Emit(TOKEN_REJECTED, "Token verification failed - invalid signature",
			zlog.String("reason", "signature_verification_failed"),
			zlog.String("algorithm", string(algorithm)),
		)
		return nil, ErrInvalidSignature
	}

	// Unmarshal payload
	var payload tokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, ErrInvalidContext
	}

	// Check expiration
	if time.Now().After(payload.Expiry) {
		zlog.Emit(TOKEN_REJECTED, "Token verification failed - expired",
			zlog.String("reason", "expired"),
			zlog.String("fingerprint", payload.Fingerprint),
			zlog.Time("expired_at", payload.Expiry),
		)
		return nil, ErrExpiredContext
	}

	// Successful verification
	zlog.Emit(TOKEN_VERIFIED, "Token successfully verified",
		zlog.String("fingerprint", payload.Fingerprint),
		zlog.String("algorithm", string(algorithm)),
	)

	return &payload, nil
}

// getFingerprint calculates the SHA256 fingerprint of a certificate
func getFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	hash := sha256.Sum256(cert.Raw)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// extractCertificateInfo extracts relevant information from an x509.Certificate
// This allows us to avoid storing the full certificate while retaining necessary data
func extractCertificateInfo(cert *x509.Certificate) CertificateInfo {
	if cert == nil {
		return CertificateInfo{}
	}

	// Extract key usage information
	var keyUsage []string
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsage = append(keyUsage, "digital_signature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsage = append(keyUsage, "key_encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		keyUsage = append(keyUsage, "data_encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		keyUsage = append(keyUsage, "cert_sign")
	}

	// Add extended key usage
	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageClientAuth:
			keyUsage = append(keyUsage, "client_auth")
		case x509.ExtKeyUsageServerAuth:
			keyUsage = append(keyUsage, "server_auth")
		case x509.ExtKeyUsageCodeSigning:
			keyUsage = append(keyUsage, "code_signing")
		case x509.ExtKeyUsageEmailProtection:
			keyUsage = append(keyUsage, "email_protection")
		}
	}

	return CertificateInfo{
		CommonName:   cert.Subject.CommonName,
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Issuer:       cert.Issuer.CommonName,
		KeyUsage:     keyUsage,
	}
}

// generateContextID creates a unique context identifier
func generateContextID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // This should never happen
	}
	return base64.URLEncoding.EncodeToString(b)
}
