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

// This replaces storing the full x509.Certificate for better serialization.
type CertificateInfo struct {
	// Subject fields
	CommonName         string   `json:"cn,omitempty"`
	Organization       []string `json:"o,omitempty"`
	OrganizationalUnit []string `json:"ou,omitempty"`
	Country            string   `json:"c,omitempty"`
	Province           string   `json:"st,omitempty"`
	Locality           string   `json:"l,omitempty"`
	StreetAddress      []string `json:"street,omitempty"`
	PostalCode         []string `json:"postal,omitempty"`

	// Certificate metadata
	SerialNumber string    `json:"serial"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`

	// Issuer fields
	Issuer             string   `json:"issuer,omitempty"`
	IssuerOrganization []string `json:"issuerOrg,omitempty"`

	// Extensions
	KeyUsage       []string `json:"keyUsage,omitempty"`
	DNSNames       []string `json:"dnsNames,omitempty"`
	EmailAddresses []string `json:"emails,omitempty"`
	URIs           []string `json:"uris,omitempty"`
	IPAddresses    []string `json:"ips,omitempty"`
}

// Context contains the security context information.
type Context[M any] struct {
	IssuedAt               time.Time
	ExpiresAt              time.Time
	Metadata               M
	CertificateInfo        CertificateInfo
	CertificateFingerprint string
	Permissions            []string
}

// HasPermission checks if the context data includes a specific permission scope.
func (c *Context[M]) HasPermission(scope string) bool {
	return slices.Contains(c.Permissions, scope)
}

// IsExpired checks if the context data has expired.
func (c *Context[M]) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// Clone creates a deep copy of the context for parallel processing.
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
		Country:      c.CertificateInfo.Country,
		Province:     c.CertificateInfo.Province,
		Locality:     c.CertificateInfo.Locality,
		SerialNumber: c.CertificateInfo.SerialNumber,
		NotBefore:    c.CertificateInfo.NotBefore,
		NotAfter:     c.CertificateInfo.NotAfter,
		Issuer:       c.CertificateInfo.Issuer,
	}

	// Deep copy slice fields
	if c.CertificateInfo.Organization != nil {
		clone.CertificateInfo.Organization = make([]string, len(c.CertificateInfo.Organization))
		copy(clone.CertificateInfo.Organization, c.CertificateInfo.Organization)
	}
	if c.CertificateInfo.OrganizationalUnit != nil {
		clone.CertificateInfo.OrganizationalUnit = make([]string, len(c.CertificateInfo.OrganizationalUnit))
		copy(clone.CertificateInfo.OrganizationalUnit, c.CertificateInfo.OrganizationalUnit)
	}
	if c.CertificateInfo.StreetAddress != nil {
		clone.CertificateInfo.StreetAddress = make([]string, len(c.CertificateInfo.StreetAddress))
		copy(clone.CertificateInfo.StreetAddress, c.CertificateInfo.StreetAddress)
	}
	if c.CertificateInfo.PostalCode != nil {
		clone.CertificateInfo.PostalCode = make([]string, len(c.CertificateInfo.PostalCode))
		copy(clone.CertificateInfo.PostalCode, c.CertificateInfo.PostalCode)
	}
	if c.CertificateInfo.IssuerOrganization != nil {
		clone.CertificateInfo.IssuerOrganization = make([]string, len(c.CertificateInfo.IssuerOrganization))
		copy(clone.CertificateInfo.IssuerOrganization, c.CertificateInfo.IssuerOrganization)
	}
	if c.CertificateInfo.KeyUsage != nil {
		clone.CertificateInfo.KeyUsage = make([]string, len(c.CertificateInfo.KeyUsage))
		copy(clone.CertificateInfo.KeyUsage, c.CertificateInfo.KeyUsage)
	}
	if c.CertificateInfo.DNSNames != nil {
		clone.CertificateInfo.DNSNames = make([]string, len(c.CertificateInfo.DNSNames))
		copy(clone.CertificateInfo.DNSNames, c.CertificateInfo.DNSNames)
	}
	if c.CertificateInfo.EmailAddresses != nil {
		clone.CertificateInfo.EmailAddresses = make([]string, len(c.CertificateInfo.EmailAddresses))
		copy(clone.CertificateInfo.EmailAddresses, c.CertificateInfo.EmailAddresses)
	}
	if c.CertificateInfo.URIs != nil {
		clone.CertificateInfo.URIs = make([]string, len(c.CertificateInfo.URIs))
		copy(clone.CertificateInfo.URIs, c.CertificateInfo.URIs)
	}
	if c.CertificateInfo.IPAddresses != nil {
		clone.CertificateInfo.IPAddresses = make([]string, len(c.CertificateInfo.IPAddresses))
		copy(clone.CertificateInfo.IPAddresses, c.CertificateInfo.IPAddresses)
	}

	// Deep copy permissions slice
	if c.Permissions != nil {
		clone.Permissions = make([]string, len(c.Permissions))
		copy(clone.Permissions, c.Permissions)
	}

	return clone
}

// tokenPayload represents the wire format of a session token.
type tokenPayload struct {
	Fingerprint string    `json:"f"`           // Certificate fingerprint
	IssuedAt    time.Time `json:"i,omitempty"` // When token was issued (omitempty for backward compat)
	Expiry      time.Time `json:"e"`           // Token expiry
	Nonce       string    `json:"n"`           // Random nonce for uniqueness
}

// encodeAndSign creates a signed session token from a payload.
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

// verifyTokenPayload verifies a token and returns the payload.
func verifyTokenPayload(token SignedToken, publicKey crypto.PublicKey) (*tokenPayload, error) {
	// Split token into payload and signature
	parts := strings.Split(string(token), ":")
	if len(parts) != 2 {
		// Token verification failed - invalid format
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
		// Token verification failed - invalid signature
		return nil, ErrInvalidSignature
	}

	// Unmarshal payload
	var payload tokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, ErrInvalidContext
	}

	// Check expiration
	if time.Now().After(payload.Expiry) {
		// Token verification failed - expired
		return nil, ErrExpiredContext
	}

	// Token successfully verified

	return &payload, nil
}

// GetFingerprint calculates the SHA256 fingerprint of a certificate.
func GetFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	hash := sha256.Sum256(cert.Raw)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// getFingerprint is an alias for internal usage.
func getFingerprint(cert *x509.Certificate) string {
	return GetFingerprint(cert)
}

// This allows us to avoid storing the full certificate while retaining necessary data.
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

	// Extract country (first value if multiple)
	country := ""
	if len(cert.Subject.Country) > 0 {
		country = cert.Subject.Country[0]
	}

	// Extract province/state (first value if multiple)
	province := ""
	if len(cert.Subject.Province) > 0 {
		province = cert.Subject.Province[0]
	}

	// Extract locality (first value if multiple)
	locality := ""
	if len(cert.Subject.Locality) > 0 {
		locality = cert.Subject.Locality[0]
	}

	// Convert IP addresses to strings
	ipAddresses := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	// Convert URIs to strings
	uris := make([]string, 0, len(cert.URIs))
	for _, uri := range cert.URIs {
		uris = append(uris, uri.String())
	}

	return CertificateInfo{
		// Subject fields
		CommonName:         cert.Subject.CommonName,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		Country:            country,
		Province:           province,
		Locality:           locality,
		StreetAddress:      cert.Subject.StreetAddress,
		PostalCode:         cert.Subject.PostalCode,

		// Certificate metadata
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,

		// Issuer fields
		Issuer:             cert.Issuer.CommonName,
		IssuerOrganization: cert.Issuer.Organization,

		// Extensions
		KeyUsage:       keyUsage,
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		URIs:           uris,
		IPAddresses:    ipAddresses,
	}
}

// generateContextID creates a unique context identifier.
func generateContextID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // This should never happen
	}
	return base64.URLEncoding.EncodeToString(b)
}

// DefaultContextPolicy provides a simple default policy that sets basic permissions and expiry.
func DefaultContextPolicy[M any]() ContextPolicy[M] {
	return func(cert *x509.Certificate) (*Context[M], error) {
		if cert == nil {
			return nil, errors.New("certificate is required")
		}

		// Create context with 1 hour expiry by default
		var metadata M // Zero value of M
		ctx := &Context[M]{
			CertificateInfo:        extractCertificateInfo(cert),
			CertificateFingerprint: getFingerprint(cert),
			IssuedAt:               time.Now(),
			ExpiresAt:              time.Now().Add(time.Hour),
			Metadata:               metadata,
			Permissions:            []string{}, // No permissions by default
		}

		return ctx, nil
	}
}
