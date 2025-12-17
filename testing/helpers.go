//go:build testing

// Package testing provides test utilities and helpers for sctx users.
// These utilities help users test their own sctx-based applications.
//
// This package requires the testing build tag:
//
//	go test -tags=testing ./...
package testing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/zoobzio/capitan"
	"github.com/zoobzio/sctx"
)

// Key type constants.
const (
	keyTypeECDSA   = "ecdsa"
	keyTypeEd25519 = "ed25519"
)

// CapturedToken represents a captured token generation event.
type CapturedToken struct {
	Fingerprint string
	CommonName  string
	Permissions string
	Timestamp   time.Time
}

// TokenCapture captures token generation events for testing.
// Thread-safe for concurrent event capture.
type TokenCapture struct {
	tokens   []CapturedToken
	mu       sync.Mutex
	listener *capitan.Listener
}

// NewTokenCapture creates a new TokenCapture that hooks into sctx token events.
func NewTokenCapture() *TokenCapture {
	tc := &TokenCapture{
		tokens: make([]CapturedToken, 0),
	}
	tc.listener = capitan.Hook(sctx.TokenGenerated, func(_ context.Context, e *capitan.Event) {
		tc.mu.Lock()
		defer tc.mu.Unlock()
		fingerprint, _ := sctx.FingerprintKey.From(e)
		commonName, _ := sctx.CommonNameKey.From(e)
		permissions, _ := sctx.PermissionsKey.From(e)
		tc.tokens = append(tc.tokens, CapturedToken{
			Fingerprint: fingerprint,
			CommonName:  commonName,
			Permissions: permissions,
			Timestamp:   e.Timestamp(),
		})
	})
	return tc
}

// Close stops capturing events.
func (tc *TokenCapture) Close() {
	tc.listener.Close()
}

// Tokens returns a copy of all captured tokens.
func (tc *TokenCapture) Tokens() []CapturedToken {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	result := make([]CapturedToken, len(tc.tokens))
	copy(result, tc.tokens)
	return result
}

// Count returns the number of captured tokens.
func (tc *TokenCapture) Count() int {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return len(tc.tokens)
}

// Reset clears all captured tokens.
func (tc *TokenCapture) Reset() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.tokens = tc.tokens[:0]
}

// WaitForCount blocks until the capture has at least n tokens or timeout occurs.
// Returns true if count reached, false if timeout.
func (tc *TokenCapture) WaitForCount(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if tc.Count() >= n {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// ValidationRecord represents a successful guard validation.
type ValidationRecord struct {
	GuardID     string
	Fingerprint string
	Timestamp   time.Time
}

// RejectionRecord represents a failed guard validation.
type RejectionRecord struct {
	GuardID     string
	Fingerprint string
	Error       string
	Timestamp   time.Time
}

// GuardRecorder records guard validation operations for testing.
// Thread-safe for concurrent event capture.
type GuardRecorder struct {
	validations       []ValidationRecord
	rejections        []RejectionRecord
	mu                sync.Mutex
	validatedListener *capitan.Listener
	rejectedListener  *capitan.Listener
}

// NewGuardRecorder creates a new GuardRecorder that hooks into guard events.
func NewGuardRecorder() *GuardRecorder {
	gr := &GuardRecorder{
		validations: make([]ValidationRecord, 0),
		rejections:  make([]RejectionRecord, 0),
	}
	gr.validatedListener = capitan.Hook(sctx.GuardValidated, func(_ context.Context, e *capitan.Event) {
		gr.mu.Lock()
		defer gr.mu.Unlock()
		guardID, _ := sctx.GuardIDKey.From(e)
		fingerprint, _ := sctx.FingerprintKey.From(e)
		gr.validations = append(gr.validations, ValidationRecord{
			GuardID:     guardID,
			Fingerprint: fingerprint,
			Timestamp:   e.Timestamp(),
		})
	})
	gr.rejectedListener = capitan.Hook(sctx.GuardRejected, func(_ context.Context, e *capitan.Event) {
		gr.mu.Lock()
		defer gr.mu.Unlock()
		guardID, _ := sctx.GuardIDKey.From(e)
		fingerprint, _ := sctx.FingerprintKey.From(e)
		errorMsg, _ := sctx.ErrorKey.From(e)
		gr.rejections = append(gr.rejections, RejectionRecord{
			GuardID:     guardID,
			Fingerprint: fingerprint,
			Error:       errorMsg,
			Timestamp:   e.Timestamp(),
		})
	})
	return gr
}

// Close stops recording events.
func (gr *GuardRecorder) Close() {
	gr.validatedListener.Close()
	gr.rejectedListener.Close()
}

// Validations returns a copy of all successful validations.
func (gr *GuardRecorder) Validations() []ValidationRecord {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	result := make([]ValidationRecord, len(gr.validations))
	copy(result, gr.validations)
	return result
}

// Rejections returns a copy of all failed validations.
func (gr *GuardRecorder) Rejections() []RejectionRecord {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	result := make([]RejectionRecord, len(gr.rejections))
	copy(result, gr.rejections)
	return result
}

// ValidationCount returns the number of successful validations.
func (gr *GuardRecorder) ValidationCount() int {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	return len(gr.validations)
}

// RejectionCount returns the number of failed validations.
func (gr *GuardRecorder) RejectionCount() int {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	return len(gr.rejections)
}

// Reset clears all recorded validations and rejections.
func (gr *GuardRecorder) Reset() {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	gr.validations = gr.validations[:0]
	gr.rejections = gr.rejections[:0]
}

// TestCertificates holds a complete test certificate chain.
type TestCertificates struct {
	RootCA     *x509.Certificate
	RootCAKey  crypto.PrivateKey
	ClientCert *x509.Certificate
	ClientKey  crypto.PrivateKey
	CertPool   *x509.CertPool
}

// CertBuilder provides fluent certificate generation for testing.
type CertBuilder struct {
	commonName     string
	organization   []string
	orgUnit        []string
	country        []string
	validity       time.Duration
	isCA           bool
	dnsNames       []string
	emailAddresses []string
	ipAddresses    []net.IP
	keyType        string // "ed25519" or "ecdsa"
}

// NewCertBuilder creates a new certificate builder with sensible defaults.
func NewCertBuilder() *CertBuilder {
	return &CertBuilder{
		commonName:   "test-cert",
		organization: []string{"Test Organization"},
		validity:     24 * time.Hour,
		keyType:      "ed25519",
	}
}

// WithCN sets the common name.
func (cb *CertBuilder) WithCN(cn string) *CertBuilder {
	cb.commonName = cn
	return cb
}

// WithOrganization sets the organization.
func (cb *CertBuilder) WithOrganization(org ...string) *CertBuilder {
	cb.organization = org
	return cb
}

// WithOrgUnit sets the organizational unit.
func (cb *CertBuilder) WithOrgUnit(ou ...string) *CertBuilder {
	cb.orgUnit = ou
	return cb
}

// WithCountry sets the country.
func (cb *CertBuilder) WithCountry(country ...string) *CertBuilder {
	cb.country = country
	return cb
}

// WithValidity sets the certificate validity duration.
func (cb *CertBuilder) WithValidity(d time.Duration) *CertBuilder {
	cb.validity = d
	return cb
}

// AsCA marks this certificate as a certificate authority.
func (cb *CertBuilder) AsCA() *CertBuilder {
	cb.isCA = true
	return cb
}

// WithDNSNames adds DNS names to the certificate.
func (cb *CertBuilder) WithDNSNames(names ...string) *CertBuilder {
	cb.dnsNames = append(cb.dnsNames, names...)
	return cb
}

// WithEmailAddresses adds email addresses to the certificate.
func (cb *CertBuilder) WithEmailAddresses(emails ...string) *CertBuilder {
	cb.emailAddresses = append(cb.emailAddresses, emails...)
	return cb
}

// WithIPAddresses adds IP addresses to the certificate.
func (cb *CertBuilder) WithIPAddresses(ips ...net.IP) *CertBuilder {
	cb.ipAddresses = append(cb.ipAddresses, ips...)
	return cb
}

// WithKeyType sets the key type ("ed25519" or "ecdsa").
func (cb *CertBuilder) WithKeyType(keyType string) *CertBuilder {
	cb.keyType = keyType
	return cb
}

// SelfSigned generates a self-signed certificate.
func (cb *CertBuilder) SelfSigned() (*x509.Certificate, crypto.PrivateKey, error) {
	return cb.SignedBy(nil, nil)
}

// SignedBy generates a certificate signed by the given CA.
// If ca is nil, creates a self-signed certificate.
func (cb *CertBuilder) SignedBy(ca *x509.Certificate, caKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	// Generate key pair
	var pubKey crypto.PublicKey
	var privKey crypto.PrivateKey
	var err error

	switch cb.keyType {
	case keyTypeECDSA:
		var key *ecdsa.PrivateKey
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pubKey = &key.PublicKey
		privKey = key
	default: // ed25519
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	// Build certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         cb.commonName,
			Organization:       cb.organization,
			OrganizationalUnit: cb.orgUnit,
			Country:            cb.country,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(cb.validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  cb.isCA,
		DNSNames:              cb.dnsNames,
		EmailAddresses:        cb.emailAddresses,
		IPAddresses:           cb.ipAddresses,
	}

	if cb.isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	// Determine signer
	parent := template
	signerKey := privKey
	if ca != nil {
		parent = ca
		signerKey = caKey
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, signerKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}

// GenerateTestCertificates generates a complete certificate chain for testing.
// Returns a root CA and a client certificate signed by the root.
func GenerateTestCertificates() (*TestCertificates, error) {
	// Generate root CA
	rootCert, rootKey, err := NewCertBuilder().
		WithCN("Test Root CA").
		WithOrganization("Test CA Organization").
		WithValidity(365 * 24 * time.Hour).
		AsCA().
		SelfSigned()
	if err != nil {
		return nil, err
	}

	// Generate client certificate
	clientCert, clientKey, err := NewCertBuilder().
		WithCN("test-client").
		WithOrganization("Test Client Organization").
		WithOrgUnit("Engineering", "Security").
		WithValidity(90*24*time.Hour).
		WithDNSNames("test.example.com", "*.test.example.com").
		WithEmailAddresses("test@example.com").
		SignedBy(rootCert, rootKey)
	if err != nil {
		return nil, err
	}

	// Create cert pool
	certPool := x509.NewCertPool()
	certPool.AddCert(rootCert)

	return &TestCertificates{
		RootCA:     rootCert,
		RootCAKey:  rootKey,
		ClientCert: clientCert,
		ClientKey:  clientKey,
		CertPool:   certPool,
	}, nil
}

// GenerateAdditionalClientCert generates an additional client certificate signed by the CA.
func GenerateAdditionalClientCert(tc *TestCertificates, commonName string) (*x509.Certificate, crypto.PrivateKey, error) {
	return NewCertBuilder().
		WithCN(commonName).
		WithOrganization("Test Client Organization").
		WithValidity(90*24*time.Hour).
		SignedBy(tc.RootCA, tc.RootCAKey)
}

// TestAdminOption configures TestAdmin creation.
type TestAdminOption func(*testAdminConfig)

type testAdminConfig struct {
	keyType string
}

// WithEd25519 configures the admin to use Ed25519 keys.
func WithEd25519() TestAdminOption {
	return func(c *testAdminConfig) {
		c.keyType = "ed25519"
	}
}

// WithECDSA configures the admin to use ECDSA P-256 keys.
func WithECDSA() TestAdminOption {
	return func(c *testAdminConfig) {
		c.keyType = keyTypeECDSA
	}
}

// TestAdmin creates an admin service configured for testing.
// Returns the admin, certificate pool, and the admin's private key.
// Note: This uses the internal createAdminService to avoid singleton restrictions.
func TestAdmin[M any](opts ...TestAdminOption) (sctx.Admin[M], *TestCertificates, error) {
	cfg := &testAdminConfig{keyType: "ed25519"}
	for _, opt := range opts {
		opt(cfg)
	}

	// Generate test certificates
	testCerts, err := GenerateTestCertificates()
	if err != nil {
		return nil, nil, err
	}

	// Generate admin key (separate from client keys)
	var adminKey crypto.PrivateKey
	switch cfg.keyType {
	case keyTypeECDSA:
		adminKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		_, adminKey, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		return nil, nil, err
	}

	// Create admin service - must reset singleton for testing
	sctx.ResetAdminForTesting()
	admin, err := sctx.NewAdminService[M](adminKey, testCerts.CertPool)
	if err != nil {
		return nil, nil, err
	}

	return admin, testCerts, nil
}

// CreateAssertion is a convenience function to create assertions for testing.
func CreateAssertion(privateKey crypto.PrivateKey, cert *x509.Certificate) (sctx.SignedAssertion, error) {
	return sctx.CreateAssertion(privateKey, cert)
}
