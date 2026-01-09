//go:build testing

package testing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

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
		keyType:      keyTypeEd25519,
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
