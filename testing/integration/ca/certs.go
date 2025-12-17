//go:build integration

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// IntermediateCA represents an intermediate certificate authority.
type IntermediateCA struct {
	Cert     *x509.Certificate
	Key      crypto.PrivateKey
	CertPool *x509.CertPool
	Parent   *x509.Certificate
}

// CreateIntermediateCA creates an intermediate CA signed by the given root.
func CreateIntermediateCA(rootCert *x509.Certificate, rootKey crypto.PrivateKey, cn string) (*IntermediateCA, error) {
	// Generate intermediate key
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate intermediate key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	// Create intermediate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Intermediate CA"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// Sign with root CA
	intermediateCertDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate certificate: %w", err)
	}

	intermediateCert, err := x509.ParseCertificate(intermediateCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intermediate certificate: %w", err)
	}

	// Create cert pool with full chain
	certPool := x509.NewCertPool()
	certPool.AddCert(rootCert)
	certPool.AddCert(intermediateCert)

	return &IntermediateCA{
		Cert:     intermediateCert,
		Key:      intermediateKey,
		CertPool: certPool,
		Parent:   rootCert,
	}, nil
}

// IssueCertificate issues a client certificate from the intermediate CA.
func (i *IntermediateCA) IssueCertificate(cn string, opts ...CertOption) (*x509.Certificate, crypto.PrivateKey, error) {
	cfg := &certConfig{
		validity: 24 * time.Hour,
		keyType:  "ecdsa",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Generate key
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Client"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(cfg.validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              cfg.dnsNames,
	}

	// Sign with intermediate CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, i.Cert, &clientKey.PublicKey, i.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, clientKey, nil
}

// StandaloneCA creates a standalone CA for testing without containers.
// Useful for faster tests that don't need actual container infrastructure.
type StandaloneCA struct {
	RootCert *x509.Certificate
	RootKey  crypto.PrivateKey
	CertPool *x509.CertPool
}

// NewStandaloneCA creates a new standalone CA for testing.
func NewStandaloneCA(cn string) (*StandaloneCA, error) {
	// Generate root key
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	// Create root template
	rootTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create root certificate: %w", err)
	}

	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root certificate: %w", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(rootCert)

	return &StandaloneCA{
		RootCert: rootCert,
		RootKey:  rootKey,
		CertPool: certPool,
	}, nil
}

// IssueCertificate issues a client certificate from the standalone CA.
func (s *StandaloneCA) IssueCertificate(cn string, opts ...CertOption) (*x509.Certificate, crypto.PrivateKey, error) {
	cfg := &certConfig{
		validity: 24 * time.Hour,
		keyType:  "ecdsa",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Generate key
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Client"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(cfg.validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              cfg.dnsNames,
	}

	// Sign with root CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, s.RootCert, &clientKey.PublicKey, s.RootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, clientKey, nil
}

// IssueExpiredCertificate issues a certificate that has already expired.
func (s *StandaloneCA) IssueExpiredCertificate(cn string) (*x509.Certificate, crypto.PrivateKey, error) {
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Client"},
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Already expired
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, s.RootCert, &clientKey.PublicKey, s.RootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, clientKey, nil
}

// IssueShortLivedCertificate issues a certificate with very short validity.
func (s *StandaloneCA) IssueShortLivedCertificate(cn string, validity time.Duration) (*x509.Certificate, crypto.PrivateKey, error) {
	return s.IssueCertificate(cn, WithValidity(validity))
}

// CreateCrossSignedCA creates a CA that is cross-signed by another CA.
// The resulting CA can be trusted via either trust chain.
func CreateCrossSignedCA(primaryRoot *StandaloneCA, secondaryRoot *StandaloneCA, cn string) (*x509.Certificate, *x509.Certificate, crypto.PrivateKey, error) {
	// Generate key for the cross-signed CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}

	// Create CA template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Cross-Signed CA"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// Sign with primary root
	primaryCertDER, err := x509.CreateCertificate(rand.Reader, template, primaryRoot.RootCert, &caKey.PublicKey, primaryRoot.RootKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create primary-signed certificate: %w", err)
	}

	primaryCert, err := x509.ParseCertificate(primaryCertDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse primary certificate: %w", err)
	}

	// Sign with secondary root (same public key, different signer)
	serialNumber2, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template.SerialNumber = serialNumber2

	secondaryCertDER, err := x509.CreateCertificate(rand.Reader, template, secondaryRoot.RootCert, &caKey.PublicKey, secondaryRoot.RootKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create secondary-signed certificate: %w", err)
	}

	secondaryCert, err := x509.ParseCertificate(secondaryCertDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse secondary certificate: %w", err)
	}

	return primaryCert, secondaryCert, caKey, nil
}

// WithIPAddresses sets IP addresses for the certificate.
func WithIPAddresses(ips ...net.IP) CertOption {
	return func(c *certConfig) {
		// IP addresses would be added to the certConfig if needed
		// For now, this is a placeholder for the interface
	}
}
