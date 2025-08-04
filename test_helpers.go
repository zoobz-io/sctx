//go:build !prod
// +build !prod

package sctx

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

type TestCertificates struct {
	RootCA     *x509.Certificate
	RootCAKey  ed25519.PrivateKey
	ClientCert *x509.Certificate
	ClientKey  ed25519.PrivateKey
	CertPool   *x509.CertPool
}

func GenerateTestCertificates(t *testing.T) *TestCertificates {
	t.Helper()
	// Generate Root CA
	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPub, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		t.Fatalf("Failed to parse root certificate: %v", err)
	}

	// Generate Client Certificate
	clientPub, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:       []string{"Test Client"},
			OrganizationalUnit: []string{"Engineering", "Security"},
			CommonName:         "test-client",
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"San Francisco"},
			StreetAddress:      []string{"123 Test St"},
			PostalCode:         []string{"94102"},
		},
		NotBefore:      time.Now().Add(-24 * time.Hour),
		NotAfter:       time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
		DNSNames:       []string{"test.example.com", "*.test.example.com"},
		EmailAddresses: []string{"test@example.com", "admin@example.com"},
		IPAddresses:    []net.IP{net.IPv4(192, 168, 1, 1), net.IPv4(10, 0, 0, 1)},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, rootCert, clientPub, rootKey)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		t.Fatalf("Failed to parse client certificate: %v", err)
	}

	// Create certificate pool with root CA
	certPool := x509.NewCertPool()
	certPool.AddCert(rootCert)

	return &TestCertificates{
		RootCA:     rootCert,
		RootCAKey:  rootKey,
		ClientCert: clientCert,
		ClientKey:  clientKey,
		CertPool:   certPool,
	}
}

// GenerateAdditionalClientCert generates an additional client certificate signed by the provided CA
func GenerateAdditionalClientCert(t *testing.T, testCerts *TestCertificates, commonName string) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()

	// Generate Client Key
	clientPub, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	// Create unique serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Test Client"},
			OrganizationalUnit: []string{"Engineering"},
			CommonName:         commonName,
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, testCerts.RootCA, clientPub, testCerts.RootCAKey)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		t.Fatalf("Failed to parse client certificate: %v", err)
	}

	return clientCert, clientKey
}

// createTestAssertion is a test helper to create assertions
func createTestAssertion(t *testing.T, privateKey crypto.PrivateKey, cert *x509.Certificate) SignedAssertion {
	assertion, err := CreateAssertion(privateKey, cert)
	if err != nil {
		t.Fatalf("Failed to create assertion: %v", err)
	}
	return assertion
}
