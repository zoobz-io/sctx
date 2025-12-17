//go:build integration

package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// StepCAContainer wraps a step-ca testcontainer for integration testing.
type StepCAContainer struct {
	container testcontainers.Container
	RootCert  *x509.Certificate
	RootKey   crypto.PrivateKey
	CertPool  *x509.CertPool
	host      string
	port      string
}

// stepCAConfig represents step-ca configuration
type stepCAConfig struct {
	Root             []string         `json:"root"`
	FederatedRoots   []string         `json:"federatedRoots"`
	Crt              string           `json:"crt"`
	Key              string           `json:"key"`
	Address          string           `json:"address"`
	DNSNames         []string         `json:"dnsNames"`
	Logger           map[string]any   `json:"logger"`
	DB               map[string]any   `json:"db"`
	Authority        authorityConfig  `json:"authority"`
	TLS              tlsConfig        `json:"tls"`
}

type authorityConfig struct {
	Provisioners []provisionerConfig `json:"provisioners"`
}

type provisionerConfig struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Key  any    `json:"key"`
}

type tlsConfig struct {
	CipherSuites  []string `json:"cipherSuites"`
	MinVersion    float64  `json:"minVersion"`
	MaxVersion    float64  `json:"maxVersion"`
	Renegotiation bool     `json:"renegotiation"`
}

// NewStepCA creates and starts a new step-ca container for testing.
// The container is configured with a self-signed root CA.
func NewStepCA(ctx context.Context) (*StepCAContainer, error) {
	// Generate root CA certificate and key
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root key: %w", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Step CA"},
			CommonName:   "Test Step CA Root",
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

	// Create certificate pool
	certPool := x509.NewCertPool()
	certPool.AddCert(rootCert)

	// Encode root cert and key as PEM
	rootCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCertDER,
	})

	rootKeyDER, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal root key: %w", err)
	}
	rootKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: rootKeyDER,
	})

	// Generate step-ca config
	config := stepCAConfig{
		Root:           []string{"/home/step/certs/root_ca.crt"},
		FederatedRoots: []string{},
		Crt:            "/home/step/certs/root_ca.crt",
		Key:            "/home/step/secrets/root_ca_key",
		Address:        ":9000",
		DNSNames:       []string{"localhost", "step-ca"},
		Logger:         map[string]any{"format": "text"},
		DB: map[string]any{
			"type":       "badgerv2",
			"dataSource": "/home/step/db",
		},
		Authority: authorityConfig{
			Provisioners: []provisionerConfig{
				{
					Type: "JWK",
					Name: "test-provisioner",
					Key: map[string]any{
						"use": "sig",
						"kty": "EC",
						"crv": "P-256",
						"alg": "ES256",
					},
				},
			},
		},
		TLS: tlsConfig{
			CipherSuites: []string{
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			},
			MinVersion:    1.2,
			MaxVersion:    1.3,
			Renegotiation: false,
		},
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	// Create container request
	req := testcontainers.ContainerRequest{
		Image:        "smallstep/step-ca:latest",
		ExposedPorts: []string{"9000/tcp"},
		WaitingFor:   wait.ForLog("Serving HTTPS on").WithStartupTimeout(60 * time.Second),
		Files: []testcontainers.ContainerFile{
			{
				Reader:            stringReader(string(rootCertPEM)),
				ContainerFilePath: "/home/step/certs/root_ca.crt",
				FileMode:          0644,
			},
			{
				Reader:            stringReader(string(rootKeyPEM)),
				ContainerFilePath: "/home/step/secrets/root_ca_key",
				FileMode:          0600,
			},
			{
				Reader:            stringReader(string(configJSON)),
				ContainerFilePath: "/home/step/config/ca.json",
				FileMode:          0644,
			},
		},
		Cmd: []string{
			"/home/step/config/ca.json",
		},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}

	mappedPort, err := container.MappedPort(ctx, "9000/tcp")
	if err != nil {
		container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get mapped port: %w", err)
	}

	return &StepCAContainer{
		container: container,
		RootCert:  rootCert,
		RootKey:   rootKey,
		CertPool:  certPool,
		host:      host,
		port:      mappedPort.Port(),
	}, nil
}

// APIURL returns the URL to the step-ca API.
func (s *StepCAContainer) APIURL() string {
	return fmt.Sprintf("https://%s:%s", s.host, s.port)
}

// Terminate stops and removes the container.
func (s *StepCAContainer) Terminate(ctx context.Context) error {
	if s.container != nil {
		return s.container.Terminate(ctx)
	}
	return nil
}

// IssueCertificate issues a new client certificate signed by the root CA.
// This bypasses the step-ca API and signs directly with the root key.
func (s *StepCAContainer) IssueCertificate(cn string, opts ...CertOption) (*x509.Certificate, crypto.PrivateKey, error) {
	cfg := &certConfig{
		validity: 24 * time.Hour,
		keyType:  "ecdsa",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Generate key
	var pubKey crypto.PublicKey
	var privKey crypto.PrivateKey
	var err error

	switch cfg.keyType {
	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pubKey = &key.PublicKey
		privKey = key
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", cfg.keyType)
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
	certDER, err := x509.CreateCertificate(rand.Reader, template, s.RootCert, pubKey, s.RootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, privKey, nil
}

// RevokeCertificate marks a certificate as revoked.
// Note: This is a simplified implementation that doesn't use actual CRL/OCSP.
// In real step-ca, you would call the revocation API.
func (s *StepCAContainer) RevokeCertificate(serial string) error {
	// For integration tests, revocation is handled at the sctx level
	// by calling admin.RevokeByFingerprint()
	return nil
}

// certConfig holds certificate options.
type certConfig struct {
	validity time.Duration
	keyType  string
	dnsNames []string
}

// CertOption configures certificate generation.
type CertOption func(*certConfig)

// WithValidity sets the certificate validity duration.
func WithValidity(d time.Duration) CertOption {
	return func(c *certConfig) {
		c.validity = d
	}
}

// WithDNSNames sets DNS names for the certificate.
func WithDNSNames(names ...string) CertOption {
	return func(c *certConfig) {
		c.dnsNames = names
	}
}

// stringReader wraps a string as an io.Reader.
type stringReaderImpl struct {
	s string
	i int64
}

func stringReader(s string) *stringReaderImpl {
	return &stringReaderImpl{s: s}
}

func (r *stringReaderImpl) Read(b []byte) (n int, err error) {
	if r.i >= int64(len(r.s)) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(b, r.s[r.i:])
	r.i += int64(n)
	return
}
