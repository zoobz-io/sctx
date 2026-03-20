//go:build integration && testing

package integration

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zoobz-io/sctx"
	"github.com/zoobz-io/sctx/testing/integration/ca"
)

// TestIntegration_MultiCA_IntermediateCA tests certificates issued by intermediate CA.
func TestIntegration_MultiCA_IntermediateCA(t *testing.T) {
	ctx := context.Background()

	// Create root CA
	rootCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}

	// Create intermediate CA signed by root
	intermediateCA, err := ca.CreateIntermediateCA(rootCA.RootCert, rootCA.RootKey, "Test Intermediate CA")
	if err != nil {
		t.Fatalf("Failed to create intermediate CA: %v", err)
	}

	// Issue client certificate from intermediate CA
	clientCert, clientKey, err := intermediateCA.IssueCertificate("intermediate-client")
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create admin that trusts the root CA
	sctx.ResetAdminForTesting()

	// Build cert pool with root and intermediate
	certPool := x509.NewCertPool()
	certPool.AddCert(rootCA.RootCert)
	certPool.AddCert(intermediateCA.Cert)

	admin, err := sctx.NewAdminService[any](clientKey, certPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	// Set policy
	_ = admin.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	// Generate token
	assertion, _ := sctx.CreateAssertion(clientKey, clientCert)
	token, err := admin.Generate(ctx, clientCert, assertion)
	if err != nil {
		t.Fatalf("Failed to generate token via intermediate CA: %v", err)
	}

	// Create and validate guard
	guard, err := admin.CreateGuard(ctx, token, "read")
	if err != nil {
		t.Fatalf("Failed to create guard: %v", err)
	}

	if err := guard.Validate(ctx, token); err != nil {
		t.Errorf("Guard validation failed: %v", err)
	}
}

// TestIntegration_MultiCA_CrossSigning tests cross-signed certificate chains.
func TestIntegration_MultiCA_CrossSigning(t *testing.T) {
	ctx := context.Background()

	// Create two independent root CAs
	primaryCA, err := ca.NewStandaloneCA("Primary Root CA")
	if err != nil {
		t.Fatalf("Failed to create primary CA: %v", err)
	}

	secondaryCA, err := ca.NewStandaloneCA("Secondary Root CA")
	if err != nil {
		t.Fatalf("Failed to create secondary CA: %v", err)
	}

	// Create a cross-signed intermediate CA
	primarySigned, secondarySigned, crossKey, err := ca.CreateCrossSignedCA(primaryCA, secondaryCA, "Cross-Signed CA")
	if err != nil {
		t.Fatalf("Failed to create cross-signed CA: %v", err)
	}

	// Issue client cert from cross-signed CA (using primary-signed version)
	clientKey, err := generateECDSAKey()
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	clientCert, err := issueCertFromCA(primarySigned, crossKey, "cross-signed-client", clientKey)
	if err != nil {
		t.Fatalf("Failed to issue client cert: %v", err)
	}

	// Test 1: Verify via primary CA trust
	sctx.ResetAdminForTesting()

	primaryPool := x509.NewCertPool()
	primaryPool.AddCert(primaryCA.RootCert)
	primaryPool.AddCert(primarySigned)

	admin1, err := sctx.NewAdminService[any](clientKey, primaryPool)
	if err != nil {
		t.Fatalf("Failed to create admin with primary trust: %v", err)
	}

	_ = admin1.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	assertion1, _ := sctx.CreateAssertion(clientKey, clientCert)
	token1, err := admin1.Generate(ctx, clientCert, assertion1)
	if err != nil {
		t.Fatalf("Token generation via primary trust failed: %v", err)
	}

	guard1, _ := admin1.CreateGuard(ctx, token1, "read")
	if err := guard1.Validate(ctx, token1); err != nil {
		t.Errorf("Validation via primary trust failed: %v", err)
	}

	// Test 2: Verify via secondary CA trust (using secondary-signed version of cross CA)
	// Issue a new client cert using the secondary-signed version
	sctx.ResetAdminForTesting()

	clientCert2, err := issueCertFromCA(secondarySigned, crossKey, "cross-signed-client-2", clientKey)
	if err != nil {
		t.Fatalf("Failed to issue client cert via secondary: %v", err)
	}

	secondaryPool := x509.NewCertPool()
	secondaryPool.AddCert(secondaryCA.RootCert)
	secondaryPool.AddCert(secondarySigned)

	admin2, err := sctx.NewAdminService[any](clientKey, secondaryPool)
	if err != nil {
		t.Fatalf("Failed to create admin with secondary trust: %v", err)
	}

	_ = admin2.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	assertion2, _ := sctx.CreateAssertion(clientKey, clientCert2)
	token2, err := admin2.Generate(ctx, clientCert2, assertion2)
	if err != nil {
		t.Fatalf("Token generation via secondary trust failed: %v", err)
	}

	guard2, _ := admin2.CreateGuard(ctx, token2, "read")
	if err := guard2.Validate(ctx, token2); err != nil {
		t.Errorf("Validation via secondary trust failed: %v", err)
	}
}

// TestIntegration_MultiCA_PartialChain tests trust with only intermediate in pool.
func TestIntegration_MultiCA_PartialChain(t *testing.T) {
	ctx := context.Background()

	// Create root CA
	rootCA, err := ca.NewStandaloneCA("Test Root CA")
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}

	// Create intermediate CA
	intermediateCA, err := ca.CreateIntermediateCA(rootCA.RootCert, rootCA.RootKey, "Test Intermediate CA")
	if err != nil {
		t.Fatalf("Failed to create intermediate CA: %v", err)
	}

	// Issue client certificate from intermediate
	clientCert, clientKey, err := intermediateCA.IssueCertificate("partial-chain-client")
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create admin that only trusts the intermediate (not root)
	sctx.ResetAdminForTesting()

	partialPool := x509.NewCertPool()
	partialPool.AddCert(intermediateCA.Cert)

	admin, err := sctx.NewAdminService[any](clientKey, partialPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	_ = admin.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	// Generate token - should work because client cert is directly signed by trusted intermediate
	assertion, _ := sctx.CreateAssertion(clientKey, clientCert)
	token, err := admin.Generate(ctx, clientCert, assertion)
	if err != nil {
		t.Fatalf("Token generation with partial chain failed: %v", err)
	}

	guard, _ := admin.CreateGuard(ctx, token, "read")
	if err := guard.Validate(ctx, token); err != nil {
		t.Errorf("Validation with partial chain failed: %v", err)
	}
}

// TestIntegration_MultiCA_MultipleRoots tests trust with multiple root CAs.
func TestIntegration_MultiCA_MultipleRoots(t *testing.T) {
	ctx := context.Background()

	// Create multiple root CAs
	rootCA1, _ := ca.NewStandaloneCA("Root CA 1")
	rootCA2, _ := ca.NewStandaloneCA("Root CA 2")
	rootCA3, _ := ca.NewStandaloneCA("Root CA 3")

	// Issue client certs from each
	client1Cert, client1Key, _ := rootCA1.IssueCertificate("client-from-ca1")
	client2Cert, client2Key, _ := rootCA2.IssueCertificate("client-from-ca2")
	client3Cert, client3Key, _ := rootCA3.IssueCertificate("client-from-ca3")

	// Create admin that trusts all three roots
	sctx.ResetAdminForTesting()

	multiRootPool := x509.NewCertPool()
	multiRootPool.AddCert(rootCA1.RootCert)
	multiRootPool.AddCert(rootCA2.RootCert)
	multiRootPool.AddCert(rootCA3.RootCert)

	admin, err := sctx.NewAdminService[any](client1Key, multiRootPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

	_ = admin.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	// All clients should be able to authenticate
	assertion1, _ := sctx.CreateAssertion(client1Key, client1Cert)
	token1, err := admin.Generate(ctx, client1Cert, assertion1)
	if err != nil {
		t.Fatalf("Client from CA1 failed: %v", err)
	}

	assertion2, _ := sctx.CreateAssertion(client2Key, client2Cert)
	token2, err := admin.Generate(ctx, client2Cert, assertion2)
	if err != nil {
		t.Fatalf("Client from CA2 failed: %v", err)
	}

	assertion3, _ := sctx.CreateAssertion(client3Key, client3Cert)
	token3, err := admin.Generate(ctx, client3Cert, assertion3)
	if err != nil {
		t.Fatalf("Client from CA3 failed: %v", err)
	}

	// All should work
	guard, _ := admin.CreateGuard(ctx, token1, "read")
	if guard.Validate(ctx, token1) != nil {
		t.Error("Token1 validation failed")
	}

	// Create guards for other tokens too
	guard2, _ := admin.CreateGuard(ctx, token2, "read")
	guard3, _ := admin.CreateGuard(ctx, token3, "read")

	if guard2.Validate(ctx, token2) != nil {
		t.Error("Token2 validation failed")
	}
	if guard3.Validate(ctx, token3) != nil {
		t.Error("Token3 validation failed")
	}

	// Should have 3 active contexts
	if admin.ActiveCount() != 3 {
		t.Errorf("Expected 3 active contexts, got %d", admin.ActiveCount())
	}
}

// TestIntegration_MultiCA_MixedChainDepths tests certificates at different chain depths.
func TestIntegration_MultiCA_MixedChainDepths(t *testing.T) {
	ctx := context.Background()

	// Create root CA
	rootCA, _ := ca.NewStandaloneCA("Test Root CA")

	// Create intermediate CA
	intermediateCA, _ := ca.CreateIntermediateCA(rootCA.RootCert, rootCA.RootKey, "Test Intermediate CA")

	// Issue cert directly from root
	directCert, directKey, _ := rootCA.IssueCertificate("direct-client")

	// Issue cert from intermediate
	intermediateCert, intermediateKey, _ := intermediateCA.IssueCertificate("intermediate-client")

	// Create admin trusting root and intermediate
	sctx.ResetAdminForTesting()

	fullPool := x509.NewCertPool()
	fullPool.AddCert(rootCA.RootCert)
	fullPool.AddCert(intermediateCA.Cert)

	admin, _ := sctx.NewAdminService[any](directKey, fullPool)
	_ = admin.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	// Both should work
	directAssertion, _ := sctx.CreateAssertion(directKey, directCert)
	directToken, err := admin.Generate(ctx, directCert, directAssertion)
	if err != nil {
		t.Fatalf("Direct cert auth failed: %v", err)
	}

	intermediateAssertion, _ := sctx.CreateAssertion(intermediateKey, intermediateCert)
	intermediateToken, err := admin.Generate(ctx, intermediateCert, intermediateAssertion)
	if err != nil {
		t.Fatalf("Intermediate cert auth failed: %v", err)
	}

	// Verify both tokens work
	directGuard, _ := admin.CreateGuard(ctx, directToken, "read")
	intermediateGuard, _ := admin.CreateGuard(ctx, intermediateToken, "read")

	if directGuard.Validate(ctx, directToken) != nil {
		t.Error("Direct token validation failed")
	}
	if intermediateGuard.Validate(ctx, intermediateToken) != nil {
		t.Error("Intermediate token validation failed")
	}
}

// Helper functions for the tests

func generateECDSAKey() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func issueCertFromCA(caCert *x509.Certificate, caKey crypto.PrivateKey, cn string, clientKey crypto.PrivateKey) (*x509.Certificate, error) {
	clientPubKey := clientKey.(*ecdsa.PrivateKey).Public()

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Client"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, clientPubKey, caKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}
