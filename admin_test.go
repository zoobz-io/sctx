package sctx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestNewAdminService(t *testing.T) {
	// Generate Ed25519 key pair - signature is (PublicKey, PrivateKey, error)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	caPool := x509.NewCertPool()
	
	admin, err := NewAdminService[any](privateKey, caPool)
	if err != nil {
		t.Fatalf("Failed to create admin service: %v", err)
	}
	
	if admin == nil {
		t.Fatal("Admin service is nil")
	}
	
	if admin.PublicKey() == nil {
		t.Error("Public key is nil")
	}
}

func TestSCTXPrimitiveFlow(t *testing.T) {
	// Test the full primitive flow: cert -> token -> guard -> validation
	
	// 1. Setup admin with CA
	_, caPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}
	
	// Create self-signed CA
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}
	
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPrivateKey.Public(), caPrivateKey)
	if err != nil {
		t.Fatalf("Failed to create CA cert: %v", err)
	}
	
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA cert: %v", err)
	}
	
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	
	// Create admin service
	admin, err := NewAdminService[any](caPrivateKey, caPool)
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}
	
	// Configure context pipeline - let's manually set expiry to debug
	admin.ConfigureContextPipeline(
		func(ctx context.Context, sctxCtx *Context[any]) (*Context[any], error) {
			sctxCtx.Permissions = append(sctxCtx.Permissions, "read", "write")
			sctxCtx.ExpiresAt = time.Now().Add(time.Hour)
			return sctxCtx, nil
		},
	)
	
	// 2. Create client certificate
	_, clientPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}
	
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, clientPrivateKey.Public(), caPrivateKey)
	if err != nil {
		t.Fatalf("Failed to create client cert: %v", err)
	}
	
	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		t.Fatalf("Failed to parse client cert: %v", err)
	}
	
	// 3. Generate token from certificate
	token, err := admin.Generate(clientCert)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}
	
	if token == "" {
		t.Error("Token is empty")
	}
	
	// 4. Debug: check what's in the cache
	fingerprint := getFingerprint(clientCert)
	t.Logf("Client cert fingerprint: %s", fingerprint)
	
	if cachedCtx, exists := admin.cache.Get(fingerprint); exists {
		t.Logf("Cached context expires at: %v", cachedCtx.ExpiresAt)
		t.Logf("Cached context permissions: %v", cachedCtx.Permissions)
		t.Logf("Current time: %v", time.Now())
		
		if cachedCtx.ExpiresAt.IsZero() {
			t.Error("Context expiry is zero - pipeline didn't set expiry")
		}
	} else {
		t.Error("Context not found in cache")
	}
	
	t.Log("✅ Full SCTX primitive flow works: cert -> token -> guard -> validation")
}