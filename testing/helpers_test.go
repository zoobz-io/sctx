//go:build testing

package testing

import (
	"context"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/zoobzio/capitan"
	"github.com/zoobzio/sctx"
)

func TestMain(m *testing.M) {
	capitan.Configure(capitan.WithSyncMode())
	os.Exit(m.Run())
}

func TestTokenCapture(t *testing.T) {
	admin, testCerts, err := TestAdmin[any]()
	if err != nil {
		t.Fatalf("TestAdmin failed: %v", err)
	}

	capture := NewTokenCapture()
	defer capture.Close()

	// Generate a token
	assertion, err := CreateAssertion(testCerts.ClientKey, testCerts.ClientCert)
	if err != nil {
		t.Fatalf("CreateAssertion failed: %v", err)
	}

	_, err = admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Check capture
	if capture.Count() != 1 {
		t.Errorf("expected 1 captured token, got %d", capture.Count())
	}

	tokens := capture.Tokens()
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0].CommonName != testCerts.ClientCert.Subject.CommonName {
		t.Errorf("expected CN %q, got %q", testCerts.ClientCert.Subject.CommonName, tokens[0].CommonName)
	}
	if tokens[0].Fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}
}

func TestTokenCapture_WaitForCount(t *testing.T) {
	capture := NewTokenCapture()
	defer capture.Close()

	// Should timeout when no tokens
	if capture.WaitForCount(1, 10*time.Millisecond) {
		t.Error("WaitForCount should have timed out")
	}
}

func TestTokenCapture_Reset(t *testing.T) {
	admin, testCerts, err := TestAdmin[any]()
	if err != nil {
		t.Fatalf("TestAdmin failed: %v", err)
	}

	capture := NewTokenCapture()
	defer capture.Close()

	// Generate a token
	assertion, err := CreateAssertion(testCerts.ClientKey, testCerts.ClientCert)
	if err != nil {
		t.Fatalf("CreateAssertion failed: %v", err)
	}

	_, err = admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if capture.Count() != 1 {
		t.Fatalf("expected 1 token, got %d", capture.Count())
	}

	capture.Reset()
	if capture.Count() != 0 {
		t.Errorf("expected 0 tokens after reset, got %d", capture.Count())
	}
}

func TestGuardRecorder(t *testing.T) {
	admin, testCerts, err := TestAdmin[any]()
	if err != nil {
		t.Fatalf("TestAdmin failed: %v", err)
	}

	// Set policy that grants permissions
	_ = admin.SetPolicy(func(_ *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	recorder := NewGuardRecorder()
	defer recorder.Close()

	// Generate token
	assertion, err := CreateAssertion(testCerts.ClientKey, testCerts.ClientCert)
	if err != nil {
		t.Fatalf("CreateAssertion failed: %v", err)
	}

	token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Create guard
	guard, err := admin.CreateGuard(context.Background(), token, "read")
	if err != nil {
		t.Fatalf("CreateGuard failed: %v", err)
	}

	// Validate (should succeed)
	err = guard.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if recorder.ValidationCount() != 1 {
		t.Errorf("expected 1 validation, got %d", recorder.ValidationCount())
	}

	// Validate with no token (should fail)
	_ = guard.Validate(context.Background())

	if recorder.RejectionCount() != 1 {
		t.Errorf("expected 1 rejection, got %d", recorder.RejectionCount())
	}

	rejections := recorder.Rejections()
	if len(rejections) != 1 {
		t.Fatalf("expected 1 rejection, got %d", len(rejections))
	}
	if rejections[0].Error == "" {
		t.Error("rejection error should not be empty")
	}
}

func TestGuardRecorder_Reset(t *testing.T) {
	recorder := NewGuardRecorder()
	defer recorder.Close()

	// Manually add entries would require actual operations, so just test Reset
	if recorder.ValidationCount() != 0 {
		t.Error("initial validation count should be 0")
	}
	if recorder.RejectionCount() != 0 {
		t.Error("initial rejection count should be 0")
	}

	recorder.Reset()
	if recorder.ValidationCount() != 0 {
		t.Error("validation count after reset should be 0")
	}
}

func TestCertBuilder_SelfSigned(t *testing.T) {
	cert, key, err := NewCertBuilder().
		WithCN("test-self-signed").
		WithOrganization("Test Org").
		WithValidity(time.Hour).
		SelfSigned()
	if err != nil {
		t.Fatalf("SelfSigned failed: %v", err)
	}

	if cert.Subject.CommonName != "test-self-signed" {
		t.Errorf("expected CN 'test-self-signed', got %q", cert.Subject.CommonName)
	}
	if key == nil {
		t.Error("key should not be nil")
	}
}

func TestCertBuilder_SignedBy(t *testing.T) {
	// Create CA
	caCert, caKey, err := NewCertBuilder().
		WithCN("Test CA").
		AsCA().
		WithValidity(24 * time.Hour).
		SelfSigned()
	if err != nil {
		t.Fatalf("CA creation failed: %v", err)
	}

	// Create client signed by CA
	clientCert, clientKey, err := NewCertBuilder().
		WithCN("test-client").
		WithDNSNames("test.example.com").
		WithValidity(time.Hour).
		SignedBy(caCert, caKey)
	if err != nil {
		t.Fatalf("SignedBy failed: %v", err)
	}

	if clientCert.Subject.CommonName != "test-client" {
		t.Errorf("expected CN 'test-client', got %q", clientCert.Subject.CommonName)
	}
	if clientKey == nil {
		t.Error("client key should not be nil")
	}
	if clientCert.Issuer.CommonName != "Test CA" {
		t.Errorf("expected issuer 'Test CA', got %q", clientCert.Issuer.CommonName)
	}
}

func TestCertBuilder_ECDSA(t *testing.T) {
	cert, key, err := NewCertBuilder().
		WithCN("ecdsa-cert").
		WithKeyType("ecdsa").
		SelfSigned()
	if err != nil {
		t.Fatalf("SelfSigned with ECDSA failed: %v", err)
	}

	if cert.Subject.CommonName != "ecdsa-cert" {
		t.Errorf("expected CN 'ecdsa-cert', got %q", cert.Subject.CommonName)
	}
	if key == nil {
		t.Error("key should not be nil")
	}
}

func TestGenerateTestCertificates(t *testing.T) {
	testCerts, err := GenerateTestCertificates()
	if err != nil {
		t.Fatalf("GenerateTestCertificates failed: %v", err)
	}

	if testCerts.RootCA == nil {
		t.Error("RootCA should not be nil")
	}
	if testCerts.RootCAKey == nil {
		t.Error("RootCAKey should not be nil")
	}
	if testCerts.ClientCert == nil {
		t.Error("ClientCert should not be nil")
	}
	if testCerts.ClientKey == nil {
		t.Error("ClientKey should not be nil")
	}
	if testCerts.CertPool == nil {
		t.Error("CertPool should not be nil")
	}

	// Verify client cert is signed by root
	if testCerts.ClientCert.Issuer.CommonName != testCerts.RootCA.Subject.CommonName {
		t.Errorf("client cert issuer mismatch: got %q, want %q",
			testCerts.ClientCert.Issuer.CommonName, testCerts.RootCA.Subject.CommonName)
	}
}

func TestGenerateAdditionalClientCert(t *testing.T) {
	testCerts, err := GenerateTestCertificates()
	if err != nil {
		t.Fatalf("GenerateTestCertificates failed: %v", err)
	}

	additionalCert, additionalKey, err := GenerateAdditionalClientCert(testCerts, "additional-client")
	if err != nil {
		t.Fatalf("GenerateAdditionalClientCert failed: %v", err)
	}

	if additionalCert.Subject.CommonName != "additional-client" {
		t.Errorf("expected CN 'additional-client', got %q", additionalCert.Subject.CommonName)
	}
	if additionalKey == nil {
		t.Error("additional key should not be nil")
	}
	if additionalCert.Issuer.CommonName != testCerts.RootCA.Subject.CommonName {
		t.Errorf("additional cert issuer mismatch: got %q, want %q",
			additionalCert.Issuer.CommonName, testCerts.RootCA.Subject.CommonName)
	}
}

func TestTestAdmin(t *testing.T) {
	admin, testCerts, err := TestAdmin[any]()
	if err != nil {
		t.Fatalf("TestAdmin failed: %v", err)
	}

	if admin == nil {
		t.Error("admin should not be nil")
	}
	if testCerts == nil {
		t.Error("testCerts should not be nil")
	}
}

func TestTestAdmin_WithECDSA(t *testing.T) {
	admin, testCerts, err := TestAdmin[any](WithECDSA())
	if err != nil {
		t.Fatalf("TestAdmin with ECDSA failed: %v", err)
	}

	if admin == nil {
		t.Error("admin should not be nil")
	}
	if testCerts == nil {
		t.Error("testCerts should not be nil")
	}
}
