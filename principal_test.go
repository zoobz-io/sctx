package sctx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestNewPrincipal(t *testing.T) {
	testCerts := GenerateTestCertificates(t)
	admin := createPrincipalTestAdmin(t, testCerts)

	ctx := context.Background()
	p, err := NewPrincipal(ctx, admin, testCerts.ClientKey, testCerts.ClientCert)
	if err != nil {
		t.Fatalf("failed to create principal: %v", err)
	}

	if p.Token() == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestPrincipalInjectExtract(t *testing.T) {
	testCerts := GenerateTestCertificates(t)
	admin := createPrincipalTestAdmin(t, testCerts)

	ctx := context.Background()
	p, err := NewPrincipal(ctx, admin, testCerts.ClientKey, testCerts.ClientCert)
	if err != nil {
		t.Fatalf("failed to create principal: %v", err)
	}

	injected := p.Inject(ctx)

	token, ok := TokenFromContext(injected)
	if !ok {
		t.Fatal("expected token in context")
	}
	if token != p.Token() {
		t.Fatal("extracted token does not match principal token")
	}
}

func TestTokenFromContextMissing(t *testing.T) {
	_, ok := TokenFromContext(context.Background())
	if ok {
		t.Fatal("expected no token in empty context")
	}
}

func TestPrincipalGuardValidatesFromContext(t *testing.T) {
	testCerts := GenerateTestCertificates(t)
	admin := createPrincipalTestAdmin(t, testCerts)

	ctx := context.Background()

	creator, err := NewPrincipal(ctx, admin, testCerts.ClientKey, testCerts.ClientCert)
	if err != nil {
		t.Fatalf("failed to create creator principal: %v", err)
	}

	callerCert, callerKey := GenerateAdditionalClientCert(t, testCerts, "caller")

	caller, err := NewPrincipal(ctx, admin, callerKey, callerCert)
	if err != nil {
		t.Fatalf("failed to create caller principal: %v", err)
	}

	guard, err := creator.Guard(ctx)
	if err != nil {
		t.Fatalf("failed to create guard: %v", err)
	}

	callerCtx := caller.Inject(ctx)

	if err := guard.Validate(callerCtx); err != nil {
		t.Fatalf("guard validation failed: %v", err)
	}
}

func TestPrincipalGuardRejectsMissingContextToken(t *testing.T) {
	testCerts := GenerateTestCertificates(t)
	admin := createPrincipalTestAdmin(t, testCerts)

	ctx := context.Background()
	p, err := NewPrincipal(ctx, admin, testCerts.ClientKey, testCerts.ClientCert)
	if err != nil {
		t.Fatalf("failed to create principal: %v", err)
	}

	guard, err := p.Guard(ctx)
	if err != nil {
		t.Fatalf("failed to create guard: %v", err)
	}

	if err := guard.Validate(context.Background()); err == nil {
		t.Fatal("expected error for missing context token")
	}
}

func createPrincipalTestAdmin(t *testing.T, testCerts *TestCertificates) Admin[any] {
	t.Helper()
	resetAdminForTesting()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	admin, err := NewAdminService[any](privateKey, testCerts.CertPool)
	if err != nil {
		t.Fatalf("failed to create admin service: %v", err)
	}

	return admin
}
