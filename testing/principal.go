//go:build testing

package testing

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/zoobz-io/sctx"
)

// TokenFromContext is a convenience re-export for testing.
func TokenFromContext(ctx context.Context) (sctx.SignedToken, bool) {
	return sctx.TokenFromContext(ctx)
}

// InjectToken is a convenience re-export for testing.
func InjectToken(ctx context.Context, token sctx.SignedToken) context.Context {
	return sctx.InjectToken(ctx, token)
}

// GenerateTrusted creates a token from an mTLS-verified certificate for testing.
// This is a convenience wrapper around admin.GenerateTrusted that fails the test on error.
func GenerateTrusted[M any](ctx context.Context, tb testing.TB, admin sctx.Admin[M], cert *x509.Certificate) sctx.SignedToken {
	tb.Helper()

	token, err := admin.GenerateTrusted(ctx, cert)
	if err != nil {
		tb.Fatalf("failed to generate trusted token: %v", err)
	}

	return token
}

// TestPrincipal creates a principal for testing using the provided admin and certificate.
func TestPrincipal[M any](ctx context.Context, tb testing.TB, admin sctx.Admin[M], cert *x509.Certificate, key crypto.PrivateKey) sctx.Principal {
	tb.Helper()

	p, err := sctx.NewPrincipal(ctx, admin, key, cert)
	if err != nil {
		tb.Fatalf("failed to create principal: %v", err)
	}

	return p
}
