//go:build testing

package testing

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/zoobzio/sctx"
)

// TokenFromContext is a convenience re-export for testing.
func TokenFromContext(ctx context.Context) (sctx.SignedToken, bool) {
	return sctx.TokenFromContext(ctx)
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
