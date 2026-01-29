package sctx

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/zoobzio/capitan"
)

// contextKey is the unexported key type for embedding tokens in context.Context.
type contextKey struct{}

// TokenFromContext extracts a SignedToken from context.Context.
func TokenFromContext(ctx context.Context) (SignedToken, bool) {
	token, ok := ctx.Value(contextKey{}).(SignedToken)
	return token, ok
}

// NewPrincipal creates a principal by authenticating a certificate against the admin.
// It creates an assertion, generates a token, and returns a ready-to-use principal.
func NewPrincipal[M any](ctx context.Context, admin Admin[M], privateKey crypto.PrivateKey, cert *x509.Certificate) (Principal, error) {
	assertion, err := CreateAssertion(privateKey, cert)
	if err != nil {
		return nil, err
	}

	token, err := admin.Generate(ctx, cert, assertion)
	if err != nil {
		return nil, err
	}

	capitan.Debug(ctx, PrincipalCreated,
		FingerprintKey.Field(GetFingerprint(cert)),
		CommonNameKey.Field(cert.Subject.CommonName),
	)

	return &principal[M]{
		token: token,
		admin: admin,
	}, nil
}

type principal[M any] struct {
	token SignedToken
	admin Admin[M]
}

func (p *principal[M]) Token() SignedToken {
	return p.token
}

func (p *principal[M]) Inject(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKey{}, p.token)
}

func (p *principal[M]) Guard(ctx context.Context, requiredPermissions ...string) (Guard, error) {
	inner, err := p.admin.CreateGuard(ctx, p.token, requiredPermissions...)
	if err != nil {
		return nil, err
	}
	return &contextGuard{
		inner:        inner,
		creatorToken: p.token,
	}, nil
}

// contextGuard wraps a Guard to automatically extract tokens from context.Context.
type contextGuard struct {
	inner        Guard
	creatorToken SignedToken
}

func (g *contextGuard) ID() string { return g.inner.ID() }

func (g *contextGuard) Permissions() []string { return g.inner.Permissions() }

func (g *contextGuard) Validate(ctx context.Context, tokens ...SignedToken) error {
	if len(tokens) == 0 {
		token, ok := TokenFromContext(ctx)
		if !ok {
			return errors.New("no token in context")
		}
		return g.inner.Validate(ctx, g.creatorToken, token)
	}
	all := make([]SignedToken, 0, len(tokens)+1)
	all = append(all, g.creatorToken)
	all = append(all, tokens...)
	return g.inner.Validate(ctx, all...)
}
