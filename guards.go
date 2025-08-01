package sctx

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// ContextGuard is a function that enriches a context in the pipeline
type ContextGuard[M any] = func(context.Context, *Context[M]) (*Context[M], error)

// Context Enrichment Guards - for building security context from certificates

// RequireCertField ensures a certificate field matches an expected value
func RequireCertField[M any](field, expected string) ContextGuard[M] {
	return func(_ context.Context, ctx *Context[M]) (*Context[M], error) {
		actual := extractCertField(ctx.Certificate, field)
		if actual != expected {
			return nil, fmt.Errorf("certificate field %s mismatch: expected %q, got %q", field, expected, actual)
		}
		return ctx, nil
	}
}

// RequireCertPattern ensures a certificate field matches a pattern
func RequireCertPattern[M any](field, pattern string) ContextGuard[M] {
	return func(_ context.Context, ctx *Context[M]) (*Context[M], error) {
		// TODO: Implement regex matching
		// For now, just check contains
		actual := extractCertField(ctx.Certificate, field)
		if !strings.Contains(actual, pattern) {
			return nil, fmt.Errorf("certificate field %s does not match pattern %q", field, pattern)
		}
		return ctx, nil
	}
}

// GrantPermissions adds permissions to the context
func GrantPermissions[M any](permissions ...string) ContextGuard[M] {
	return func(_ context.Context, ctx *Context[M]) (*Context[M], error) {
		ctx.Permissions = append(ctx.Permissions, permissions...)
		return ctx, nil
	}
}

// ContextOptions contains optional fields to set on a context
type ContextOptions struct {
	Expiry      *time.Duration
	Issuer      *string
	Permissions []string
}

// SetContext sets multiple context fields at once for efficiency
func SetContext[M any](opts ContextOptions) ContextGuard[M] {
	return func(_ context.Context, ctx *Context[M]) (*Context[M], error) {
		if opts.Expiry != nil {
			ctx.ExpiresAt = time.Now().Add(*opts.Expiry)
		}
		if opts.Issuer != nil {
			ctx.Issuer = *opts.Issuer
		}
		if len(opts.Permissions) > 0 {
			ctx.Permissions = append(ctx.Permissions, opts.Permissions...)
		}
		
		return ctx, nil
	}
}

// Helper function to extract certificate fields
func extractCertField(cert *x509.Certificate, field string) string {
	if cert == nil {
		return ""
	}
	
	switch strings.ToUpper(field) {
	case "CN":
		return cert.Subject.CommonName
	case "O":
		if len(cert.Subject.Organization) > 0 {
			return cert.Subject.Organization[0]
		}
	case "OU":
		if len(cert.Subject.OrganizationalUnit) > 0 {
			return cert.Subject.OrganizationalUnit[0]
		}
	case "C":
		if len(cert.Subject.Country) > 0 {
			return cert.Subject.Country[0]
		}
	case "L":
		if len(cert.Subject.Locality) > 0 {
			return cert.Subject.Locality[0]
		}
	case "ST":
		if len(cert.Subject.Province) > 0 {
			return cert.Subject.Province[0]
		}
	case "EMAIL":
		if len(cert.EmailAddresses) > 0 {
			return cert.EmailAddresses[0]
		}
	}
	return ""
}