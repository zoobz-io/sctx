package sctx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ContextGuard is a function that enriches a context in the pipeline
type ContextGuard[M any] func(context.Context, *Context[M]) (*Context[M], error)

// Context Enrichment Guards - for building security context from certificates

// RequireCertField ensures a certificate field matches an expected value
func RequireCertField[M any](field, expected string) ContextGuard[M] {
	return func(_ context.Context, ctx *Context[M]) (*Context[M], error) {
		actual := extractCertInfoField(ctx.CertificateInfo, field)
		if actual != expected {
			return nil, fmt.Errorf("certificate field %s mismatch: expected %q, got %q", field, expected, actual)
		}
		return ctx, nil
	}
}

// RequireCertPattern ensures a certificate field matches a regex pattern
func RequireCertPattern[M any](field, pattern string) ContextGuard[M] {
	return func(_ context.Context, ctx *Context[M]) (*Context[M], error) {
		// Compile regex pattern
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
		}

		actual := extractCertInfoField(ctx.CertificateInfo, field)
		if !re.MatchString(actual) {
			return nil, fmt.Errorf("certificate field %s with value %q does not match pattern %q", field, actual, pattern)
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
	Permissions []string
}

// SetContext sets multiple context fields at once for efficiency
func SetContext[M any](opts ContextOptions) ContextGuard[M] {
	return func(_ context.Context, ctx *Context[M]) (*Context[M], error) {
		if opts.Expiry != nil {
			ctx.ExpiresAt = time.Now().Add(*opts.Expiry)
		}
		if len(opts.Permissions) > 0 {
			ctx.Permissions = append(ctx.Permissions, opts.Permissions...)
		}

		return ctx, nil
	}
}

// Helper function to extract certificate info fields
func extractCertInfoField(certInfo CertificateInfo, field string) string {
	switch strings.ToUpper(field) {
	case "CN", "COMMONNAME":
		return certInfo.CommonName
	case "O", "ORGANIZATION":
		return strings.Join(certInfo.Organization, ",")
	case "OU", "ORGANIZATIONALUNIT":
		return strings.Join(certInfo.OrganizationalUnit, ",")
	case "C", "COUNTRY":
		return certInfo.Country
	case "ST", "STATE", "PROVINCE":
		return certInfo.Province
	case "L", "LOCALITY":
		return certInfo.Locality
	case "STREET", "STREETADDRESS":
		return strings.Join(certInfo.StreetAddress, ",")
	case "POSTALCODE":
		return strings.Join(certInfo.PostalCode, ",")
	case "ISSUER":
		return certInfo.Issuer
	case "ISSUERORG", "ISSUERORGANIZATION":
		return strings.Join(certInfo.IssuerOrganization, ",")
	case "SERIAL", "SERIALNUMBER":
		return certInfo.SerialNumber
	case "NOTBEFORE":
		return certInfo.NotBefore.Format(time.RFC3339)
	case "NOTAFTER":
		return certInfo.NotAfter.Format(time.RFC3339)
	case "KEYUSAGE":
		return strings.Join(certInfo.KeyUsage, ",")
	case "DNSNAMES", "DNS":
		return strings.Join(certInfo.DNSNames, ",")
	case "EMAILS", "EMAILADDRESSES":
		return strings.Join(certInfo.EmailAddresses, ",")
	case "URIS":
		return strings.Join(certInfo.URIs, ",")
	case "IPS", "IPADDRESSES":
		return strings.Join(certInfo.IPAddresses, ",")
	default:
		return ""
	}
}

// guardImpl implements the Guard interface
type guardImpl struct {
	id                  string
	creatorFingerprint  string   // Certificate fingerprint of the guard creator
	requiredPermissions []string
	validate            func(context.Context, ...SignedToken) error
}

// ID returns the unique identifier for this guard
func (g *guardImpl) ID() string {
	return g.id
}

// Validate checks if the token has the required permissions
func (g *guardImpl) Validate(ctx context.Context, tokens ...SignedToken) error {
	return g.validate(ctx, tokens...)
}

// Permissions returns the list of permissions this guard checks
func (g *guardImpl) Permissions() []string {
	// Return a copy to prevent modification
	perms := make([]string, len(g.requiredPermissions))
	copy(perms, g.requiredPermissions)
	return perms
}

// generateGuardID creates a unique identifier for a guard
func generateGuardID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("failed to generate guard ID: %v", err))
	}
	return hex.EncodeToString(bytes)
}

// hasPermission checks if a permission exists in the list
func hasPermission(permissions []string, permission string) bool {
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}
