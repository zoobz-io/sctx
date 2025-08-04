package sctx

import (
	"context"
	"fmt"

	"github.com/zoobzio/pipz"
	"github.com/zoobzio/zlog"
)

// ContextEvent represents token/context lifecycle events
type ContextEvent[M any] struct {
	Context   *Context[M]
	Token     string
	Operation string // "generated", "verified", "revoked", "expired"
}

// CertificateEvent represents certificate validation events
type CertificateEvent struct {
	CertificateInfo CertificateInfo
	Reason          string
	Error           error
}

// Clone creates a deep copy of ContextEvent for pipz.Cloner interface
func (e ContextEvent[M]) Clone() ContextEvent[M] {
	return ContextEvent[M]{
		Context:   e.Context.Clone(),
		Token:     e.Token,
		Operation: e.Operation,
	}
}

// Clone creates a deep copy of CertificateEvent for pipz.Cloner interface
func (e CertificateEvent) Clone() CertificateEvent {
	cloned := CertificateEvent{
		Reason: e.Reason,
		Error:  e.Error,
	}

	// Deep copy CertificateInfo
	cloned.CertificateInfo = CertificateInfo{
		CommonName:   e.CertificateInfo.CommonName,
		SerialNumber: e.CertificateInfo.SerialNumber,
		NotBefore:    e.CertificateInfo.NotBefore,
		NotAfter:     e.CertificateInfo.NotAfter,
		Issuer:       e.CertificateInfo.Issuer,
	}

	// Deep copy KeyUsage slice
	if e.CertificateInfo.KeyUsage != nil {
		cloned.CertificateInfo.KeyUsage = make([]string, len(e.CertificateInfo.KeyUsage))
		copy(cloned.CertificateInfo.KeyUsage, e.CertificateInfo.KeyUsage)
	}

	return cloned
}

// Security audit signals for sctx events.
// These signals can be routed to audit logs, SIEM systems, or monitoring tools.
//
//nolint:revive // Signal constants follow zlog convention of ALL_CAPS
const (
	// TOKEN_GENERATED indicates a new token was created from a certificate
	TOKEN_GENERATED = zlog.Signal("TOKEN_GENERATED")

	// TOKEN_VERIFIED indicates successful token verification
	TOKEN_VERIFIED = zlog.Signal("TOKEN_VERIFIED")

	// TOKEN_REJECTED indicates failed token verification
	TOKEN_REJECTED = zlog.Signal("TOKEN_REJECTED")

	// GUARD_CREATED indicates a new guard was created
	GUARD_CREATED = zlog.Signal("GUARD_CREATED")

	// GUARD_VALIDATED indicates successful guard validation
	GUARD_VALIDATED = zlog.Signal("GUARD_VALIDATED")

	// GUARD_REJECTED indicates failed guard validation
	GUARD_REJECTED = zlog.Signal("GUARD_REJECTED")

	// CONTEXT_REVOKED indicates a context was manually revoked
	CONTEXT_REVOKED = zlog.Signal("CONTEXT_REVOKED")

	// CONTEXT_EXPIRED indicates a context expired naturally
	CONTEXT_EXPIRED = zlog.Signal("CONTEXT_EXPIRED")

	// CERTIFICATE_REJECTED indicates certificate validation failure
	CERTIFICATE_REJECTED = zlog.Signal("CERTIFICATE_REJECTED")

	// ADMIN_CHANGED indicates the admin service was changed
	ADMIN_CHANGED = zlog.Signal("ADMIN_CHANGED")
)

// Processor names as constants
const (
	ProcessorSanitizeContext     = "sanitize-context"
	ProcessorSanitizeCertificate = "sanitize-certificate"
)

// certificateSanitizer sanitizes certificate events
var certificateSanitizer = pipz.Transform[zlog.Event[CertificateEvent]](ProcessorSanitizeCertificate,
	func(ctx context.Context, event zlog.Event[CertificateEvent]) zlog.Event[CertificateEvent] {
		sanitized := event.Clone()

		// Keep certificate for debugging but could redact sensitive fields
		// For now, just ensure error messages don't leak sensitive info
		if sanitized.Data.Error != nil {
			sanitized.Data.Error = fmt.Errorf("certificate validation failed")
		}

		return sanitized
	})

// getContextSanitizer returns a type-specific context sanitizer
func getContextSanitizer[M any]() pipz.Chainable[zlog.Event[ContextEvent[M]]] {
	// Create type-specific sanitizer
	return pipz.Transform[zlog.Event[ContextEvent[M]]](ProcessorSanitizeContext,
		func(ctx context.Context, event zlog.Event[ContextEvent[M]]) zlog.Event[ContextEvent[M]] {
			sanitized := event.Clone()

			if sanitized.Data.Context != nil {
				safeCtx := sanitized.Data.Context.Clone()
				// Clear metadata - we can't assign nil to generic type
				var zeroMetadata M
				safeCtx.Metadata = zeroMetadata

				if len(safeCtx.Permissions) > 5 {
					safeCtx.Permissions = append(safeCtx.Permissions[:3],
						fmt.Sprintf("...and %d more", len(safeCtx.Permissions)-3))
				}

				sanitized.Data.Context = safeCtx
			}

			return sanitized
		})
}
