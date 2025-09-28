package sctx

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
//nolint:revive // Signal constants follow convention of ALL_CAPS
const (
	// TOKEN_GENERATED indicates a new token was created from a certificate
	TOKEN_GENERATED = "TOKEN_GENERATED"

	// TOKEN_VERIFIED indicates successful token verification
	TOKEN_VERIFIED = "TOKEN_VERIFIED"

	// TOKEN_REJECTED indicates failed token verification
	TOKEN_REJECTED = "TOKEN_REJECTED"

	// GUARD_CREATED indicates a new guard was created
	GUARD_CREATED = "GUARD_CREATED"

	// GUARD_VALIDATED indicates successful guard validation
	GUARD_VALIDATED = "GUARD_VALIDATED"

	// GUARD_REJECTED indicates failed guard validation
	GUARD_REJECTED = "GUARD_REJECTED"

	// CONTEXT_REVOKED indicates a context was manually revoked
	CONTEXT_REVOKED = "CONTEXT_REVOKED"

	// CONTEXT_EXPIRED indicates a context expired naturally
	CONTEXT_EXPIRED = "CONTEXT_EXPIRED"

	// CERTIFICATE_REJECTED indicates certificate validation failure
	CERTIFICATE_REJECTED = "CERTIFICATE_REJECTED"

	// ADMIN_CHANGED indicates the admin service was changed
	ADMIN_CHANGED = "ADMIN_CHANGED"

	// PIPELINE_UPDATED indicates the context pipeline was updated
	PIPELINE_UPDATED = "PIPELINE_UPDATED"
)

// Processor names as constants
const (
	ProcessorSanitizeContext     = "sanitize-context"
	ProcessorSanitizeCertificate = "sanitize-certificate"
)

