package sctx

import "github.com/zoobzio/capitan"

// Token lifecycle signals.
var (
	// TokenGenerated is emitted when a token is created from a certificate.
	// Fields: FingerprintKey, CommonNameKey, PermissionsKey.
	TokenGenerated = capitan.NewSignal("sctx.token.generated", "Security token created from certificate")

	// TokenVerified is emitted when a token is successfully verified.
	// Fields: FingerprintKey.
	TokenVerified = capitan.NewSignal("sctx.token.verified", "Security token successfully verified")

	// TokenRejected is emitted when token verification fails.
	// Fields: FingerprintKey, ErrorKey.
	TokenRejected = capitan.NewSignal("sctx.token.rejected", "Security token verification failed")
)

// Guard lifecycle signals.
var (
	// GuardCreated is emitted when a guard is created.
	// Fields: GuardIDKey, FingerprintKey, RequiredPermsKey.
	GuardCreated = capitan.NewSignal("sctx.guard.created", "Permission guard created by token holder")

	// GuardValidated is emitted when guard validation succeeds.
	// Fields: GuardIDKey, FingerprintKey.
	GuardValidated = capitan.NewSignal("sctx.guard.validated", "Guard validation succeeded for token")

	// GuardRejected is emitted when guard validation fails.
	// Fields: GuardIDKey, FingerprintKey, ErrorKey.
	GuardRejected = capitan.NewSignal("sctx.guard.rejected", "Guard validation failed for token")
)

// Context lifecycle signals.
var (
	// ContextRevoked is emitted when a context is manually revoked.
	// Fields: FingerprintKey.
	ContextRevoked = capitan.NewSignal("sctx.context.revoked", "Security context manually revoked")
)

// Principal lifecycle signals.
var (
	// PrincipalCreated is emitted when a principal is established from a certificate.
	// Fields: FingerprintKey, CommonNameKey.
	PrincipalCreated = capitan.NewSignal("sctx.principal.created", "Authenticated principal established from certificate")
)

// Assertion signals.
var (
	// AssertionValidated is emitted when an assertion passes validation.
	// Fields: FingerprintKey.
	AssertionValidated = capitan.NewSignal("sctx.assertion.validated", "Assertion validation succeeded")

	// AssertionRejected is emitted when assertion validation fails.
	// Fields: FingerprintKey, ErrorKey.
	AssertionRejected = capitan.NewSignal("sctx.assertion.rejected", "Assertion validation failed")
)

// Certificate signals.
var (
	// CertificateRejected is emitted when certificate verification fails.
	// Fields: CommonNameKey, ErrorKey.
	CertificateRejected = capitan.NewSignal("sctx.certificate.rejected", "Certificate verification failed")
)

// Cache operation signals.
var (
	// CacheStored is emitted when a context is stored in cache.
	// Fields: FingerprintKey.
	CacheStored = capitan.NewSignal("sctx.cache.stored", "Security context stored in cache")

	// CacheHit is emitted when a cache lookup succeeds.
	// Fields: FingerprintKey.
	CacheHit = capitan.NewSignal("sctx.cache.hit", "Cache lookup found existing context")

	// CacheMiss is emitted when a cache lookup fails.
	// Fields: FingerprintKey.
	CacheMiss = capitan.NewSignal("sctx.cache.miss", "Cache lookup did not find context")

	// CacheDeleted is emitted when a context is deleted from cache.
	// Fields: FingerprintKey.
	CacheDeleted = capitan.NewSignal("sctx.cache.deleted", "Security context deleted from cache")

	// CacheExpired is emitted when a context expires during cleanup.
	// Fields: FingerprintKey.
	CacheExpired = capitan.NewSignal("sctx.cache.expired", "Security context expired during cache cleanup")

	// CacheEvicted is emitted when a context is evicted due to cache size limits.
	// Fields: FingerprintKey.
	CacheEvicted = capitan.NewSignal("sctx.cache.evicted", "Security context evicted due to cache size limit")
)

// Event field keys.
var (
	// Identity fields.
	FingerprintKey = capitan.NewStringKey("fingerprint")
	CommonNameKey  = capitan.NewStringKey("common_name")

	// Permission fields.
	PermissionsKey   = capitan.NewStringKey("permissions")
	RequiredPermsKey = capitan.NewStringKey("required_permissions")

	// Guard fields.
	GuardIDKey = capitan.NewStringKey("guard_id")

	// Error field.
	ErrorKey = capitan.NewStringKey("error")

	// Time fields.
	ExpiresAtKey  = capitan.NewTimeKey("expires_at")
	DurationMsKey = capitan.NewInt64Key("duration_ms")
)
