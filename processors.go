package sctx

import (
	"time"

	"github.com/zoobzio/pipz"
)

// Processor name constants for introspection and schema validation
const (
	// Context manipulation processors
	ProcessorSetExpiryOneHour     = "set-expiry-1h"
	ProcessorSetExpiryFiveMinutes = "set-expiry-5m"

	// Permission processors
	ProcessorGrantRead        = "grant-read"
	ProcessorGrantWrite       = "grant-write"
	ProcessorGrantAdmin       = "grant-admin"
	ProcessorGrantCreateGuard = "grant-create-guard"
)

// CreateProcessors creates processor instances for a specific metadata type
func CreateProcessors[M any]() ProcessorSet[M] {
	return ProcessorSet[M]{
		// Context manipulation processors
		SetExpiryOneHour:     pipz.Apply(ProcessorSetExpiryOneHour, SetContext[M](ContextOptions{Expiry: func() *time.Duration { d := time.Hour; return &d }()})),
		SetExpiryFiveMinutes: pipz.Apply(ProcessorSetExpiryFiveMinutes, SetContext[M](ContextOptions{Expiry: func() *time.Duration { d := 5 * time.Minute; return &d }()})),

		// Permission processors
		GrantRead:        pipz.Apply(ProcessorGrantRead, GrantPermissions[M]("read")),
		GrantWrite:       pipz.Apply(ProcessorGrantWrite, GrantPermissions[M]("write")),
		GrantAdmin:       pipz.Apply(ProcessorGrantAdmin, GrantPermissions[M]("admin")),
		GrantCreateGuard: pipz.Apply(ProcessorGrantCreateGuard, GrantPermissions[M]("create-guard")),
	}
}

// ProcessorSet holds all the available processors for a specific metadata type
type ProcessorSet[M any] struct {
	// Context manipulation processors
	SetExpiryOneHour     pipz.Chainable[*Context[M]]
	SetExpiryFiveMinutes pipz.Chainable[*Context[M]]

	// Permission processors
	GrantRead        pipz.Chainable[*Context[M]]
	GrantWrite       pipz.Chainable[*Context[M]]
	GrantAdmin       pipz.Chainable[*Context[M]]
	GrantCreateGuard pipz.Chainable[*Context[M]]
}
