package sctx

import (
	"errors"
	"fmt"
	"time"
)

// IssuedGuard represents a guard created by a token holder
type IssuedGuard[M any] struct {
	id          string
	createdBy   string   // Fingerprint of creating token
	permissions []string // Required permissions
	expiresAt   time.Time
	admin       *AdminService[M]
}

// ID returns the unique identifier of this guard
func (g *IssuedGuard[M]) ID() string {
	return g.id
}

// Permissions returns the permissions this guard checks for
func (g *IssuedGuard[M]) Permissions() []string {
	return g.permissions
}

// Validate checks if a token has the required permissions
func (g *IssuedGuard[M]) Validate(token SignedToken) error {
	// Check if guard is expired
	if time.Now().After(g.expiresAt) {
		return errors.New("guard expired")
	}
	
	// Check if creating token is still valid
	creator, exists := g.admin.cache.Get(g.createdBy)
	if !exists {
		return errors.New("guard creator revoked")
	}
	if time.Now().After(creator.ExpiresAt) {
		return errors.New("guard creator expired")
	}
	
	// Decrypt target token
	fingerprint, err := g.admin.decryptToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}
	
	// Get context from cache
	ctx, exists := g.admin.cache.Get(fingerprint)
	if !exists {
		return errors.New("token not found or revoked")
	}
	
	// Check expiry
	if time.Now().After(ctx.ExpiresAt) {
		g.admin.cache.Delete(fingerprint)
		return errors.New("token expired")
	}
	
	// Check permissions
	for _, perm := range g.permissions {
		if !ctx.HasPermission(perm) {
			return fmt.Errorf("missing required permission: %s", perm)
		}
	}
	
	return nil
}