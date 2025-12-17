package sctx

import (
	"context"
	"sync"
	"time"

	"github.com/zoobzio/capitan"
)

// ContextCache manages active contexts with automatic cleanup.
type ContextCache[M any] interface {
	// Get retrieves an active context by certificate fingerprint
	Get(ctx context.Context, fingerprint string) (*Context[M], bool)

	// Store stores or updates an active context
	Store(ctx context.Context, fingerprint string, sctx *Context[M])

	// Delete removes an active token
	Delete(ctx context.Context, fingerprint string) error

	// Start begins the cleanup goroutine
	Start(shutdown chan struct{}, wg *sync.WaitGroup)
}

// memoryContextCache is an in-memory implementation of ContextCache.
type memoryContextCache[M any] struct {
	contexts        map[string]*Context[M]
	mu              sync.RWMutex
	cleanupInterval time.Duration
}

// NewMemoryContextCache creates a new in-memory context cache.
// cleanupInterval specifies how often expired contexts are cleaned up.
// If cleanupInterval is 0, defaults to 5 minutes.
func NewMemoryContextCache[M any](cleanupInterval time.Duration) ContextCache[M] {
	if cleanupInterval == 0 {
		cleanupInterval = 5 * time.Minute
	}
	return &memoryContextCache[M]{
		contexts:        make(map[string]*Context[M]),
		cleanupInterval: cleanupInterval,
	}
}

// newMemoryContextCache is an alias for internal usage.
func newMemoryContextCache[M any](cleanupInterval time.Duration) ContextCache[M] {
	return NewMemoryContextCache[M](cleanupInterval)
}

// Get retrieves an active context by certificate fingerprint.
func (s *memoryContextCache[M]) Get(ctx context.Context, fingerprint string) (*Context[M], bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sctx, exists := s.contexts[fingerprint]
	if exists {
		capitan.Debug(ctx, CacheHit, FingerprintKey.Field(fingerprint))
	} else {
		capitan.Debug(ctx, CacheMiss, FingerprintKey.Field(fingerprint))
	}
	return sctx, exists
}

// Store stores or updates an active context.
func (s *memoryContextCache[M]) Store(ctx context.Context, fingerprint string, sctx *Context[M]) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.contexts[fingerprint] = sctx
	capitan.Debug(ctx, CacheStored, FingerprintKey.Field(fingerprint))
}

// Delete removes an active context.
func (s *memoryContextCache[M]) Delete(ctx context.Context, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.contexts, fingerprint)
	capitan.Debug(ctx, CacheDeleted, FingerprintKey.Field(fingerprint))
	return nil
}

// Start begins the cleanup goroutine.
func (s *memoryContextCache[M]) Start(shutdown chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.cleanupExpiredContexts(shutdown)
	}()
}

// cleanupExpiredContexts periodically removes expired contexts.
func (s *memoryContextCache[M]) cleanupExpiredContexts(shutdown chan struct{}) {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for fingerprint, sctx := range s.contexts {
				if now.After(sctx.ExpiresAt) {
					delete(s.contexts, fingerprint)
					capitan.Debug(context.Background(), CacheExpired, FingerprintKey.Field(fingerprint))
				}
			}
			s.mu.Unlock()
		}
	}
}

// Count returns the number of active contexts (useful for stats/testing).
func (s *memoryContextCache[M]) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.contexts)
}

// Clear removes all contexts from the cache.
func (s *memoryContextCache[M]) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contexts = make(map[string]*Context[M])
}
