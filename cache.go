package sctx

import (
	"sync"
	"time"

	"github.com/zoobzio/zlog"
)

// ContextCache manages active contexts with automatic cleanup
type ContextCache[M any] interface {
	// Get retrieves an active context by certificate fingerprint
	Get(fingerprint string) (*Context[M], bool)

	// Store stores or updates an active context
	Store(fingerprint string, ctx *Context[M])

	// Delete removes an active token
	Delete(fingerprint string) error

	// Start begins the cleanup goroutine
	Start(shutdown chan struct{}, wg *sync.WaitGroup)
}

// memoryContextCache is an in-memory implementation of ContextCache
type memoryContextCache[M any] struct {
	contexts        map[string]*Context[M]
	mu              sync.RWMutex
	cleanupInterval time.Duration
}

// newMemoryContextCache creates a new in-memory context cache (private)
func newMemoryContextCache[M any](cleanupInterval time.Duration) ContextCache[M] {
	if cleanupInterval == 0 {
		cleanupInterval = 5 * time.Minute
	}
	return &memoryContextCache[M]{
		contexts:        make(map[string]*Context[M]),
		cleanupInterval: cleanupInterval,
	}
}

// Get retrieves an active context by certificate fingerprint
func (s *memoryContextCache[M]) Get(fingerprint string) (*Context[M], bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ctx, exists := s.contexts[fingerprint]
	return ctx, exists
}

// Set stores or updates an active context
func (s *memoryContextCache[M]) Store(fingerprint string, ctx *Context[M]) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.contexts[fingerprint] = ctx
}

// Delete removes an active context
func (s *memoryContextCache[M]) Delete(fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.contexts, fingerprint)
	return nil
}

// Start begins the cleanup goroutine
func (s *memoryContextCache[M]) Start(shutdown chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.cleanupExpiredContexts(shutdown)
	}()
}

// cleanupExpiredContexts periodically removes expired contexts
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
			for fingerprint, ctx := range s.contexts {
				if now.After(ctx.ExpiresAt) {
					delete(s.contexts, fingerprint)
					// Emit audit event for natural expiration
					cn := ""
					if ctx != nil {
						cn = ctx.CertificateInfo.CommonName
					}
					zlog.Emit(CONTEXT_EXPIRED, "Context expired naturally",
						zlog.String("fingerprint", fingerprint),
						zlog.String("cn", cn),
						zlog.Time("expired_at", ctx.ExpiresAt),
					)
				}
			}
			s.mu.Unlock()
		}
	}
}

// Count returns the number of active contexts (useful for stats/testing)
func (s *memoryContextCache[M]) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.contexts)
}
