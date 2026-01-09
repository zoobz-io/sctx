package sctx

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestCacheCleanup tests the cache cleanup functionality.
func TestCacheCleanup(t *testing.T) {
	// Create cache with very short cleanup interval
	cache := newMemoryContextCache[any](100 * time.Millisecond)

	// Create contexts with different expiry times
	ctx1 := &Context[any]{
		ExpiresAt: time.Now().Add(-time.Hour), // Already expired
		CertificateInfo: CertificateInfo{
			CommonName: "expired-context",
		},
	}

	ctx2 := &Context[any]{
		ExpiresAt: time.Now().Add(time.Hour), // Still valid
		CertificateInfo: CertificateInfo{
			CommonName: "valid-context",
		},
	}

	// Store contexts
	cache.Store(context.Background(), "expired", ctx1)
	cache.Store(context.Background(), "valid", ctx2)

	// Verify both exist
	if cache.Count() != 2 {
		t.Errorf("Expected 2 contexts, got %d", cache.Count())
	}

	// Start cleanup
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	cache.Start(shutdown, &wg)

	// Wait for cleanup to run at least once
	time.Sleep(200 * time.Millisecond)

	// Check that expired context was removed
	if _, exists := cache.Get(context.Background(), "expired"); exists {
		t.Error("Expired context should have been cleaned up")
	}

	// Check that valid context still exists
	if _, exists := cache.Get(context.Background(), "valid"); !exists {
		t.Error("Valid context should still exist")
	}

	// Test shutdown
	close(shutdown)
	wg.Wait()
}

// TestNewMemoryContextCacheDefaultInterval tests default cleanup interval.
func TestNewMemoryContextCacheDefaultInterval(t *testing.T) {
	// Create cache with zero interval (should use default)
	cache := newMemoryContextCache[any](0)

	// Verify it's created (can't easily test the interval value)
	if cache == nil {
		t.Error("Cache should be created with default interval")
	}

	memCache := cache.(*memoryContextCache[any])
	if memCache.cleanupInterval == 0 {
		t.Error("Cleanup interval should not be zero")
	}
}

// TestCacheGetAndStore tests basic cache operations.
func TestCacheGetAndStore(t *testing.T) {
	cache := newMemoryContextCache[any](5 * time.Minute)
	ctx := context.Background()

	// Test store and get
	sctxContext := &Context[any]{
		Permissions:            []string{"read"},
		ExpiresAt:              time.Now().Add(time.Hour),
		CertificateFingerprint: "test-fingerprint",
	}

	cache.Store(ctx, "test-fingerprint", sctxContext)

	retrieved, exists := cache.Get(ctx, "test-fingerprint")
	if !exists {
		t.Error("Context should exist after store")
	}
	if retrieved.CertificateFingerprint != "test-fingerprint" {
		t.Error("Retrieved context fingerprint mismatch")
	}

	// Test get non-existent
	_, exists = cache.Get(ctx, "non-existent")
	if exists {
		t.Error("Non-existent context should not exist")
	}
}

// TestCacheDelete tests cache deletion.
func TestCacheDelete(t *testing.T) {
	cache := newMemoryContextCache[any](5 * time.Minute)
	ctx := context.Background()

	// Store a context
	sctxContext := &Context[any]{
		Permissions: []string{"read"},
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	cache.Store(ctx, "to-delete", sctxContext)

	// Verify it exists
	if _, exists := cache.Get(ctx, "to-delete"); !exists {
		t.Error("Context should exist before delete")
	}

	// Delete it
	err := cache.Delete(ctx, "to-delete")
	if err != nil {
		t.Errorf("Delete failed: %v", err)
	}

	// Verify it's gone
	if _, exists := cache.Get(ctx, "to-delete"); exists {
		t.Error("Context should not exist after delete")
	}

	// Delete non-existent (should not error)
	err = cache.Delete(ctx, "non-existent")
	if err != nil {
		t.Errorf("Deleting non-existent should not error: %v", err)
	}
}

// TestCacheCount tests the count functionality.
func TestCacheCount(t *testing.T) {
	cache := newMemoryContextCache[any](5 * time.Minute)
	ctx := context.Background()

	if cache.Count() != 0 {
		t.Error("Empty cache should have count 0")
	}

	// Add some contexts
	for i := 0; i < 5; i++ {
		sctxContext := &Context[any]{
			ExpiresAt: time.Now().Add(time.Hour),
		}
		cache.Store(ctx, string(rune('a'+i)), sctxContext)
	}

	if cache.Count() != 5 {
		t.Errorf("Expected count 5, got %d", cache.Count())
	}
}

// TestCacheClear tests the clear functionality.
func TestCacheClear(t *testing.T) {
	cache := newMemoryContextCache[any](5 * time.Minute)
	ctx := context.Background()
	memCache := cache.(*memoryContextCache[any])

	// Add some contexts
	for i := 0; i < 3; i++ {
		sctxContext := &Context[any]{
			ExpiresAt: time.Now().Add(time.Hour),
		}
		cache.Store(ctx, string(rune('a'+i)), sctxContext)
	}

	if cache.Count() != 3 {
		t.Errorf("Expected count 3, got %d", cache.Count())
	}

	// Clear the cache
	memCache.Clear()

	if cache.Count() != 0 {
		t.Errorf("Expected count 0 after clear, got %d", cache.Count())
	}
}

// TestCacheConcurrentAccess tests thread safety.
func TestCacheConcurrentAccess(t *testing.T) {
	t.Parallel()
	cache := newMemoryContextCache[any](5 * time.Minute)
	ctx := context.Background()

	// Run concurrent operations
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			fingerprint := string(rune('a' + (id % 26)))
			sctxContext := &Context[any]{
				ExpiresAt:              time.Now().Add(time.Hour),
				CertificateFingerprint: fingerprint,
			}
			cache.Store(ctx, fingerprint, sctxContext)
			cache.Get(ctx, fingerprint)
		}(i)
	}

	wg.Wait()
	// If we got here without panic, the test passed
}
