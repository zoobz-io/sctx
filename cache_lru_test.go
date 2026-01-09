package sctx

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDefaultCacheOptions(t *testing.T) {
	opts := DefaultCacheOptions()
	if opts.MaxSize != 0 {
		t.Errorf("Expected MaxSize 0 (unbounded), got %d", opts.MaxSize)
	}
	if opts.CleanupInterval != 5*time.Minute {
		t.Errorf("Expected CleanupInterval 5m, got %v", opts.CleanupInterval)
	}
}

func TestBoundedMemoryCache_LRUEviction(t *testing.T) {
	cache := NewBoundedMemoryCache[any](CacheOptions{MaxSize: 3})
	ctx := context.Background()

	// Add 3 entries
	for i := 0; i < 3; i++ {
		fp := string(rune('a' + i))
		cache.Store(ctx, fp, &Context[any]{
			CertificateFingerprint: fp,
			ExpiresAt:              time.Now().Add(time.Hour),
		})
	}

	if cache.Count() != 3 {
		t.Errorf("Expected 3 entries, got %d", cache.Count())
	}

	// Access 'a' to make it recently used
	cache.Get(ctx, "a")

	// Add 4th entry - should evict 'b' (oldest not accessed)
	cache.Store(ctx, "d", &Context[any]{
		CertificateFingerprint: "d",
		ExpiresAt:              time.Now().Add(time.Hour),
	})

	if cache.Count() != 3 {
		t.Errorf("Expected 3 entries after eviction, got %d", cache.Count())
	}

	// 'b' should be evicted (was LRU)
	if _, exists := cache.Get(ctx, "b"); exists {
		t.Error("Entry 'b' should have been evicted")
	}

	// 'a', 'c', 'd' should still exist
	for _, fp := range []string{"a", "c", "d"} {
		if _, exists := cache.Get(ctx, fp); !exists {
			t.Errorf("Entry '%s' should still exist", fp)
		}
	}
}

func TestBoundedMemoryCache_GetPromotesToFront(t *testing.T) {
	cache := NewBoundedMemoryCache[any](CacheOptions{MaxSize: 2})
	ctx := context.Background()

	// Add 2 entries: a, then b
	cache.Store(ctx, "a", &Context[any]{ExpiresAt: time.Now().Add(time.Hour)})
	cache.Store(ctx, "b", &Context[any]{ExpiresAt: time.Now().Add(time.Hour)})

	// Access 'a' to promote it
	cache.Get(ctx, "a")

	// Add 'c' - should evict 'b' (now LRU)
	cache.Store(ctx, "c", &Context[any]{ExpiresAt: time.Now().Add(time.Hour)})

	if _, exists := cache.Get(ctx, "b"); exists {
		t.Error("Entry 'b' should have been evicted")
	}
	if _, exists := cache.Get(ctx, "a"); !exists {
		t.Error("Entry 'a' should still exist after promotion")
	}
}

func TestBoundedMemoryCache_StoreUpdatesExisting(t *testing.T) {
	cache := NewBoundedMemoryCache[any](CacheOptions{MaxSize: 2})
	ctx := context.Background()

	// Store initial value
	cache.Store(ctx, "a", &Context[any]{
		Permissions: []string{"read"},
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	// Update with new value
	cache.Store(ctx, "a", &Context[any]{
		Permissions: []string{"read", "write"},
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	// Should still be 1 entry
	if cache.Count() != 1 {
		t.Errorf("Expected 1 entry after update, got %d", cache.Count())
	}

	// Should have updated permissions
	retrieved, _ := cache.Get(ctx, "a")
	if len(retrieved.Permissions) != 2 {
		t.Error("Permissions should be updated")
	}
}

func TestBoundedMemoryCache_UnboundedMode(t *testing.T) {
	cache := NewBoundedMemoryCache[any](CacheOptions{MaxSize: 0})
	ctx := context.Background()

	// Add many entries - should not evict
	for i := 0; i < 100; i++ {
		fp := string(rune(i))
		cache.Store(ctx, fp, &Context[any]{ExpiresAt: time.Now().Add(time.Hour)})
	}

	if cache.Count() != 100 {
		t.Errorf("Expected 100 entries in unbounded mode, got %d", cache.Count())
	}
}

func TestBoundedMemoryCache_Delete(t *testing.T) {
	cache := NewBoundedMemoryCache[any](CacheOptions{MaxSize: 10})
	ctx := context.Background()

	cache.Store(ctx, "a", &Context[any]{ExpiresAt: time.Now().Add(time.Hour)})
	cache.Store(ctx, "b", &Context[any]{ExpiresAt: time.Now().Add(time.Hour)})

	if err := cache.Delete(ctx, "a"); err != nil {
		t.Errorf("Delete failed: %v", err)
	}

	if cache.Count() != 1 {
		t.Errorf("Expected 1 entry after delete, got %d", cache.Count())
	}

	if _, exists := cache.Get(ctx, "a"); exists {
		t.Error("Deleted entry should not exist")
	}

	// Delete non-existent should not error
	if err := cache.Delete(ctx, "nonexistent"); err != nil {
		t.Errorf("Delete non-existent should not error: %v", err)
	}
}

func TestBoundedMemoryCache_Clear(t *testing.T) {
	cache := NewBoundedMemoryCache[any](CacheOptions{MaxSize: 10})
	boundedCache := cache.(*boundedMemoryCache[any])
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		cache.Store(ctx, string(rune('a'+i)), &Context[any]{ExpiresAt: time.Now().Add(time.Hour)})
	}

	boundedCache.Clear()

	if cache.Count() != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", cache.Count())
	}
}

func TestBoundedMemoryCache_CleanupExpired(t *testing.T) {
	cache := NewBoundedMemoryCache[any](CacheOptions{
		MaxSize:         10,
		CleanupInterval: 50 * time.Millisecond,
	})
	ctx := context.Background()

	// Add expired and valid entries
	cache.Store(ctx, "expired", &Context[any]{ExpiresAt: time.Now().Add(-time.Hour)})
	cache.Store(ctx, "valid", &Context[any]{ExpiresAt: time.Now().Add(time.Hour)})

	// Start cleanup
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	cache.Start(shutdown, &wg)

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)

	if _, exists := cache.Get(ctx, "expired"); exists {
		t.Error("Expired entry should have been cleaned up")
	}
	if _, exists := cache.Get(ctx, "valid"); !exists {
		t.Error("Valid entry should still exist")
	}

	close(shutdown)
	wg.Wait()
}

func TestBoundedMemoryCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	cache := NewBoundedMemoryCache[any](CacheOptions{MaxSize: 10})
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			fp := string(rune('a' + (id % 26)))
			cache.Store(ctx, fp, &Context[any]{
				CertificateFingerprint: fp,
				ExpiresAt:              time.Now().Add(time.Hour),
			})
			cache.Get(ctx, fp)
			if id%10 == 0 {
				cache.Delete(ctx, fp)
			}
		}(i)
	}

	wg.Wait()
}

func TestBoundedMemoryCache_DefaultCleanupInterval(t *testing.T) {
	cache := NewBoundedMemoryCache[any](CacheOptions{MaxSize: 10})
	boundedCache := cache.(*boundedMemoryCache[any])

	if boundedCache.cleanupInterval != 5*time.Minute {
		t.Errorf("Expected default cleanup interval 5m, got %v", boundedCache.cleanupInterval)
	}
}
