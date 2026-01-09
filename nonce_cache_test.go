package sctx

import (
	"testing"
	"time"
)

func TestDefaultNonceOptions(t *testing.T) {
	opts := DefaultNonceOptions()
	if opts.MaxSize != 10000 {
		t.Errorf("Expected MaxSize 10000, got %d", opts.MaxSize)
	}
}

func TestBoundedNonceCache_FIFOEviction(t *testing.T) {
	cache := newBoundedNonceCache(3)
	expiry := time.Now().Add(time.Hour)

	// Add 3 nonces
	cache.Add("a", expiry)
	cache.Add("b", expiry)
	cache.Add("c", expiry)

	if cache.Count() != 3 {
		t.Errorf("Expected 3 nonces, got %d", cache.Count())
	}

	// Add 4th - should evict 'a' (FIFO)
	cache.Add("d", expiry)

	if cache.Count() != 3 {
		t.Errorf("Expected 3 nonces after eviction, got %d", cache.Count())
	}

	if cache.Contains("a") {
		t.Error("Nonce 'a' should have been evicted (FIFO)")
	}

	for _, nonce := range []string{"b", "c", "d"} {
		if !cache.Contains(nonce) {
			t.Errorf("Nonce '%s' should still exist", nonce)
		}
	}
}

func TestBoundedNonceCache_DuplicateSkipped(t *testing.T) {
	cache := newBoundedNonceCache(10)
	expiry := time.Now().Add(time.Hour)

	cache.Add("a", expiry)
	cache.Add("a", expiry) // duplicate

	if cache.Count() != 1 {
		t.Errorf("Expected 1 nonce (duplicate skipped), got %d", cache.Count())
	}
}

func TestBoundedNonceCache_Contains(t *testing.T) {
	cache := newBoundedNonceCache(10)

	if cache.Contains("nonexistent") {
		t.Error("Contains should return false for nonexistent nonce")
	}

	cache.Add("exists", time.Now().Add(time.Hour))

	if !cache.Contains("exists") {
		t.Error("Contains should return true for existing nonce")
	}
}

func TestBoundedNonceCache_CleanExpired(t *testing.T) {
	cache := newBoundedNonceCache(10)

	// Add expired and valid nonces using test helper
	cache.addForTesting("expired1", time.Now().Add(-time.Hour))
	cache.addForTesting("expired2", time.Now().Add(-time.Minute))
	cache.Add("valid", time.Now().Add(time.Hour))

	if cache.Count() != 3 {
		t.Errorf("Expected 3 nonces before cleanup, got %d", cache.Count())
	}

	cache.CleanExpired()

	if cache.Count() != 1 {
		t.Errorf("Expected 1 nonce after cleanup, got %d", cache.Count())
	}

	if cache.Contains("expired1") || cache.Contains("expired2") {
		t.Error("Expired nonces should have been cleaned up")
	}

	if !cache.Contains("valid") {
		t.Error("Valid nonce should still exist")
	}
}

func TestBoundedNonceCache_UnboundedMode(t *testing.T) {
	cache := newBoundedNonceCache(0) // unbounded
	expiry := time.Now().Add(time.Hour)

	// Add many nonces - should not evict
	for i := 0; i < 100; i++ {
		cache.Add(string(rune(i)), expiry)
	}

	if cache.Count() != 100 {
		t.Errorf("Expected 100 nonces in unbounded mode, got %d", cache.Count())
	}
}

func TestBoundedNonceCache_EvictOldestEmpty(t *testing.T) {
	cache := newBoundedNonceCache(3)

	// evictOldest on empty cache should not panic
	cache.evictOldest()

	if cache.Count() != 0 {
		t.Error("Empty cache should remain empty after evictOldest")
	}
}

func TestBoundedNonceCache_AllNonces(t *testing.T) {
	cache := newBoundedNonceCache(10)
	expiry := time.Now().Add(time.Hour)

	cache.Add("a", expiry)
	cache.Add("b", expiry)

	all := cache.allNonces()

	if len(all) != 2 {
		t.Errorf("Expected 2 nonces, got %d", len(all))
	}

	if _, exists := all["a"]; !exists {
		t.Error("Nonce 'a' should be in allNonces")
	}
	if _, exists := all["b"]; !exists {
		t.Error("Nonce 'b' should be in allNonces")
	}
}

func TestBoundedNonceCache_OrderPreservedAfterCleanup(t *testing.T) {
	cache := newBoundedNonceCache(5)

	// Add mix of expired and valid
	cache.addForTesting("expired1", time.Now().Add(-time.Hour))
	cache.Add("valid1", time.Now().Add(time.Hour))
	cache.addForTesting("expired2", time.Now().Add(-time.Hour))
	cache.Add("valid2", time.Now().Add(time.Hour))

	cache.CleanExpired()

	// After cleanup, valid1 should be evicted first (FIFO)
	cache.Add("new1", time.Now().Add(time.Hour))
	cache.Add("new2", time.Now().Add(time.Hour))
	cache.Add("new3", time.Now().Add(time.Hour))

	// Now at capacity (5), add one more
	cache.Add("new4", time.Now().Add(time.Hour))

	if cache.Contains("valid1") {
		t.Error("valid1 should have been evicted (oldest after cleanup)")
	}
}
