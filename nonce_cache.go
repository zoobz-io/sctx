package sctx

import (
	"time"
)

// NonceOptions configures nonce cache behavior.
type NonceOptions struct {
	// MaxSize is the maximum number of nonces. 0 means unbounded.
	MaxSize int
}

// DefaultNonceOptions returns sensible defaults.
func DefaultNonceOptions() NonceOptions {
	return NonceOptions{
		MaxSize: 10000, // reasonable default for most deployments
	}
}

// nonceEntry tracks a nonce with its expiry.
type nonceEntry struct {
	nonce  string
	expiry time.Time
}

// boundedNonceCache manages nonces with optional size limits using FIFO eviction.
type boundedNonceCache struct {
	entries map[string]time.Time
	order   []nonceEntry // insertion order for FIFO eviction
	maxSize int
}

// newBoundedNonceCache creates a new bounded nonce cache.
func newBoundedNonceCache(maxSize int) *boundedNonceCache {
	return &boundedNonceCache{
		entries: make(map[string]time.Time),
		order:   make([]nonceEntry, 0),
		maxSize: maxSize,
	}
}

// Add adds a nonce with its expiry, evicting oldest if at capacity.
func (c *boundedNonceCache) Add(nonce string, expiry time.Time) {
	// If already exists, skip
	if _, exists := c.entries[nonce]; exists {
		return
	}

	// Evict oldest if at capacity (and maxSize > 0)
	if c.maxSize > 0 && len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[nonce] = expiry
	c.order = append(c.order, nonceEntry{nonce: nonce, expiry: expiry})
}

// Contains checks if a nonce exists.
func (c *boundedNonceCache) Contains(nonce string) bool {
	_, exists := c.entries[nonce]
	return exists
}

// evictOldest removes the oldest nonce.
func (c *boundedNonceCache) evictOldest() {
	if len(c.order) == 0 {
		return
	}
	oldest := c.order[0]
	c.order = c.order[1:]
	delete(c.entries, oldest.nonce)
}

// CleanExpired removes expired nonces.
func (c *boundedNonceCache) CleanExpired() {
	now := time.Now()
	newOrder := make([]nonceEntry, 0, len(c.order))
	for _, entry := range c.order {
		if now.After(entry.expiry) {
			delete(c.entries, entry.nonce)
		} else {
			newOrder = append(newOrder, entry)
		}
	}
	c.order = newOrder
}

// Count returns the number of nonces in the cache.
func (c *boundedNonceCache) Count() int {
	return len(c.entries)
}

// addForTesting adds a nonce with a specific expiry for testing purposes.
// This is used by tests to add expired nonces to verify cleanup behavior.
func (c *boundedNonceCache) addForTesting(nonce string, expiry time.Time) {
	c.entries[nonce] = expiry
	c.order = append(c.order, nonceEntry{nonce: nonce, expiry: expiry})
}

// allNonces returns all nonces with their expiry times (for testing).
func (c *boundedNonceCache) allNonces() map[string]time.Time {
	result := make(map[string]time.Time, len(c.entries))
	for k, v := range c.entries {
		result[k] = v
	}
	return result
}
