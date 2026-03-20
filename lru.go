package sctx

import (
	"context"
	"sync"
	"time"

	"github.com/zoobz-io/capitan"
)

// CacheOptions configures cache behavior.
type CacheOptions struct {
	// MaxSize is the maximum number of entries. 0 means unbounded.
	MaxSize int
	// CleanupInterval is how often to clean expired entries.
	// Defaults to 5 minutes if not specified.
	CleanupInterval time.Duration
}

// DefaultCacheOptions returns sensible defaults (unbounded for backward compat).
func DefaultCacheOptions() CacheOptions {
	return CacheOptions{
		MaxSize:         0, // unbounded by default
		CleanupInterval: 5 * time.Minute,
	}
}

// lruNode is a node in the typed doubly-linked list.
type lruNode[M any] struct {
	fingerprint string
	context     *Context[M]
	prev        *lruNode[M]
	next        *lruNode[M]
}

// lruList is a typed doubly-linked list for LRU tracking.
type lruList[M any] struct {
	head *lruNode[M]
	tail *lruNode[M]
	len  int
}

// pushFront adds a node to the front of the list.
func (l *lruList[M]) pushFront(node *lruNode[M]) {
	node.prev = nil
	node.next = l.head
	if l.head != nil {
		l.head.prev = node
	}
	l.head = node
	if l.tail == nil {
		l.tail = node
	}
	l.len++
}

// remove removes a node from the list.
func (l *lruList[M]) remove(node *lruNode[M]) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		l.head = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	} else {
		l.tail = node.prev
	}
	node.prev = nil
	node.next = nil
	l.len--
}

// moveToFront moves an existing node to the front.
func (l *lruList[M]) moveToFront(node *lruNode[M]) {
	if l.head == node {
		return
	}
	l.remove(node)
	l.pushFront(node)
}

// back returns the last node (least recently used).
func (l *lruList[M]) back() *lruNode[M] {
	return l.tail
}

// boundedMemoryCache is an LRU-evicting context cache.
type boundedMemoryCache[M any] struct {
	nodes           map[string]*lruNode[M]
	list            lruList[M]
	mu              sync.RWMutex
	maxSize         int
	cleanupInterval time.Duration
}

// NewBoundedMemoryCache creates a cache with optional size limits.
func NewBoundedMemoryCache[M any](opts CacheOptions) ContextCache[M] {
	if opts.CleanupInterval == 0 {
		opts.CleanupInterval = 5 * time.Minute
	}
	return &boundedMemoryCache[M]{
		nodes:           make(map[string]*lruNode[M]),
		maxSize:         opts.MaxSize,
		cleanupInterval: opts.CleanupInterval,
	}
}

// Get retrieves and promotes entry to front of LRU.
func (c *boundedMemoryCache[M]) Get(ctx context.Context, fingerprint string) (*Context[M], bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	node, exists := c.nodes[fingerprint]
	if exists {
		c.list.moveToFront(node)
		capitan.Debug(ctx, CacheHit, FingerprintKey.Field(fingerprint))
		return node.context, true
	}
	capitan.Debug(ctx, CacheMiss, FingerprintKey.Field(fingerprint))
	return nil, false
}

// Store adds/updates entry and evicts LRU if over capacity.
func (c *boundedMemoryCache[M]) Store(ctx context.Context, fingerprint string, sctx *Context[M]) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If already exists, update and promote
	if node, exists := c.nodes[fingerprint]; exists {
		node.context = sctx
		c.list.moveToFront(node)
		capitan.Debug(ctx, CacheStored, FingerprintKey.Field(fingerprint))
		return
	}

	// Evict LRU entries if at capacity
	if c.maxSize > 0 && len(c.nodes) >= c.maxSize {
		c.evictLRU(ctx)
	}

	// Add new entry
	node := &lruNode[M]{
		fingerprint: fingerprint,
		context:     sctx,
	}
	c.list.pushFront(node)
	c.nodes[fingerprint] = node
	capitan.Debug(ctx, CacheStored, FingerprintKey.Field(fingerprint))
}

// evictLRU removes the least recently used entry (must hold write lock).
func (c *boundedMemoryCache[M]) evictLRU(ctx context.Context) {
	node := c.list.back()
	if node == nil {
		return
	}
	c.list.remove(node)
	delete(c.nodes, node.fingerprint)
	capitan.Debug(ctx, CacheEvicted, FingerprintKey.Field(node.fingerprint))
}

// Delete removes an entry.
func (c *boundedMemoryCache[M]) Delete(ctx context.Context, fingerprint string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if node, exists := c.nodes[fingerprint]; exists {
		c.list.remove(node)
		delete(c.nodes, fingerprint)
		capitan.Debug(ctx, CacheDeleted, FingerprintKey.Field(fingerprint))
	}
	return nil
}

// Start begins the cleanup goroutine.
func (c *boundedMemoryCache[M]) Start(shutdown chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.cleanupExpiredContexts(shutdown)
	}()
}

// cleanupExpiredContexts periodically removes expired contexts.
func (c *boundedMemoryCache[M]) cleanupExpiredContexts(shutdown chan struct{}) {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			return
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			// Iterate from tail (oldest) to head
			node := c.list.tail
			for node != nil {
				prev := node.prev
				if now.After(node.context.ExpiresAt) {
					c.list.remove(node)
					delete(c.nodes, node.fingerprint)
					capitan.Debug(context.Background(), CacheExpired, FingerprintKey.Field(node.fingerprint))
				}
				node = prev
			}
			c.mu.Unlock()
		}
	}
}

// Count returns the number of entries.
func (c *boundedMemoryCache[M]) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.nodes)
}

// Clear removes all entries.
func (c *boundedMemoryCache[M]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodes = make(map[string]*lruNode[M])
	c.list = lruList[M]{}
}
