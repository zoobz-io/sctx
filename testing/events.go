//go:build testing

package testing

import (
	"context"
	"sync"
	"time"

	"github.com/zoobz-io/capitan"
	"github.com/zoobz-io/sctx"
)

// CapturedToken represents a captured token generation event.
type CapturedToken struct {
	Fingerprint string
	CommonName  string
	Permissions string
	Timestamp   time.Time
}

// TokenCapture captures token generation events for testing.
// Thread-safe for concurrent event capture.
type TokenCapture struct {
	tokens   []CapturedToken
	mu       sync.Mutex
	listener *capitan.Listener
}

// NewTokenCapture creates a new TokenCapture that hooks into sctx token events.
func NewTokenCapture() *TokenCapture {
	tc := &TokenCapture{
		tokens: make([]CapturedToken, 0),
	}
	tc.listener = capitan.Hook(sctx.TokenGenerated, func(_ context.Context, e *capitan.Event) {
		tc.mu.Lock()
		defer tc.mu.Unlock()
		fingerprint, _ := sctx.FingerprintKey.From(e)
		commonName, _ := sctx.CommonNameKey.From(e)
		permissions, _ := sctx.PermissionsKey.From(e)
		tc.tokens = append(tc.tokens, CapturedToken{
			Fingerprint: fingerprint,
			CommonName:  commonName,
			Permissions: permissions,
			Timestamp:   e.Timestamp(),
		})
	})
	return tc
}

// Close stops capturing events.
func (tc *TokenCapture) Close() {
	tc.listener.Close()
}

// Tokens returns a copy of all captured tokens.
func (tc *TokenCapture) Tokens() []CapturedToken {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	result := make([]CapturedToken, len(tc.tokens))
	copy(result, tc.tokens)
	return result
}

// Count returns the number of captured tokens.
func (tc *TokenCapture) Count() int {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return len(tc.tokens)
}

// Reset clears all captured tokens.
func (tc *TokenCapture) Reset() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.tokens = tc.tokens[:0]
}

// WaitForCount blocks until the capture has at least n tokens or timeout occurs.
// Returns true if count reached, false if timeout.
func (tc *TokenCapture) WaitForCount(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if tc.Count() >= n {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// ValidationRecord represents a successful guard validation.
type ValidationRecord struct {
	GuardID     string
	Fingerprint string
	Timestamp   time.Time
}

// RejectionRecord represents a failed guard validation.
type RejectionRecord struct {
	GuardID     string
	Fingerprint string
	Error       string
	Timestamp   time.Time
}

// GuardRecorder records guard validation operations for testing.
// Thread-safe for concurrent event capture.
type GuardRecorder struct {
	validations       []ValidationRecord
	rejections        []RejectionRecord
	mu                sync.Mutex
	validatedListener *capitan.Listener
	rejectedListener  *capitan.Listener
}

// NewGuardRecorder creates a new GuardRecorder that hooks into guard events.
func NewGuardRecorder() *GuardRecorder {
	gr := &GuardRecorder{
		validations: make([]ValidationRecord, 0),
		rejections:  make([]RejectionRecord, 0),
	}
	gr.validatedListener = capitan.Hook(sctx.GuardValidated, func(_ context.Context, e *capitan.Event) {
		gr.mu.Lock()
		defer gr.mu.Unlock()
		guardID, _ := sctx.GuardIDKey.From(e)
		fingerprint, _ := sctx.FingerprintKey.From(e)
		gr.validations = append(gr.validations, ValidationRecord{
			GuardID:     guardID,
			Fingerprint: fingerprint,
			Timestamp:   e.Timestamp(),
		})
	})
	gr.rejectedListener = capitan.Hook(sctx.GuardRejected, func(_ context.Context, e *capitan.Event) {
		gr.mu.Lock()
		defer gr.mu.Unlock()
		guardID, _ := sctx.GuardIDKey.From(e)
		fingerprint, _ := sctx.FingerprintKey.From(e)
		errorMsg, _ := sctx.ErrorKey.From(e)
		gr.rejections = append(gr.rejections, RejectionRecord{
			GuardID:     guardID,
			Fingerprint: fingerprint,
			Error:       errorMsg,
			Timestamp:   e.Timestamp(),
		})
	})
	return gr
}

// Close stops recording events.
func (gr *GuardRecorder) Close() {
	gr.validatedListener.Close()
	gr.rejectedListener.Close()
}

// Validations returns a copy of all successful validations.
func (gr *GuardRecorder) Validations() []ValidationRecord {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	result := make([]ValidationRecord, len(gr.validations))
	copy(result, gr.validations)
	return result
}

// Rejections returns a copy of all failed validations.
func (gr *GuardRecorder) Rejections() []RejectionRecord {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	result := make([]RejectionRecord, len(gr.rejections))
	copy(result, gr.rejections)
	return result
}

// ValidationCount returns the number of successful validations.
func (gr *GuardRecorder) ValidationCount() int {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	return len(gr.validations)
}

// RejectionCount returns the number of failed validations.
func (gr *GuardRecorder) RejectionCount() int {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	return len(gr.rejections)
}

// Reset clears all recorded validations and rejections.
func (gr *GuardRecorder) Reset() {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	gr.validations = gr.validations[:0]
	gr.rejections = gr.rejections[:0]
}
