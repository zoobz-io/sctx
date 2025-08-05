package sctx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zoobzio/zlog"
)

func TestTypedHooks(t *testing.T) {
	resetAdminForTesting()
	// Generate test certificates
	testCerts := GenerateTestCertificates(t)

	// Create admin service
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	admin, err := NewAdminService[any](privateKey, testCerts.CertPool)
	if err != nil {
		t.Fatalf("Failed to create admin service: %v", err)
	}

	// Configure context pipeline
	err = admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
  - ref: grant-write
  - ref: grant-create-guard
`)
	if err != nil {
		t.Fatalf("Failed to load context schema: %v", err)
	}

	t.Run("context event hooks", func(t *testing.T) {
		var capturedEvents []zlog.Event[ContextEvent[any]]

		// Cast to access hook methods
		adminSvc := admin.(*adminService[any])

		// Register hook for token generation
		adminSvc.OnContext(TOKEN_GENERATED,
			func(ctx context.Context, event zlog.Event[ContextEvent[any]]) (zlog.Event[ContextEvent[any]], error) {
				capturedEvents = append(capturedEvents, event)
				return event, nil
			})

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token
		token, err := admin.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Verify hook was called
		if len(capturedEvents) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(capturedEvents))
		}

		event := capturedEvents[0]
		if event.Signal != TOKEN_GENERATED {
			t.Errorf("Expected signal %v, got %v", TOKEN_GENERATED, event.Signal)
		}
		if event.Data.Token != string(token) {
			t.Errorf("Expected token %s, got %s", token, event.Data.Token)
		}
		if event.Data.Context == nil {
			t.Error("Expected context to be non-nil")
		}
		if event.Data.Operation != "generated" {
			t.Errorf("Expected operation 'generated', got %s", event.Data.Operation)
		}
	})

	t.Run("certificate event hooks", func(t *testing.T) {
		var capturedEvents []zlog.Event[CertificateEvent]

		// Cast to access hook methods
		adminSvc := admin.(*adminService[any])

		// Register hook for certificate rejection
		adminSvc.OnCertificate(CERTIFICATE_REJECTED,
			func(ctx context.Context, event zlog.Event[CertificateEvent]) (zlog.Event[CertificateEvent], error) {
				capturedEvents = append(capturedEvents, event)
				return event, nil
			})

		// Try to generate with untrusted certificate
		untrustedCerts := GenerateTestCertificates(t)
		untrustedAssertion := createTestAssertion(t, untrustedCerts.ClientKey, untrustedCerts.ClientCert)
		_, err := admin.Generate(untrustedCerts.ClientCert, untrustedAssertion)
		if err == nil {
			t.Fatal("Expected error with untrusted certificate")
		}

		// Verify hook was called
		if len(capturedEvents) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(capturedEvents))
		}

		event := capturedEvents[0]
		if event.Signal != CERTIFICATE_REJECTED {
			t.Errorf("Expected signal %v, got %v", CERTIFICATE_REJECTED, event.Signal)
		}
		if event.Data.CertificateInfo.CommonName == "" {
			t.Error("Expected certificate info to be populated")
		}
		if event.Data.Reason == "" {
			t.Error("Expected reason to be populated")
		}
	})

	t.Run("guard creation event", func(t *testing.T) {
		var capturedContextEvents []zlog.Event[ContextEvent[any]]

		// Cast to access hook methods
		adminSvc := admin.(*adminService[any])

		// Register hook for context events (guard creation emits context event)
		adminSvc.OnContext(GUARD_CREATED,
			func(ctx context.Context, event zlog.Event[ContextEvent[any]]) (zlog.Event[ContextEvent[any]], error) {
				capturedContextEvents = append(capturedContextEvents, event)
				return event, nil
			})

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token and create guard
		token, err := admin.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		guard, err := admin.CreateGuard(token, "read", "write")
		if err != nil {
			t.Fatalf("Failed to create guard: %v", err)
		}

		// Verify hook was called
		if len(capturedContextEvents) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(capturedContextEvents))
		}

		event := capturedContextEvents[0]
		if event.Signal != GUARD_CREATED {
			t.Errorf("Expected signal %v, got %v", GUARD_CREATED, event.Signal)
		}
		if guard.ID() == "" {
			t.Error("Guard ID should not be empty")
		}
		if event.Data.Context == nil {
			t.Error("Expected context to be non-nil")
		}
		if event.Data.Operation != "guard_created" {
			t.Errorf("Expected operation 'guard_created', got %s", event.Data.Operation)
		}
	})

	t.Run("multiple hooks on same signal", func(t *testing.T) {
		resetAdminForTesting()
		// Create a fresh admin service for this test
		_, privateKey2, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		admin2, err := NewAdminService[any](privateKey2, testCerts.CertPool)
		if err != nil {
			t.Fatalf("Failed to create admin service: %v", err)
		}

		// Configure context pipeline
		err = admin2.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
  - ref: grant-write
  - ref: grant-create-guard
`)
		if err != nil {
			t.Fatalf("Failed to load context schema: %v", err)
		}

		var hooksCalled atomic.Int32
		done := make(chan struct{}, 2)

		// Cast to access hook methods
		adminSvc2 := admin2.(*adminService[any])

		// Register multiple hooks
		adminSvc2.OnContext(TOKEN_GENERATED,
			func(ctx context.Context, event zlog.Event[ContextEvent[any]]) (zlog.Event[ContextEvent[any]], error) {
				hooksCalled.Add(1)
				done <- struct{}{}
				return event, nil
			},
			func(ctx context.Context, event zlog.Event[ContextEvent[any]]) (zlog.Event[ContextEvent[any]], error) {
				hooksCalled.Add(1)
				done <- struct{}{}
				return event, nil
			},
		)

		// Create assertion
		assertion := createTestAssertion(t, testCerts.ClientKey, testCerts.ClientCert)

		// Generate token
		_, err = admin2.Generate(testCerts.ClientCert, assertion)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Wait for both hooks to complete (with timeout)
		for i := 0; i < 2; i++ {
			select {
			case <-done:
				// Hook completed
			case <-time.After(time.Second):
				t.Fatalf("Timeout waiting for hook %d", i+1)
			}
		}

		// Both hooks should have been called
		if got := hooksCalled.Load(); got != 2 {
			t.Errorf("Expected 2 hooks to be called, got %d", got)
		}
	})
}
