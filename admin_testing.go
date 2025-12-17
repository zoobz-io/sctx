//go:build testing

package sctx

import "sync"

// ResetAdminForTesting resets the admin singleton state for testing purposes.
// This function is only available when building with -tags=testing.
//
// Usage:
//
//	go test -tags=testing ./...
//
// This build tag restriction prevents the function from being available in
// production builds, eliminating the security risk of singleton reset.
func ResetAdminForTesting() {
	adminOnce = sync.Once{}
	adminCreated = false
}

// resetAdminForTesting is an unexported alias for internal test usage.
func resetAdminForTesting() {
	ResetAdminForTesting()
}
