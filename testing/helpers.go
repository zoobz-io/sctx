//go:build testing

// Package testing provides test utilities and helpers for sctx users.
// These utilities help users test their own sctx-based applications.
//
// This package requires the testing build tag:
//
//	go test -tags=testing ./...
//
// The package is organized into the following modules:
//
//   - events.go: Event capture utilities (TokenCapture, GuardRecorder)
//   - certs.go: Certificate generation (CertBuilder, TestCertificates)
//   - admin.go: Admin service factory (TestAdmin)
//   - assertions.go: Assertion utilities (CreateAssertion)
package testing
