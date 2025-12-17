# sctx Testing Infrastructure

This directory contains testing utilities, benchmarks, and integration tests for the sctx package.

## Build Tag Requirement

All testing utilities require the `testing` build tag:

```bash
go test -tags=testing ./...
```

This is a security measure. The `ResetAdminForTesting()` function, which resets the admin singleton, is only available with this build tag. Without it, malicious code could reset the singleton in production.

## Directory Structure

```
testing/
├── helpers.go              # Public test utilities for sctx-based applications
├── helpers_test.go         # Tests for helpers
├── benchmarks/             # Performance benchmarks
│   └── core_performance_test.go
└── integration/            # Integration tests with real PKI
    ├── ca/                 # step-ca testcontainer setup
    │   ├── stepca.go
    │   └── certs.go
    ├── mtls_test.go        # mTLS handshake flow tests
    ├── rotation_test.go    # Certificate rotation tests
    ├── revocation_test.go  # Revocation handling tests
    └── multichain_test.go  # Multi-CA trust chain tests
```

## Test Helpers

The `helpers.go` file provides utilities for testing applications built with sctx:

```go
import "github.com/zoobzio/sctx/testing"

// Create a test admin with generated certificates
admin, certPool, privateKey := testing.TestAdmin[MyMetadata]()

// Build custom certificates
cert, key := testing.NewCertBuilder().
    WithCN("test-client").
    WithValidity(time.Hour).
    SignedBy(caCert, caKey)

// Capture token generation events
capture := testing.NewTokenCapture()
defer capture.Close()
// ... generate tokens ...
tokens := capture.Tokens()

// Record guard operations
recorder := testing.NewGuardRecorder()
defer recorder.Close()
// ... validate guards ...
validations := recorder.Validations()
```

## Running Benchmarks

```bash
# Run all benchmarks
go test -tags=testing -bench=. ./testing/benchmarks/...

# Run specific benchmark with memory stats
go test -tags=testing -bench=BenchmarkGenerate -benchmem ./testing/benchmarks/...

# Run with custom iteration count
go test -tags=testing -bench=. -benchtime=5s ./testing/benchmarks/...
```

## Running Integration Tests

Integration tests require Docker and use testcontainers with step-ca.

```bash
# Run all integration tests
go test -tags=integration,testing -v ./testing/integration/...

# Run specific test suite
go test -tags=integration,testing -v -run TestIntegration_mTLS ./testing/integration/...

# Run with verbose container logs
TESTCONTAINERS_RYUK_DISABLED=true go test -tags=integration,testing -v ./testing/integration/...
```

## CI Integration

Integration tests are designed to run in CI environments with Docker support:

```yaml
integration-tests:
  runs-on: ubuntu-latest
  services:
    docker:
      image: docker:dind
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-go@v5
      with:
        go-version: '1.23'
    - name: Run integration tests
      run: go test -tags=integration,testing -v ./testing/integration/...
```
