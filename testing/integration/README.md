# sctx Integration Tests

Integration tests using step-ca testcontainers for real-world PKI scenarios.

## Prerequisites

- Docker installed and running
- Go 1.21+ with testcontainers-go

## Test Suites

### mTLS Handshake Flow (`mtls_test.go`)
Tests the complete mTLS authentication flow:
- Basic handshake with valid certificate
- Rejection of untrusted CA certificates
- Rejection of expired certificates
- Proper event emission during handshake

### Certificate Rotation (`rotation_test.go`)
Tests certificate lifecycle management:
- New certificate with same identity
- Old token validity during rotation window
- Context cleanup after rotation
- Smooth handoff between certificates

### Revocation Handling (`revocation_test.go`)
Tests certificate and context revocation:
- Immediate invalidation on revocation
- Guard behavior after revocation
- Event emission on revocation
- Cache cleanup verification

### Multi-CA Trust Chains (`multichain_test.go`)
Tests complex PKI configurations:
- Intermediate CA verification
- Cross-signed certificate chains
- Partial chain trust scenarios
- Multi-root trust stores

## Running Tests

```bash
# All integration tests
go test -tags=integration -v ./testing/integration/...

# Specific suite
go test -tags=integration -v -run TestIntegration_mTLS ./testing/integration/...

# With timeout (containers can be slow to start)
go test -tags=integration -v -timeout 5m ./testing/integration/...

# Keep containers running for debugging
TESTCONTAINERS_RYUK_DISABLED=true go test -tags=integration -v ./testing/integration/...
```

## step-ca Container

Tests use the `smallstep/step-ca:latest` Docker image. The container is configured with:

- ECDSA P-256 root CA
- Short-lived certificates for testing
- JWK provisioner for programmatic issuance

## Troubleshooting

### Container fails to start
Ensure Docker daemon is running:
```bash
docker info
```

### Tests timeout
Increase test timeout:
```bash
go test -tags=integration -timeout 10m ./testing/integration/...
```

### Permission errors
Ensure your user can run Docker commands:
```bash
docker run hello-world
```
