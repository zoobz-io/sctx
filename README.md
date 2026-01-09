# sctx

[![CI Status](https://github.com/zoobzio/sctx/workflows/CI/badge.svg)](https://github.com/zoobzio/sctx/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/zoobzio/sctx/graph/badge.svg?branch=main)](https://codecov.io/gh/zoobzio/sctx)
[![Go Report Card](https://goreportcard.com/badge/github.com/zoobzio/sctx)](https://goreportcard.com/report/github.com/zoobzio/sctx)
[![CodeQL](https://github.com/zoobzio/sctx/workflows/CodeQL/badge.svg)](https://github.com/zoobzio/sctx/security/code-scanning)
[![Go Reference](https://pkg.go.dev/badge/github.com/zoobzio/sctx.svg)](https://pkg.go.dev/github.com/zoobzio/sctx)
[![License](https://img.shields.io/github/license/zoobzio/sctx)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/zoobzio/sctx)](go.mod)
[![Release](https://img.shields.io/github/v/release/zoobzio/sctx)](https://github.com/zoobzio/sctx/releases)

Certificate-based security contexts for Go.

Turn mTLS certificates into typed authorization tokens with permissions, metadata, and delegatable guards.

## Certificates Become Capabilities

Your PKI already establishes identity. sctx turns that identity into authorization.

```go
// Define how certificates map to permissions
admin.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[UserMeta], error) {
    return &sctx.Context[UserMeta]{
        Permissions: permissionsFromOU(cert.Subject.OrganizationalUnit),
        Metadata:    UserMeta{TenantID: cert.Subject.Organization[0]},
        ExpiresAt:   time.Now().Add(time.Hour),
    }, nil
})

// Client proves key possession, gets a signed token
assertion, _ := sctx.CreateAssertion(clientKey, clientCert)
token, _ := admin.Generate(ctx, clientCert, assertion)

// Token holder creates guards for specific permissions
guard, _ := admin.CreateGuard(ctx, token, "api:read", "api:write")

// Guards validate other tokens
err := guard.Validate(ctx, incomingToken)
```

No JWT parsing. No external identity provider. Your certificates are your identity system.

## Install

```bash
go get github.com/zoobzio/sctx
```

Requires Go 1.24+.

## Quick Start

```go
package main

import (
    "context"
    "crypto/ed25519"
    "crypto/x509"
    "fmt"
    "time"

    "github.com/zoobzio/sctx"
)

type UserMeta struct {
    Role     string
    TenantID string
}

func main() {
    ctx := context.Background()

    // Create the admin service with your signing key and trusted CAs
    admin, _ := sctx.NewAdminService[UserMeta](privateKey, trustedCAPool)

    // Define authorization policy: certificate -> context
    admin.SetPolicy(func(cert *x509.Certificate) (*sctx.Context[UserMeta], error) {
        return &sctx.Context[UserMeta]{
            Permissions: []string{"read", "write"},
            Metadata:    UserMeta{Role: "admin", TenantID: cert.Subject.Organization[0]},
            ExpiresAt:   time.Now().Add(time.Hour),
        }, nil
    })

    // Client creates assertion proving key possession
    assertion, _ := sctx.CreateAssertion(clientKey, clientCert)

    // Admin generates signed token
    token, _ := admin.Generate(ctx, clientCert, assertion)

    // Create a guard for specific permissions
    guard, _ := admin.CreateGuard(ctx, token, "read")

    // Validate tokens against the guard
    if err := guard.Validate(ctx, token); err != nil {
        fmt.Println("Access denied:", err)
        return
    }

    fmt.Println("Access granted")
}
```

## Capabilities

| Feature                     | Description                                               | Docs                                          |
| --------------------------- | --------------------------------------------------------- | --------------------------------------------- |
| Policy-Driven Authorization | Transform certificates into contexts with custom policies | [Policy](docs/3.guides/1.policy.md)           |
| Permission Guards           | Create guards that check for required permissions         | [Guards](docs/3.guides/2.guards.md)           |
| Type-Safe Metadata          | Generic contexts with compile-time type checking          | [Concepts](docs/2.learn/2.concepts.md)        |
| Instant Revocation          | Revoke contexts by certificate fingerprint                | [Revocation](docs/4.cookbook/3.revocation.md) |
| Observability               | Capitan events for all operations                         | [Events](docs/3.guides/3.events.md)           |
| Testing Utilities           | Deterministic testing with mock certificates              | [Testing](docs/3.guides/4.testing.md)         |

## Why sctx?

- **Certificate-native** — Built on mTLS, no separate identity layer
- **Type-safe** — Generic metadata with compile-time checking
- **Delegatable** — Token holders create guards for others to use
- **Zero shared secrets** — Only public keys needed for validation
- **Instantly revocable** — Revoke by fingerprint, all guards reject immediately
- **Observable** — Every operation emits [capitan](https://github.com/zoobzio/capitan) events

## PKI-Native Authorization

sctx enables a pattern: **certificates establish identity, policies define permissions, guards enforce access**.

Your mTLS infrastructure already verifies who clients are. sctx adds what they can do.

```go
// In your mTLS handler — certificate is already verified
func handler(w http.ResponseWriter, r *http.Request) {
    cert := r.TLS.PeerCertificates[0]

    // Turn certificate into authorization token
    assertion, _ := sctx.CreateAssertion(clientKey, cert)
    token, _ := admin.Generate(r.Context(), cert, assertion)

    // Check permissions with a guard
    if err := readGuard.Validate(r.Context(), token); err != nil {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // Authorized — proceed
}
```

One certificate, one policy, full authorization. No JWT middleware. No token introspection endpoints.

## Documentation

- [Overview](docs/1.overview.md) — Design philosophy and architecture

### Learn

- [Quickstart](docs/2.learn/1.quickstart.md) — Get started in minutes
- [Concepts](docs/2.learn/2.concepts.md) — Contexts, tokens, guards, assertions
- [Architecture](docs/2.learn/3.architecture.md) — Internal design and components

### Guides

- [Policy](docs/3.guides/1.policy.md) — Certificate-to-context transformation
- [Guards](docs/3.guides/2.guards.md) — Permission checking and delegation
- [Events](docs/3.guides/3.events.md) — Observability with capitan
- [Testing](docs/3.guides/4.testing.md) — Testing with mock certificates

### Cookbook

- [mTLS Integration](docs/4.cookbook/1.mtls.md) — HTTP handlers with certificate auth
- [RBAC Patterns](docs/4.cookbook/2.rbac.md) — Role-based access control
- [Revocation](docs/4.cookbook/3.revocation.md) — Instant token invalidation

### Reference

- [API](docs/5.reference/1.api.md) — Complete function documentation
- [Events](docs/5.reference/2.events.md) — Capitan signal reference

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Run `make help` for available commands.

## License

MIT License — see [LICENSE](LICENSE) for details.
