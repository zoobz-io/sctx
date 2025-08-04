# SCTX - Simplified Security Context Service

A zero-trust microservices authentication framework that provides cryptographically signed security tokens based on mTLS certificate authentication.

## Key Concepts

- **Tokens**: Generated from mTLS certificates, contain permissions derived from cert properties
- **Guards**: Created by token holders to validate other tokens based on required permissions
- **Context Pipeline**: Single pipeline that enriches all certificates with permissions/metadata

## New Simplified API

### 1. Generate Tokens (Certificate → Token)

```go
// Setup admin service
admin, _ := sctx.NewAdminService[any](privateKey, caPool)

// Configure how certificates become security contexts
admin.ConfigureContextPipeline(
    // Extract permissions from Organization field
    sctx.GrantPermissions[any]("deploy", "debug"), // if O=Engineering
    
    // Set standard expiry
    sctx.SetContext[any](sctx.ContextOptions{
        Expiry: &[]time.Duration{5 * time.Minute}[0],
    }),
)

sctx.SetAdmin(admin)

// Generate token - no key needed, cert determines everything!
token, _ := sctx.Generate(clientCert)
```

### 2. Create Guards (Token → Guard)

```go
// Token holder creates a guard for "data:read" access
guard, err := sctx.CreateGuard(myToken, "data:read")
if err != nil {
    // Token doesn't have "data:read" permission
}

// Guard is now a capability object others can use
```

### 3. Validate Tokens (Guard → Validation)

```go
// Use the guard to validate another token
err := guard.Validate(incomingToken)
if err != nil {
    // Token lacks required permissions
}
```

## Flow Example

```
1. Service A has cert with O=Engineering
2. Generate(cert) → token with "deploy" permission
3. Service A creates guard: CreateGuard(token, "deploy") 
4. Service A gives guard to Service B
5. Service B validates requests: guard.Validate(userToken)
```

## Key Benefits

- **Certificate-driven**: Permissions come from cert properties, not external config
- **Delegatable security**: Token holders create guards for others to use
- **Zero shared secrets**: Only public keys needed for validation
- **Revocable**: Guards become invalid when parent tokens expire/revoke
- **Auditable**: All guard creation tracked by admin service
- **Extensible**: Register custom processors to add validation logic

See [examples/custom_processors.md](examples/custom_processors.md) for extending with custom processors.