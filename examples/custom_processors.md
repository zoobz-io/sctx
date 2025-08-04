# Custom Processors

SCTX allows you to register custom processors to extend the context pipeline.

## Registering Custom Processors

Since the Admin interface is non-generic, you need to cast to the concrete type to access `RegisterProcessor`:

```go
// Create admin service with your metadata type
admin, err := sctx.NewAdminService[MyMetadata](privateKey, caPool)

// Cast to access RegisterProcessor
adminSvc := admin.(*adminService[MyMetadata])

// Create a custom processor
myProcessor := pipz.Apply[*Context[MyMetadata]](
    pipz.Name("my-processor"),
    func(ctx context.Context, c *Context[MyMetadata]) (*Context[MyMetadata], error) {
        // Your custom logic here
        return c, nil
    },
)

// Register it
adminSvc.RegisterProcessor("my-processor", myProcessor)

// Use in schema
admin.LoadContextSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
  - ref: my-processor
`)
```

## Example: Rate Limiting Processor

```go
// This would need an external rate limiter service
rateLimiter := NewRateLimiter()

rateLimitProcessor := pipz.Apply[*Context[MyMetadata]](
    pipz.Name("rate-limit"),
    func(ctx context.Context, c *Context[MyMetadata]) (*Context[MyMetadata], error) {
        allowed, err := rateLimiter.CheckLimit(c.CertificateFingerprint)
        if err != nil {
            return nil, fmt.Errorf("rate limit check failed: %w", err)
        }
        if !allowed {
            return nil, errors.New("rate limit exceeded")
        }
        return c, nil
    },
)

adminSvc.RegisterProcessor("rate-limit", rateLimitProcessor)
```

## Using Guards

Guards created after loading a schema will use the configured pipeline:

```go
// Load schema with custom processor
admin.LoadContextSchema(schemaWithCustomProcessor)

// Guards created now enforce the full pipeline
guard := admin.CreateGuard(token, "read")

// When validating, the pipeline (including custom processors) runs first
err := guard.Validate(userToken)
```