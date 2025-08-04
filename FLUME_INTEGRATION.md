# Flume Integration - Schema-Based Pipeline Configuration

sctx now supports schema-based pipeline configuration via [flume](../flume), enabling hot-reload, graceful degradation, and declarative pipeline definitions.

## Basic Usage

```go
// Create admin service
admin, _ := sctx.NewAdminService[any](privateKey, caPool)

// Configure pipeline via YAML schema
admin.LoadSchema(`
type: sequence
children:
  - ref: set-expiry-1h
  - ref: grant-read
  - ref: grant-write
  - ref: grant-create-guard
`)

// Generate tokens - pipeline runs automatically
token, _ := admin.Generate(clientCert)
```

## Available Processors

### Context Manipulation
- `set-expiry-1h` - Set 1 hour expiry
- `set-expiry-5m` - Set 5 minute expiry  
- `set-expiry-24h` - Set 24 hour expiry

### Permission Grants
- `grant-read` - Grant read permission
- `grant-write` - Grant write permission
- `grant-admin` - Grant admin permission
- `grant-create-guard` - Grant create-guard permission

### Certificate Validation
- `require-engineering` - Require O=Engineering
- `require-production` - Require CN contains "prod"
- `require-staging` - Require CN contains "staging"

## Advanced Patterns

### Graceful Degradation
```yaml
type: fallback
children:
  - type: sequence
    children:
      - ref: require-engineering
      - ref: set-expiry-1h
      - ref: grant-admin
  - type: sequence  
    children:
      - ref: set-expiry-5m
      - ref: grant-read
```

### Hot Reload
```go
// Update pipeline at runtime - no restart needed
admin.LoadSchema(newSchemaYAML)
```

### Custom Processors
```go
// Register custom logic
admin.RegisterProcessor("custom-validator", myCustomGuard)

// Use in schema
admin.LoadSchema(`
type: sequence
children:
  - ref: custom-validator
  - ref: grant-read
`)
```

## Benefits

- **Hot Reload**: Update pipelines without restarts
- **Graceful Degradation**: Fallback patterns for reliability
- **Declarative**: YAML-based configuration
- **Composable**: Mix and match processors
- **Type Safe**: Processor names as constants
- **Introspectable**: Runtime pipeline analysis