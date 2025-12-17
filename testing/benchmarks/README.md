# sctx Benchmarks

Performance benchmarks for core sctx operations.

## Benchmark Categories

### Token Operations
- `BenchmarkGenerate` - Token generation from certificate (cold)
- `BenchmarkGenerate_Cached` - Token retrieval from cache (warm)
- `BenchmarkDecryptToken` - Token verification

### Guard Operations
- `BenchmarkCreateGuard` - Guard creation
- `BenchmarkGuardValidate` - Self-validation with permissions
- `BenchmarkGuardValidate_Delegation` - Multi-token validation

### Cache Operations
- `BenchmarkCacheGet` - Cache lookup
- `BenchmarkCacheStore` - Cache storage
- `BenchmarkCacheCleanup` - Expiry cleanup under load

### Crypto Operations
- `BenchmarkEd25519_Sign` - Ed25519 signing
- `BenchmarkEd25519_Verify` - Ed25519 verification
- `BenchmarkECDSA_Sign` - ECDSA P-256 signing
- `BenchmarkECDSA_Verify` - ECDSA P-256 verification

## Running Benchmarks

```bash
# All benchmarks
go test -bench=. ./testing/benchmarks/...

# With memory allocation stats
go test -bench=. -benchmem ./testing/benchmarks/...

# Specific benchmark
go test -bench=BenchmarkGenerate -benchmem ./testing/benchmarks/...

# Extended duration
go test -bench=. -benchtime=10s ./testing/benchmarks/...

# CPU profiling
go test -bench=BenchmarkGenerate -cpuprofile=cpu.prof ./testing/benchmarks/...
go tool pprof cpu.prof
```

## Expected Results

Typical results on modern hardware (Apple M1/Intel i7):

| Benchmark | Operations/sec | Allocs/op |
|-----------|---------------|-----------|
| Generate (cold) | ~5,000 | ~50 |
| Generate (cached) | ~500,000 | ~5 |
| DecryptToken | ~50,000 | ~10 |
| CreateGuard | ~10,000 | ~20 |
| GuardValidate | ~30,000 | ~15 |
| CacheGet | ~1,000,000 | ~2 |
| Ed25519 Sign | ~50,000 | ~3 |
| ECDSA Sign | ~20,000 | ~5 |

*Results vary based on hardware and system load.*
