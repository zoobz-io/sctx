package benchmarks

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/zoobzio/sctx"
	sctxtesting "github.com/zoobzio/sctx/testing"
)

// Token Operation Benchmarks

func BenchmarkGenerate(b *testing.B) {
	admin, testCerts, err := sctxtesting.TestAdmin[any]()
	if err != nil {
		b.Fatalf("TestAdmin failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Generate a new client cert for each iteration (cold path)
		clientCert, clientKey, err := sctxtesting.GenerateAdditionalClientCert(testCerts, "bench-client")
		if err != nil {
			b.Fatalf("GenerateAdditionalClientCert failed: %v", err)
		}

		assertion, err := sctx.CreateAssertion(clientKey, clientCert)
		if err != nil {
			b.Fatalf("CreateAssertion failed: %v", err)
		}

		_, err = admin.Generate(context.Background(), clientCert, assertion)
		if err != nil {
			b.Fatalf("Generate failed: %v", err)
		}
	}
}

func BenchmarkGenerate_Cached(b *testing.B) {
	admin, testCerts, err := sctxtesting.TestAdmin[any]()
	if err != nil {
		b.Fatalf("TestAdmin failed: %v", err)
	}

	// Generate initial token to populate cache
	assertion, err := sctx.CreateAssertion(testCerts.ClientKey, testCerts.ClientCert)
	if err != nil {
		b.Fatalf("CreateAssertion failed: %v", err)
	}

	_, err = admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		b.Fatalf("Initial Generate failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create new assertion each time (assertions have nonce)
		assertion, err := sctx.CreateAssertion(testCerts.ClientKey, testCerts.ClientCert)
		if err != nil {
			b.Fatalf("CreateAssertion failed: %v", err)
		}

		_, err = admin.Generate(context.Background(), testCerts.ClientCert, assertion)
		if err != nil {
			b.Fatalf("Generate failed: %v", err)
		}
	}
}

// Guard Operation Benchmarks

func BenchmarkCreateGuard(b *testing.B) {
	admin, testCerts, err := sctxtesting.TestAdmin[any]()
	if err != nil {
		b.Fatalf("TestAdmin failed: %v", err)
	}

	// Set policy with permissions
	_ = admin.SetPolicy(func(_ *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read", "write", "delete"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	assertion, err := sctx.CreateAssertion(testCerts.ClientKey, testCerts.ClientCert)
	if err != nil {
		b.Fatalf("CreateAssertion failed: %v", err)
	}

	token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		b.Fatalf("Generate failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := admin.CreateGuard(context.Background(), token, "read")
		if err != nil {
			b.Fatalf("CreateGuard failed: %v", err)
		}
	}
}

func BenchmarkGuardValidate(b *testing.B) {
	admin, testCerts, err := sctxtesting.TestAdmin[any]()
	if err != nil {
		b.Fatalf("TestAdmin failed: %v", err)
	}

	_ = admin.SetPolicy(func(_ *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	assertion, err := sctx.CreateAssertion(testCerts.ClientKey, testCerts.ClientCert)
	if err != nil {
		b.Fatalf("CreateAssertion failed: %v", err)
	}

	token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		b.Fatalf("Generate failed: %v", err)
	}

	guard, err := admin.CreateGuard(context.Background(), token, "read")
	if err != nil {
		b.Fatalf("CreateGuard failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := guard.Validate(context.Background(), token)
		if err != nil {
			b.Fatalf("Validate failed: %v", err)
		}
	}
}

func BenchmarkGuardValidate_MultiplePermissions(b *testing.B) {
	permCounts := []int{1, 5, 10}

	for _, count := range permCounts {
		perms := make([]string, count)
		for i := 0; i < count; i++ {
			perms[i] = string(rune('a' + i))
		}

		b.Run(string(rune('0'+count))+"_permissions", func(b *testing.B) {
			admin, testCerts, err := sctxtesting.TestAdmin[any]()
			if err != nil {
				b.Fatalf("TestAdmin failed: %v", err)
			}

			_ = admin.SetPolicy(func(_ *x509.Certificate) (*sctx.Context[any], error) {
				return &sctx.Context[any]{
					Permissions: perms,
					ExpiresAt:   time.Now().Add(time.Hour),
				}, nil
			})

			assertion, err := sctx.CreateAssertion(testCerts.ClientKey, testCerts.ClientCert)
			if err != nil {
				b.Fatalf("CreateAssertion failed: %v", err)
			}

			token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
			if err != nil {
				b.Fatalf("Generate failed: %v", err)
			}

			guard, err := admin.CreateGuard(context.Background(), token, perms...)
			if err != nil {
				b.Fatalf("CreateGuard failed: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := guard.Validate(context.Background(), token)
				if err != nil {
					b.Fatalf("Validate failed: %v", err)
				}
			}
		})
	}
}

// Cache Operation Benchmarks

func BenchmarkCacheGet(b *testing.B) {
	cache := sctx.NewMemoryContextCache[any](5 * time.Minute)
	ctx := context.Background()

	// Store a context
	sctxContext := &sctx.Context[any]{
		Permissions: []string{"read"},
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	cache.Store(ctx, "test-fingerprint", sctxContext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Get(ctx, "test-fingerprint")
	}
}

func BenchmarkCacheStore(b *testing.B) {
	cache := sctx.NewMemoryContextCache[any](5 * time.Minute)
	ctx := context.Background()

	sctxContext := &sctx.Context[any]{
		Permissions: []string{"read"},
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fingerprint := string(rune('a' + (i % 26)))
		cache.Store(ctx, fingerprint, sctxContext)
	}
}

func BenchmarkCacheGet_Concurrent(b *testing.B) {
	cache := sctx.NewMemoryContextCache[any](5 * time.Minute)
	ctx := context.Background()

	// Store a context
	sctxContext := &sctx.Context[any]{
		Permissions: []string{"read"},
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	cache.Store(ctx, "test-fingerprint", sctxContext)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = cache.Get(ctx, "test-fingerprint")
		}
	})
}

// Crypto Operation Benchmarks

func BenchmarkEd25519_Sign(b *testing.B) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey failed: %v", err)
	}

	data := []byte("test data to sign")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(privateKey, data)
	}
}

func BenchmarkEd25519_Verify(b *testing.B) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey failed: %v", err)
	}

	data := []byte("test data to sign")
	signature := ed25519.Sign(privateKey, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Verify(publicKey, data, signature)
	}
}

func BenchmarkECDSA_Sign(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey failed: %v", err)
	}

	data := []byte("test data to sign")
	hash := crypto.SHA256.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ecdsa.SignASN1(rand.Reader, privateKey, digest)
	}
}

func BenchmarkECDSA_Verify(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey failed: %v", err)
	}

	data := []byte("test data to sign")
	hash := crypto.SHA256.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
	if err != nil {
		b.Fatalf("SignASN1 failed: %v", err)
	}

	publicKey := &privateKey.PublicKey

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ecdsa.VerifyASN1(publicKey, digest, signature)
	}
}

// Assertion Benchmarks

func BenchmarkCreateAssertion(b *testing.B) {
	testCerts, err := sctxtesting.GenerateTestCertificates()
	if err != nil {
		b.Fatalf("GenerateTestCertificates failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sctx.CreateAssertion(testCerts.ClientKey, testCerts.ClientCert)
		if err != nil {
			b.Fatalf("CreateAssertion failed: %v", err)
		}
	}
}

// Parallel Benchmarks

func BenchmarkGenerate_Parallel(b *testing.B) {
	admin, testCerts, err := sctxtesting.TestAdmin[any]()
	if err != nil {
		b.Fatalf("TestAdmin failed: %v", err)
	}

	// Pre-generate many client certs
	const numClients = 100
	clients := make([]struct {
		cert *x509.Certificate
		key  crypto.PrivateKey
	}, numClients)

	for i := 0; i < numClients; i++ {
		cert, key, err := sctxtesting.GenerateAdditionalClientCert(testCerts, "parallel-client")
		if err != nil {
			b.Fatalf("GenerateAdditionalClientCert failed: %v", err)
		}
		clients[i].cert = cert
		clients[i].key = key
	}

	var counter int64
	var mu sync.Mutex

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mu.Lock()
			idx := counter % numClients
			counter++
			mu.Unlock()

			assertion, err := sctx.CreateAssertion(clients[idx].key, clients[idx].cert)
			if err != nil {
				b.Fatalf("CreateAssertion failed: %v", err)
			}

			_, err = admin.Generate(context.Background(), clients[idx].cert, assertion)
			if err != nil {
				b.Fatalf("Generate failed: %v", err)
			}
		}
	})
}

func BenchmarkGuardValidate_Parallel(b *testing.B) {
	admin, testCerts, err := sctxtesting.TestAdmin[any]()
	if err != nil {
		b.Fatalf("TestAdmin failed: %v", err)
	}

	_ = admin.SetPolicy(func(_ *x509.Certificate) (*sctx.Context[any], error) {
		return &sctx.Context[any]{
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})

	assertion, err := sctx.CreateAssertion(testCerts.ClientKey, testCerts.ClientCert)
	if err != nil {
		b.Fatalf("CreateAssertion failed: %v", err)
	}

	token, err := admin.Generate(context.Background(), testCerts.ClientCert, assertion)
	if err != nil {
		b.Fatalf("Generate failed: %v", err)
	}

	guard, err := admin.CreateGuard(context.Background(), token, "read")
	if err != nil {
		b.Fatalf("CreateGuard failed: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := guard.Validate(context.Background(), token)
			if err != nil {
				b.Fatalf("Validate failed: %v", err)
			}
		}
	})
}
