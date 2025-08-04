package sctx

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestPublicKeysEqualEdgeCases(t *testing.T) {
	// Test different RSA key sizes
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	key3, _ := rsa.GenerateKey(rand.Reader, 4096)

	// Same key should be equal
	if !publicKeysEqual(&key1.PublicKey, &key1.PublicKey) {
		t.Error("Same RSA key should be equal to itself")
	}

	// Different keys should not be equal
	if publicKeysEqual(&key1.PublicKey, &key2.PublicKey) {
		t.Error("Different RSA keys should not be equal")
	}

	// Different key sizes should not be equal
	if publicKeysEqual(&key1.PublicKey, &key3.PublicKey) {
		t.Error("RSA keys with different sizes should not be equal")
	}

	// Test nil cases - publicKeysEqual treats nil as unsupported type, so returns false
	if publicKeysEqual(nil, &key1.PublicKey) {
		t.Error("nil key should not equal non-nil key")
	}

	if publicKeysEqual(&key1.PublicKey, nil) {
		t.Error("non-nil key should not equal nil key")
	}

	if publicKeysEqual(nil, nil) {
		t.Error("nil keys should not be equal (unsupported type)")
	}
}
