package sctx

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestECDSAP256Signer(t *testing.T) {
	// Generate ECDSA P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	signer := &ecdsaP256Signer{privateKey: privateKey}

	t.Run("Algorithm", func(t *testing.T) {
		if signer.Algorithm() != CryptoECDSAP256 {
			t.Errorf("Expected algorithm %v, got %v", CryptoECDSAP256, signer.Algorithm())
		}
	})

	t.Run("PublicKey", func(t *testing.T) {
		pubKey := signer.PublicKey()
		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("Expected *ecdsa.PublicKey, got %T", pubKey)
		}
		if !ecdsaPubKey.Equal(&privateKey.PublicKey) {
			t.Error("Public key mismatch")
		}
	})

	t.Run("KeyType", func(t *testing.T) {
		expected := "ECDSA P-256"
		if signer.KeyType() != expected {
			t.Errorf("Expected key type %q, got %q", expected, signer.KeyType())
		}
	})

	t.Run("Sign and Verify", func(t *testing.T) {
		data := []byte("test data to sign")

		// Sign the data
		signature, err := signer.Sign(data)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		if len(signature) == 0 {
			t.Error("Signature is empty")
		}

		// Verify with correct public key
		if !signer.Verify(data, signature, &privateKey.PublicKey) {
			t.Error("Failed to verify valid signature")
		}

		// Verify with wrong data should fail
		wrongData := []byte("wrong data")
		if signer.Verify(wrongData, signature, &privateKey.PublicKey) {
			t.Error("Verified signature with wrong data")
		}

		// Verify with wrong public key should fail
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if signer.Verify(data, signature, &otherKey.PublicKey) {
			t.Error("Verified signature with wrong public key")
		}

		// Verify with corrupted signature should fail
		corruptedSig := make([]byte, len(signature))
		copy(corruptedSig, signature)
		corruptedSig[0] ^= 0xFF
		if signer.Verify(data, corruptedSig, &privateKey.PublicKey) {
			t.Error("Verified corrupted signature")
		}
	})

	t.Run("Verify with invalid key type", func(t *testing.T) {
		data := []byte("test data")
		signature, _ := signer.Sign(data)

		// Try with Ed25519 key
		edPub, _, _ := ed25519.GenerateKey(rand.Reader)
		if signer.Verify(data, signature, edPub) {
			t.Error("Verified ECDSA signature with Ed25519 key")
		}

		// Try with RSA key
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		if signer.Verify(data, signature, &rsaKey.PublicKey) {
			t.Error("Verified ECDSA signature with RSA key")
		}

		// Try with nil
		if signer.Verify(data, signature, nil) {
			t.Error("Verified signature with nil key")
		}
	})

	t.Run("Verify with malformed signature", func(t *testing.T) {
		data := []byte("test data")

		// Empty signature
		if signer.Verify(data, []byte{}, &privateKey.PublicKey) {
			t.Error("Verified empty signature")
		}

		// Signature too short
		if signer.Verify(data, []byte{1, 2, 3}, &privateKey.PublicKey) {
			t.Error("Verified short signature")
		}

		// Invalid DER encoding
		invalidDER := []byte{0x30, 0xFF, 0xFF, 0xFF}
		if signer.Verify(data, invalidDER, &privateKey.PublicKey) {
			t.Error("Verified invalid DER signature")
		}
	})
}

func TestGenerateKeyPair(t *testing.T) {
	t.Run("Ed25519", func(t *testing.T) {
		pubKey, privKey, err := GenerateKeyPair(CryptoEd25519)
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		// Check types
		edPriv, ok := privKey.(ed25519.PrivateKey)
		if !ok {
			t.Fatalf("Expected ed25519.PrivateKey, got %T", privKey)
		}

		edPub, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			t.Fatalf("Expected ed25519.PublicKey, got %T", pubKey)
		}

		// Verify key relationship
		expectedPub := edPriv.Public().(ed25519.PublicKey)
		if string(edPub) != string(expectedPub) {
			t.Error("Public key doesn't match private key")
		}
	})

	t.Run("ECDSA P-256", func(t *testing.T) {
		pubKey, privKey, err := GenerateKeyPair(CryptoECDSAP256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		// Check types
		ecPriv, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("Expected *ecdsa.PrivateKey, got %T", privKey)
		}

		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("Expected *ecdsa.PublicKey, got %T", pubKey)
		}

		// Verify key relationship
		if !ecPub.Equal(&ecPriv.PublicKey) {
			t.Error("Public key doesn't match private key")
		}

		// Verify curve
		if ecPriv.Curve != elliptic.P256() {
			t.Error("Expected P-256 curve")
		}
	})

	t.Run("Invalid algorithm", func(t *testing.T) {
		_, _, err := GenerateKeyPair(CryptoAlgorithm("invalid"))
		if err == nil {
			t.Error("Expected error for invalid algorithm")
		}
	})
}

func TestDetectAlgorithmFromPublicKey(t *testing.T) {
	t.Run("Ed25519", func(t *testing.T) {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		algo, err := DetectAlgorithmFromPublicKey(pub)
		if err != nil {
			t.Fatalf("Failed to detect Ed25519: %v", err)
		}
		if algo != CryptoEd25519 {
			t.Errorf("Expected %v, got %v", CryptoEd25519, algo)
		}
	})

	t.Run("ECDSA P-256", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		algo, err := DetectAlgorithmFromPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("Failed to detect ECDSA: %v", err)
		}
		if algo != CryptoECDSAP256 {
			t.Errorf("Expected %v, got %v", CryptoECDSAP256, algo)
		}
	})

	t.Run("Unsupported ECDSA curve", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		_, err := DetectAlgorithmFromPublicKey(&key.PublicKey)
		if err == nil {
			t.Error("Expected error for P384 curve")
		}
	})

	t.Run("RSA", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		_, err := DetectAlgorithmFromPublicKey(&key.PublicKey)
		if err == nil {
			t.Error("Expected error for RSA key")
		}
	})

	t.Run("nil key", func(t *testing.T) {
		_, err := DetectAlgorithmFromPublicKey(nil)
		if err == nil {
			t.Error("Expected error for nil key")
		}
	})
}

func TestDetectAlgorithmFromPrivateKey(t *testing.T) {
	t.Run("Ed25519", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		algo, err := DetectAlgorithmFromPrivateKey(priv)
		if err != nil {
			t.Fatalf("Failed to detect Ed25519: %v", err)
		}
		if algo != CryptoEd25519 {
			t.Errorf("Expected %v, got %v", CryptoEd25519, algo)
		}
	})

	t.Run("ECDSA P-256", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		algo, err := DetectAlgorithmFromPrivateKey(key)
		if err != nil {
			t.Fatalf("Failed to detect ECDSA: %v", err)
		}
		if algo != CryptoECDSAP256 {
			t.Errorf("Expected %v, got %v", CryptoECDSAP256, algo)
		}
	})

	t.Run("Unsupported ECDSA curve", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		_, err := DetectAlgorithmFromPrivateKey(key)
		if err == nil {
			t.Error("Expected error for P521 curve")
		}
	})

	t.Run("RSA", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		_, err := DetectAlgorithmFromPrivateKey(key)
		if err == nil {
			t.Error("Expected error for RSA key")
		}
	})

	t.Run("nil key", func(t *testing.T) {
		_, err := DetectAlgorithmFromPrivateKey(nil)
		if err == nil {
			t.Error("Expected error for nil key")
		}
	})
}

func TestValidateAlgorithm(t *testing.T) {
	t.Run("Valid algorithms", func(t *testing.T) {
		if err := ValidateAlgorithm(CryptoEd25519); err != nil {
			t.Errorf("Ed25519 should be valid: %v", err)
		}
		if err := ValidateAlgorithm(CryptoECDSAP256); err != nil {
			t.Errorf("ECDSA P-256 should be valid: %v", err)
		}
	})

	t.Run("Invalid algorithm", func(t *testing.T) {
		if err := ValidateAlgorithm(CryptoAlgorithm("RSA")); err == nil {
			t.Error("Expected error for RSA")
		}
		if err := ValidateAlgorithm(CryptoAlgorithm("")); err == nil {
			t.Error("Expected error for empty algorithm")
		}
		if err := ValidateAlgorithm(CryptoAlgorithm("invalid")); err == nil {
			t.Error("Expected error for invalid algorithm")
		}
	})
}

func TestNewCryptoSigner(t *testing.T) {
	t.Run("Ed25519", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		signer, err := NewCryptoSigner(CryptoEd25519, priv)
		if err != nil {
			t.Fatalf("Failed to create Ed25519 signer: %v", err)
		}
		if signer.Algorithm() != CryptoEd25519 {
			t.Error("Wrong algorithm")
		}
	})

	t.Run("ECDSA P-256", func(t *testing.T) {
		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signer, err := NewCryptoSigner(CryptoECDSAP256, priv)
		if err != nil {
			t.Fatalf("Failed to create ECDSA signer: %v", err)
		}
		if signer.Algorithm() != CryptoECDSAP256 {
			t.Error("Wrong algorithm")
		}
	})

	t.Run("Algorithm mismatch", func(t *testing.T) {
		// Ed25519 key with ECDSA algorithm
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		_, err := NewCryptoSigner(CryptoECDSAP256, priv)
		if err == nil {
			t.Error("Expected error for algorithm/key mismatch")
		}

		// ECDSA key with Ed25519 algorithm
		ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		_, err = NewCryptoSigner(CryptoEd25519, ecPriv)
		if err == nil {
			t.Error("Expected error for algorithm/key mismatch")
		}
	})

	t.Run("Invalid algorithm", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		_, err := NewCryptoSigner(CryptoAlgorithm("invalid"), priv)
		if err == nil {
			t.Error("Expected error for invalid algorithm")
		}
	})

	t.Run("nil key", func(t *testing.T) {
		_, err := NewCryptoSigner(CryptoEd25519, nil)
		if err == nil {
			t.Error("Expected error for nil key")
		}
	})
}

func TestEd25519Signer(t *testing.T) {
	// Test Ed25519 signer for completeness
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := &ed25519Signer{privateKey: priv}

	t.Run("Algorithm", func(t *testing.T) {
		if signer.Algorithm() != CryptoEd25519 {
			t.Errorf("Expected algorithm %v, got %v", CryptoEd25519, signer.Algorithm())
		}
	})

	t.Run("KeyType", func(t *testing.T) {
		expected := "Ed25519"
		if signer.KeyType() != expected {
			t.Errorf("Expected key type %q, got %q", expected, signer.KeyType())
		}
	})
}

// Test cross-algorithm scenarios
func TestCrossAlgorithmVerification(t *testing.T) {
	// Generate keys for both algorithms
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	edSigner, _ := NewCryptoSigner(CryptoEd25519, edPriv)
	ecSigner, _ := NewCryptoSigner(CryptoECDSAP256, ecPriv)

	data := []byte("test data")

	t.Run("Ed25519 signature with ECDSA verifier", func(t *testing.T) {
		sig, _ := edSigner.Sign(data)
		if ecSigner.Verify(data, sig, edSigner.PublicKey()) {
			t.Error("ECDSA verifier accepted Ed25519 signature")
		}
	})

	t.Run("ECDSA signature with Ed25519 verifier", func(t *testing.T) {
		sig, _ := ecSigner.Sign(data)
		if edSigner.Verify(data, sig, ecSigner.PublicKey()) {
			t.Error("Ed25519 verifier accepted ECDSA signature")
		}
	})
}
