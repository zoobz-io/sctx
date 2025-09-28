package sctx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

// Helper function to create test certificate and key
func createTestCertAndKey(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	// Generate key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, priv
}

func TestCreateAssertion(t *testing.T) {
	cert, priv := createTestCertAndKey(t)

	t.Run("valid assertion", func(t *testing.T) {
		assertion, err := CreateAssertion(priv, cert)
		if err != nil {
			t.Fatalf("Failed to create assertion: %v", err)
		}

		// Check claims
		if assertion.Claims.Purpose != "token-generation" {
			t.Errorf("Expected purpose 'token-generation', got %s", assertion.Claims.Purpose)
		}

		if assertion.Claims.Fingerprint != getFingerprint(cert) {
			t.Errorf("Fingerprint mismatch")
		}

		// Check timing
		if assertion.Claims.IssuedAt.After(time.Now()) {
			t.Error("IssuedAt is in the future")
		}

		if assertion.Claims.ExpiresAt.Before(time.Now()) {
			t.Error("Assertion already expired")
		}

		// Check nonce
		if assertion.Claims.Nonce == "" {
			t.Error("Nonce is empty")
		}

		// Decode and check nonce length
		decoded, err := base64.RawURLEncoding.DecodeString(assertion.Claims.Nonce)
		if err != nil {
			t.Errorf("Failed to decode nonce: %v", err)
		}
		if len(decoded) != 32 {
			t.Errorf("Expected nonce length 32, got %d", len(decoded))
		}
	})

	t.Run("nil private key", func(t *testing.T) {
		_, err := CreateAssertion(nil, cert)
		if err == nil {
			t.Error("Expected error for nil private key")
		}
	})

	t.Run("nil certificate", func(t *testing.T) {
		_, err := CreateAssertion(priv, nil)
		if err == nil {
			t.Error("Expected error for nil certificate")
		}
	})

	t.Run("mismatched key and certificate", func(t *testing.T) {
		// Create a different key
		_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		_, err = CreateAssertion(otherPriv, cert)
		if err == nil {
			t.Error("Expected error for mismatched key and certificate")
		}
	})
}

func TestVerifyAssertion(t *testing.T) {
	cert, priv := createTestCertAndKey(t)

	t.Run("valid signature", func(t *testing.T) {
		assertion, err := CreateAssertion(priv, cert)
		if err != nil {
			t.Fatalf("Failed to create assertion: %v", err)
		}

		err = verifyAssertion(assertion, cert)
		if err != nil {
			t.Errorf("Failed to verify valid assertion: %v", err)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		assertion, err := CreateAssertion(priv, cert)
		if err != nil {
			t.Fatalf("Failed to create assertion: %v", err)
		}

		// Corrupt the signature
		assertion.Signature[0] ^= 0xFF

		err = verifyAssertion(assertion, cert)
		if err == nil {
			t.Error("Expected error for invalid signature")
		}
	})

	t.Run("wrong certificate", func(t *testing.T) {
		assertion, err := CreateAssertion(priv, cert)
		if err != nil {
			t.Fatalf("Failed to create assertion: %v", err)
		}

		// Create a different certificate
		otherCert, _ := createTestCertAndKey(t)

		err = verifyAssertion(assertion, otherCert)
		if err == nil {
			t.Error("Expected error for wrong certificate")
		}
	})
}

func TestAssertionValidationSteps(t *testing.T) {
	cert, priv := createTestCertAndKey(t)
	ctx := context.Background()

	t.Run("verifySignatureStep", func(t *testing.T) {
		t.Run("valid signature", func(t *testing.T) {
			assertion, _ := CreateAssertion(priv, cert)
			ac := &AssertionContext{
				Assertion:   assertion,
				Certificate: cert,
			}

			err := verifySignatureStep(ctx, ac)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})

		t.Run("invalid signature", func(t *testing.T) {
			assertion, _ := CreateAssertion(priv, cert)
			assertion.Signature[0] ^= 0xFF // Corrupt signature
			ac := &AssertionContext{
				Assertion:   assertion,
				Certificate: cert,
			}

			err := verifySignatureStep(ctx, ac)
			if err == nil {
				t.Error("Expected error for invalid signature")
			}
		})
	})

	t.Run("checkExpirationStep", func(t *testing.T) {

		t.Run("valid assertion", func(t *testing.T) {
			assertion, _ := CreateAssertion(priv, cert)
			ac := &AssertionContext{
				Assertion:   assertion,
				Certificate: cert,
			}

			err := checkExpirationStep(ctx, ac)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})

		t.Run("expired assertion", func(t *testing.T) {
			assertion, _ := CreateAssertion(priv, cert)
			// Set expiration to past
			assertion.Claims.ExpiresAt = time.Now().Add(-1 * time.Hour)
			ac := &AssertionContext{
				Assertion:   assertion,
				Certificate: cert,
			}

			err := checkExpirationStep(ctx, ac)
			if err == nil {
				t.Error("Expected error for expired assertion")
			}
		})

		t.Run("future issued assertion", func(t *testing.T) {
			assertion, _ := CreateAssertion(priv, cert)
			// Set issued time to future (beyond clock skew)
			assertion.Claims.IssuedAt = time.Now().Add(1 * time.Hour)
			ac := &AssertionContext{
				Assertion:   assertion,
				Certificate: cert,
			}

			err := checkExpirationStep(ctx, ac)
			if err == nil {
				t.Error("Expected error for future issued assertion")
			}
		})

		t.Run("lifetime too long", func(t *testing.T) {
			assertion, _ := CreateAssertion(priv, cert)
			// Set lifetime to 10 minutes
			assertion.Claims.ExpiresAt = assertion.Claims.IssuedAt.Add(10 * time.Minute)
			ac := &AssertionContext{
				Assertion:   assertion,
				Certificate: cert,
			}

			err := checkExpirationStep(ctx, ac)
			if err == nil {
				t.Error("Expected error for assertion with long lifetime")
			}
		})
	})

	t.Run("matchFingerprintStep", func(t *testing.T) {
		t.Run("matching fingerprint", func(t *testing.T) {
			assertion, _ := CreateAssertion(priv, cert)
			ac := &AssertionContext{
				Assertion:   assertion,
				Certificate: cert,
			}

			err := matchFingerprintStep(ctx, ac)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})

		t.Run("mismatched fingerprint", func(t *testing.T) {
			assertion, _ := CreateAssertion(priv, cert)
			// Change fingerprint
			assertion.Claims.Fingerprint = "wrong-fingerprint"
			ac := &AssertionContext{
				Assertion:   assertion,
				Certificate: cert,
			}

			err := matchFingerprintStep(ctx, ac)
			if err == nil {
				t.Error("Expected error for mismatched fingerprint")
			}
		})
	})

	t.Run("validateClaimsStep", func(t *testing.T) {
		t.Run("valid claims", func(t *testing.T) {
			assertion, _ := CreateAssertion(priv, cert)
			ac := &AssertionContext{
				Assertion:   assertion,
				Certificate: cert,
			}

			err := validateClaimsStep(ctx, ac)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})

		t.Run("invalid purpose", func(t *testing.T) {
			assertion, _ := CreateAssertion(priv, cert)
			assertion.Claims.Purpose = "wrong-purpose"
			ac := &AssertionContext{
				Assertion:   assertion,
				Certificate: cert,
			}

			err := validateClaimsStep(ctx, ac)
			if err == nil {
				t.Error("Expected error for invalid purpose")
			}
		})
	})
}

func TestValidateAssertionIntegration(t *testing.T) {
	resetAdminForTesting()
	
	cert, priv := createTestCertAndKey(t)
	ctx := context.Background()

	// Create admin service to test with nonce checking
	_, adminKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	
	admin, err := NewAdminService[any](adminKey, certPool)
	if err != nil {
		t.Fatalf("Failed to create admin service: %v", err)
	}
	adminSvc := admin.(*adminService[any])

	t.Run("valid assertion passes all checks", func(t *testing.T) {
		assertion, _ := CreateAssertion(priv, cert)

		err := ValidateAssertion(ctx, assertion, cert, adminSvc)
		if err != nil {
			t.Errorf("Expected valid assertion to pass, got: %v", err)
		}
	})

	t.Run("invalid signature fails", func(t *testing.T) {
		assertion, _ := CreateAssertion(priv, cert)
		assertion.Signature[0] ^= 0xFF

		err := ValidateAssertion(ctx, assertion, cert, adminSvc)
		if err == nil {
			t.Error("Expected invalid signature to fail")
		}
	})

	t.Run("expired assertion fails", func(t *testing.T) {
		assertion, _ := CreateAssertion(priv, cert)
		assertion.Claims.ExpiresAt = time.Now().Add(-time.Hour)

		err := ValidateAssertion(ctx, assertion, cert, adminSvc)
		if err == nil {
			t.Error("Expected expired assertion to fail")
		}
	})
}
