package sctx

import (
	"context"
	"testing"
	"time"
)

// TestRequireCertField tests the RequireCertField guard
func TestRequireCertField(t *testing.T) {
	ctx := &Context[any]{
		CertificateInfo: CertificateInfo{
			CommonName:   "test.example.com",
			Issuer:       "Example CA",
			SerialNumber: "123456",
		},
	}

	tests := []struct {
		name      string
		field     string
		expected  string
		shouldErr bool
	}{
		{"Match CN", "CN", "test.example.com", false},
		{"Match Issuer", "ISSUER", "Example CA", false},
		{"Match Serial", "SERIAL", "123456", false},
		{"Mismatch CN", "CN", "wrong.example.com", true},
		{"Mismatch Issuer", "ISSUER", "Wrong CA", true},
		{"Unknown field", "UNKNOWN", "anything", true},
		{"Case insensitive field", "cn", "test.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard := RequireCertField[any](tt.field, tt.expected)
			_, err := guard(context.Background(), ctx)
			if (err != nil) != tt.shouldErr {
				t.Errorf("RequireCertField() error = %v, shouldErr %v", err, tt.shouldErr)
			}
		})
	}
}

// TestRequireCertPattern tests the RequireCertPattern guard
func TestRequireCertPattern(t *testing.T) {
	ctx := &Context[any]{
		CertificateInfo: CertificateInfo{
			CommonName:   "test.example.com",
			Issuer:       "Example CA",
			SerialNumber: "123456",
			NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			KeyUsage:     []string{"digital_signature", "key_encipherment"},
		},
	}

	tests := []struct {
		name      string
		field     string
		pattern   string
		shouldErr bool
	}{
		{"Match CN pattern", "CN", `^test\.example\.com$`, false},
		{"Match CN wildcard", "CN", `.*\.example\.com`, false},
		{"Mismatch CN pattern", "CN", `^prod\.example\.com$`, true},
		{"Match Issuer pattern", "ISSUER", "Example.*", false},
		{"Match Serial pattern", "SERIAL", "[0-9]+", false},
		{"Invalid regex", "CN", "[invalid", true},
		{"Empty field value", "UNKNOWN", "something", true},
		{"Match NotBefore", "NOTBEFORE", "2024-01-01", false},
		{"Match NotAfter", "NOTAFTER", "2025-01-01", false},
		{"Match KeyUsage", "KEYUSAGE", "digital_signature", false},
		{"Match CommonName alias", "COMMONNAME", "test", false},
		{"Match SerialNumber alias", "SERIALNUMBER", "123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard := RequireCertPattern[any](tt.field, tt.pattern)
			_, err := guard(context.Background(), ctx)
			if (err != nil) != tt.shouldErr {
				t.Errorf("RequireCertPattern() error = %v, shouldErr %v", err, tt.shouldErr)
			}
		})
	}
}

// TestExtractCertInfoField tests the extractCertInfoField function
func TestExtractCertInfoField(t *testing.T) {
	certInfo := CertificateInfo{
		CommonName:   "test.example.com",
		Issuer:       "Example CA",
		SerialNumber: "123456",
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     []string{"digital_signature", "key_encipherment"},
	}

	tests := []struct {
		name     string
		field    string
		expected string
	}{
		{"Extract CN", "CN", "test.example.com"},
		{"Extract CommonName", "COMMONNAME", "test.example.com"},
		{"Extract Issuer", "ISSUER", "Example CA"},
		{"Extract Serial", "SERIAL", "123456"},
		{"Extract SerialNumber", "SERIALNUMBER", "123456"},
		{"Extract NotBefore", "NOTBEFORE", "2024-01-01T00:00:00Z"},
		{"Extract NotAfter", "NOTAFTER", "2025-01-01T00:00:00Z"},
		{"Extract KeyUsage", "KEYUSAGE", "digital_signature,key_encipherment"},
		{"Unknown field", "UNKNOWN", ""},
		{"Lowercase field", "cn", "test.example.com"},
		{"Mixed case", "CommonName", "test.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCertInfoField(certInfo, tt.field)
			if result != tt.expected {
				t.Errorf("extractCertInfoField(%s) = %q, want %q", tt.field, result, tt.expected)
			}
		})
	}
}

// TestSetContextEdgeCases tests remaining edge cases in SetContext
func TestSetContextEdgeCases(t *testing.T) {
	ctx := &Context[any]{
		Permissions: []string{"existing"},
	}

	// Test with nil expiry
	guard := SetContext[any](ContextOptions{
		Permissions: []string{"new"},
	})

	result, err := guard(context.Background(), ctx)
	if err != nil {
		t.Fatalf("SetContext failed: %v", err)
	}

	// Should have both permissions
	if len(result.Permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(result.Permissions))
	}

	// Expiry should not be set
	if !result.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should remain zero when not specified")
	}
}

// TestGenerateGuardIDEdgeCases tests edge case in generateGuardID
func TestGenerateGuardIDEdgeCases(t *testing.T) {
	// Test that IDs are unique
	id1 := generateGuardID()
	id2 := generateGuardID()

	if id1 == id2 {
		t.Error("Generated guard IDs should be unique")
	}

	// Test format
	if len(id1) != 32 { // 16 bytes hex encoded = 32 chars
		t.Errorf("Expected 32 character ID, got %d", len(id1))
	}
}

// TestHasPermissionEdgeCases verifies hasPermission is tested (already covered)
func TestHasPermissionEdgeCases(t *testing.T) {
	// This is already tested through guard creation, but let's add explicit test
	perms := []string{"read", "write", "admin"}

	if !hasPermission(perms, "read") {
		t.Error("Should have read permission")
	}

	if hasPermission(perms, "delete") {
		t.Error("Should not have delete permission")
	}

	if hasPermission(nil, "read") {
		t.Error("Nil permissions should not have any permission")
	}

	if hasPermission([]string{}, "read") {
		t.Error("Empty permissions should not have any permission")
	}
}
