package japikey

import (
	"crypto/rsa"
	"testing"
	"time"
)

// MockJWKCallback is a mock implementation of the JWK callback for testing
func MockJWKCallback(keyID string) (*rsa.PublicKey, error) {
	// In a real test, we would return an actual public key
	// For now, we'll return nil to test error handling
	return nil, nil
}

func TestShouldVerify(t *testing.T) {
	// Test valid JWT format
	validToken := "header.payload.signature"
	if !ShouldVerify(validToken, "https://example.com/") {
		t.Errorf("ShouldVerify returned false for valid JWT format")
	}

	// Test invalid JWT format (missing part)
	invalidToken := "header.payload" // only 2 parts
	if ShouldVerify(invalidToken, "https://example.com/") {
		t.Errorf("ShouldVerify returned true for invalid JWT format")
	}

	// Test token that exceeds size limit
	largeToken := make([]byte, MaxTokenSize+1)
	for i := range largeToken {
		largeToken[i] = 'a'
	}
	if ShouldVerify(string(largeToken), "https://example.com/") {
		t.Errorf("ShouldVerify returned true for token exceeding size limit")
	}
}

func TestVerifyFunctionExists(t *testing.T) {
	// This test just verifies that the Verify function exists with the correct signature
	config := VerifyConfig{
		BaseIssuerURL: "https://example.com/",
		Timeout:       5 * time.Second,
	}
	
	// We're not testing the actual functionality here, just that the function exists
	// The actual tests would require valid JWT tokens and keys
	_, err := Verify("some.token.string", config, MockJWKCallback)
	
	// We expect an error because our mock callback returns nil keys
	if err == nil {
		t.Errorf("Expected error due to mock callback returning nil key")
	}
}