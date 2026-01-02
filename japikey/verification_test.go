package japikey

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// createValidToken creates a valid JAPIKey token for testing purposes
func createValidToken() (string, *rsa.PublicKey, error) {
	// Create a private key for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, err
	}

	// Create claims
	claims := jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://example.com/123e4567-e89b-12d3-a456-426614174000", // UUID format
		"aud": "test-audience",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"ver": "japikey-v1",
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "123e4567-e89b-12d3-a456-426614174000" // UUID matching issuer

	// Sign the token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", nil, err
	}

	// Return the token and the public key
	return tokenString, &privateKey.PublicKey, nil
}

// createInvalidToken creates an invalid JAPIKey token for testing purposes
func createInvalidToken() string {
	// Create a token with invalid version
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://example.com/123e4567-e89b-12d3-a456-426614174000",
		"aud": "test-audience",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"ver": "invalid-version", // Invalid version
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "123e4567-e89b-12d3-a456-426614174000"

	tokenString, _ := token.SignedString(privateKey)
	return tokenString
}

// mockKeyFunc creates a mock key function that returns the provided public key
func mockKeyFunc(pubKey *rsa.PublicKey) JWKCallback {
	return func(keyID string) (*rsa.PublicKey, error) {
		return pubKey, nil
	}
}

func TestVerifyValidToken(t *testing.T) {
	// Create a valid token and public key
	tokenString, pubKey, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}

	// Create config
	config := VerifyConfig{
		BaseIssuerURL: "https://example.com/",
		Timeout:       5 * time.Second,
	}

	// Verify the token
	result, err := Verify(tokenString, config, mockKeyFunc(pubKey))
	if err != nil {
		t.Errorf("Expected no error for valid token, got: %v", err)
	}

	if result == nil {
		t.Error("Expected result to not be nil for valid token")
	}

	if result.Claims == nil {
		t.Error("Expected claims to not be nil for valid token")
	}

	if result.KeyID == "" {
		t.Error("Expected key ID to not be empty for valid token")
	}

	if result.Algorithm == "" {
		t.Error("Expected algorithm to not be empty for valid token")
	}
}

func TestVerifyInvalidToken(t *testing.T) {
	// Create an invalid token
	tokenString := createInvalidToken()

	// Create config
	config := VerifyConfig{
		BaseIssuerURL: "https://example.com/",
		Timeout:       5 * time.Second,
	}

	// Create a public key (not matching the token, but we'll get an error before signature verification)
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &privateKey.PublicKey

	// Verify the token
	result, err := Verify(tokenString, config, mockKeyFunc(pubKey))
	if err == nil {
		t.Error("Expected error for invalid token, got none")
	}

	if result != nil {
		t.Error("Expected result to be nil for invalid token")
	}

	// Check that it's the right type of error
	if verificationErr, ok := err.(*JAPIKeyVerificationError); !ok {
		t.Errorf("Expected JAPIKeyVerificationError, got %T", err)
	} else if verificationErr.Code != VersionValidationError {
		t.Errorf("Expected error code %s, got %s", VersionValidationError, verificationErr.Code)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	// Create an expired token
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://example.com/123e4567-e89b-12d3-a456-426614174000",
		"aud": "test-audience",
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired
		"ver": "japikey-v1",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "123e4567-e89b-12d3-a456-426614174000"
	tokenString, _ := token.SignedString(privateKey)
	pubKey := &privateKey.PublicKey

	// Create config
	config := VerifyConfig{
		BaseIssuerURL: "https://example.com/",
		Timeout:       5 * time.Second,
	}

	// Verify the token
	result, err := Verify(tokenString, config, mockKeyFunc(pubKey))
	if err == nil {
		t.Error("Expected error for expired token, got none")
	}

	if result != nil {
		t.Error("Expected result to be nil for expired token")
	}

	// Check that it's the right type of error
	if verificationErr, ok := err.(*JAPIKeyVerificationError); !ok {
		t.Errorf("Expected JAPIKeyVerificationError, got %T", err)
	} else if verificationErr.Code != ExpirationError {
		t.Errorf("Expected error code %s, got %s", ExpirationError, verificationErr.Code)
	}
}

func TestVerifyTokenWithMismatchedKeyID(t *testing.T) {
	// Create a token with mismatched key ID and issuer UUID
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://example.com/123e4567-e89b-12d3-a456-426614174000", // UUID in issuer
		"aud": "test-audience",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"ver": "japikey-v1",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "different-uuid" // Different from issuer UUID
	tokenString, _ := token.SignedString(privateKey)
	pubKey := &privateKey.PublicKey

	// Create config
	config := VerifyConfig{
		BaseIssuerURL: "https://example.com/",
		Timeout:       5 * time.Second,
	}

	// Verify the token
	result, err := Verify(tokenString, config, mockKeyFunc(pubKey))
	if err == nil {
		t.Error("Expected error for mismatched key ID, got none")
	}

	if result != nil {
		t.Error("Expected result to be nil for mismatched key ID")
	}

	// Check that it's the right type of error
	if verificationErr, ok := err.(*JAPIKeyVerificationError); !ok {
		t.Errorf("Expected JAPIKeyVerificationError, got %T", err)
	} else if verificationErr.Code != KeyIDMismatchError {
		t.Errorf("Expected error code %s, got %s", KeyIDMismatchError, verificationErr.Code)
	}
}

func TestVerifyTokenWithInvalidAlgorithm(t *testing.T) {
	// Create a valid token but modify the header to have an invalid algorithm
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://example.com/123e4567-e89b-12d3-a456-426614174000",
		"aud": "test-audience",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"ver": "japikey-v1",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["alg"] = "HS256" // Set algorithm to HS256 instead of RS256
	token.Header["kid"] = "123e4567-e89b-12d3-a456-426614174000"
	tokenString, _ := token.SignedString(privateKey)
	pubKey := &privateKey.PublicKey

	// Create config
	config := VerifyConfig{
		BaseIssuerURL: "https://example.com/",
		Timeout:       5 * time.Second,
	}

	// Verify the token
	result, err := Verify(tokenString, config, mockKeyFunc(pubKey))
	if err == nil {
		t.Error("Expected error for invalid algorithm, got none")
	}

	if result != nil {
		t.Error("Expected result to be nil for invalid algorithm")
	}

	// Check that it's the right type of error
	if verificationErr, ok := err.(*JAPIKeyVerificationError); !ok {
		t.Errorf("Expected JAPIKeyVerificationError, got %T", err)
	} else if verificationErr.Code != AlgorithmError {
		t.Errorf("Expected error code %s, got %s", AlgorithmError, verificationErr.Code)
	}
}

func TestShouldVerifyValidToken(t *testing.T) {
	tokenString, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}

	if !ShouldVerify(tokenString, "https://example.com/") {
		t.Error("ShouldVerify returned false for valid token")
	}
}

func TestShouldVerifyInvalidFormat(t *testing.T) {
	invalidToken := "header.payload" // Only 2 parts instead of 3

	if ShouldVerify(invalidToken, "https://example.com/") {
		t.Error("ShouldVerify returned true for invalid format token")
	}
}

func TestShouldVerifyTooLargeToken(t *testing.T) {
	largeToken := make([]byte, MaxTokenSize+1)
	for i := range largeToken {
		largeToken[i] = 'a'
	}

	if ShouldVerify(string(largeToken), "https://example.com/") {
		t.Error("ShouldVerify returned true for too large token")
	}
}