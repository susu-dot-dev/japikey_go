package japikey

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/susu-dot-dev/japikey/errors"
)

// createValidToken creates a valid JAPIKey token for testing purposes
func createValidToken() (string, *rsa.PublicKey, uuid.UUID, error) {
	// Create a private key for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, uuid.Nil, err
	}

	// Generate a UUID for the key ID
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

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
	token.Header["kid"] = keyID.String() // UUID matching issuer

	// Sign the token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", nil, uuid.Nil, err
	}

	// Return the token, public key, and key ID
	return tokenString, &privateKey.PublicKey, keyID, nil
}

// createInvalidToken creates an invalid JAPIKey token for testing purposes
func createInvalidToken() string {
	// Create a token with invalid version
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	claims := jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://example.com/123e4567-e89b-12d3-a456-426614174000",
		"aud": "test-audience",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"ver": "invalid-version", // Invalid version
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID.String()

	tokenString, _ := token.SignedString(privateKey)
	return tokenString
}

// mockKeyFunc creates a mock key function that returns the provided public key
func mockKeyFunc(pubKey *rsa.PublicKey) JWKCallback {
	return func(keyID uuid.UUID) (*rsa.PublicKey, error) {
		return pubKey, nil
	}
}

func TestVerifyValidToken(t *testing.T) {
	// Create a valid token and public key
	tokenString, pubKey, expectedKeyID, err := createValidToken()
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

	if result.KeyID == uuid.Nil {
		t.Error("Expected key ID to not be empty for valid token")
	}

	if result.KeyID != expectedKeyID {
		t.Errorf("Expected key ID %v, got %v", expectedKeyID, result.KeyID)
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
	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
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
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	token.Header["kid"] = keyID.String()
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
	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
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
	differentKeyID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	token.Header["kid"] = differentKeyID.String() // Different from issuer UUID
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
	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
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
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	token.Header["kid"] = keyID.String()
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
	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestVerifyFunctionExists(t *testing.T) {
	// This test just verifies that the Verify function exists with the correct signature
	config := VerifyConfig{
		BaseIssuerURL: "https://example.com/",
		Timeout:       5 * time.Second,
	}

	// Create a mock callback that returns nil
	mockCallback := func(keyID uuid.UUID) (*rsa.PublicKey, error) {
		return nil, nil
	}

	// We're not testing the actual functionality here, just that the function exists
	// The actual tests would require valid JWT tokens and keys
	_, err := Verify("some.token.string", config, mockCallback)

	// We expect an error because our mock callback returns nil keys
	if err == nil {
		t.Errorf("Expected error due to mock callback returning nil key")
	}
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

func TestShouldVerifyValidToken(t *testing.T) {
	tokenString, _, _, err := createValidToken()
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

func TestVerifyPreservesCustomClaims(t *testing.T) {
	// Create a token manually with custom claims to ensure issuer matches keyID
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	claims := jwt.MapClaims{
		"sub": "test-user",
		"iss": fmt.Sprintf("https://example.com/%s", keyID.String()),
		"aud": "test-audience",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"ver": "japikey-v1",
		"hello": "world",
		"foo":   "bar",
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID.String()
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Set up verification
	verifyConfig := VerifyConfig{
		BaseIssuerURL: "https://example.com/",
		Timeout:       5 * time.Second,
	}

	keyFunc := func(kid uuid.UUID) (*rsa.PublicKey, error) {
		if kid != keyID {
			return nil, errors.NewKeyNotFoundError("key not found")
		}
		return &privateKey.PublicKey, nil
	}

	// Verify the token
	result, err := Verify(tokenString, verifyConfig, keyFunc)
	if err != nil {
		t.Fatalf("Failed to verify token: %v", err)
	}

	// Check that custom claims are preserved
	if result.Claims["hello"] != "world" {
		t.Errorf("Expected custom claim 'hello' to be 'world', got %v", result.Claims["hello"])
	}

	if result.Claims["foo"] != "bar" {
		t.Errorf("Expected custom claim 'foo' to be 'bar', got %v", result.Claims["foo"])
	}

	nested, ok := result.Claims["nested"].(map[string]interface{})
	if !ok {
		t.Errorf("Expected custom claim 'nested' to be a map, got %T", result.Claims["nested"])
	} else if nested["key"] != "value" {
		t.Errorf("Expected nested claim 'key' to be 'value', got %v", nested["key"])
	}

	// Verify standard claims are also present
	if result.Claims["sub"] != "test-user" {
		t.Errorf("Expected 'sub' to be 'test-user', got %v", result.Claims["sub"])
	}

	if result.Claims["ver"] != "japikey-v1" {
		t.Errorf("Expected 'ver' to be 'japikey-v1', got %v", result.Claims["ver"])
	}
}
