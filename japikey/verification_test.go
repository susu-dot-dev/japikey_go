package japikey

import (
	"crypto/rand"
	"crypto/rsa"
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
