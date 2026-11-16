package japikey

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	stderrors "errors"
	"fmt"
	"io/fs"
	"log"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/susu-dot-dev/japikey/errors"
)

// createValidToken creates a valid JAPIKey token for testing purposes
func createValidToken() (string, *rsa.PublicKey, uuid.UUID, error) {
	// Create a private key for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, uuid.Nil(), err
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
		"iat": time.Now().Unix(),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID.String() // UUID matching issuer

	// Sign the token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", nil, uuid.Nil(), err
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

// isUnauthorizedBecause reports whether err is a top-level *UnauthorizedError
// with the fixed message, whose cause is of type T.
func isUnauthorizedBecause[T error](err error) bool {
	u, ok := err.(*errors.UnauthorizedError)
	if !ok || u.Error() != errors.UnauthorizedMessage {
		return false
	}
	var cause T
	return stderrors.As(u.Cause, &cause)
}

// mockKeyFunc creates a mock key function that returns the provided public key
func mockKeyFunc(pubKey crypto.PublicKey) JWKCallback {
	return func(_ context.Context, keyID uuid.UUID) (crypto.PublicKey, error) {
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
	result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
	if err != nil {
		t.Errorf("Expected no error for valid token, got: %v", err)
	}

	if result == nil {
		t.Error("Expected result to not be nil for valid token")
		return
	}

	if result.Claims == nil {
		t.Error("Expected claims to not be nil for valid token")
	}

	if result.KeyID == uuid.Nil() {
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
	result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
	if err == nil {
		t.Error("Expected error for invalid token, got none")
	}

	if result != nil {
		t.Error("Expected result to be nil for invalid token")
	}

	// Check that it's the right type of error
	if !isUnauthorizedBecause[*errors.ValidationError](err) {
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
		"iat": time.Now().Unix(),
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
	result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
	if err == nil {
		t.Error("Expected error for expired token, got none")
	}

	if result != nil {
		t.Error("Expected result to be nil for expired token")
	}

	// Check that it's the right type of error
	if !isUnauthorizedBecause[*errors.TokenExpiredError](err) {
		t.Errorf("Expected TokenExpiredError, got %T", err)
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
		"iat": time.Now().Unix(),
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
	result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
	if err == nil {
		t.Error("Expected error for mismatched key ID, got none")
	}

	if result != nil {
		t.Error("Expected result to be nil for mismatched key ID")
	}

	// Check that it's the right type of error
	if !isUnauthorizedBecause[*errors.ValidationError](err) {
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
		"iat": time.Now().Unix(),
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
	result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
	if err == nil {
		t.Error("Expected error for invalid algorithm, got none")
	}

	if result != nil {
		t.Error("Expected result to be nil for invalid algorithm")
	}

	// Check that it's the right type of error
	if !isUnauthorizedBecause[*errors.ValidationError](err) {
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
	mockCallback := func(_ context.Context, keyID uuid.UUID) (crypto.PublicKey, error) {
		return nil, nil
	}

	// We're not testing the actual functionality here, just that the function exists
	// The actual tests would require valid JWT tokens and keys
	_, err := Verify(context.Background(), "some.token.string", config, mockCallback)

	// We expect an error because our mock callback returns nil keys
	if err == nil {
		t.Errorf("Expected error due to mock callback returning nil key")
	}
}

func TestShouldVerify(t *testing.T) {
	// Test with valid token (should pass all validations)
	tokenString, _, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}
	if !ShouldVerify(tokenString, "https://example.com/") {
		t.Errorf("ShouldVerify returned false for valid token")
	}

	// Test with invalid token format (not a valid JWT)
	invalidToken := "header.payload" // only 2 parts
	if ShouldVerify(invalidToken, "https://example.com/") {
		t.Errorf("ShouldVerify returned true for invalid JWT format")
	}

	// Test with invalid version
	invalidVersionToken := createInvalidToken()
	if ShouldVerify(invalidVersionToken, "https://example.com/") {
		t.Errorf("ShouldVerify returned true for token with invalid version")
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

func TestShouldVerifyMismatchedKid(t *testing.T) {
	// Create a token where kid doesn't match the UUID in issuer
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	differentKeyID := uuid.MustParse("987e6543-e21b-34d5-b789-123456789012")
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
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = differentKeyID.String() // Different from issuer UUID
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	if ShouldVerify(tokenString, "https://example.com/") {
		t.Error("ShouldVerify returned true for token with mismatched kid")
	}
}

func TestShouldVerifyInvalidIssuer(t *testing.T) {
	// Create a token with issuer that doesn't match baseIssuer
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	claims := jwt.MapClaims{
		"sub": "test-user",
		"iss": fmt.Sprintf("https://different.com/%s", keyID.String()),
		"aud": "test-audience",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"ver": "japikey-v1",
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID.String()
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	if ShouldVerify(tokenString, "https://example.com/") {
		t.Error("ShouldVerify returned true for token with issuer not matching baseIssuer")
	}
}

func TestShouldVerifyEmptyBaseIssuer(t *testing.T) {
	// ShouldVerify requires baseIssuer for security - empty baseIssuer should fail
	tokenString, _, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}

	// With empty baseIssuer, it should return false (security requirement)
	if ShouldVerify(tokenString, "") {
		t.Error("ShouldVerify returned true for token with empty baseIssuer (should require baseIssuer for security)")
	}
}

func TestVerifyEmptyBaseIssuerReturnsInternalError(t *testing.T) {
	// Verify requires baseIssuer - empty baseIssuer should return InternalError
	// because this is a server configuration issue, not a token validation issue
	tokenString, pubKey, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}

	// Create config with empty BaseIssuerURL
	config := VerifyConfig{
		BaseIssuerURL: "",
		Timeout:       5 * time.Second,
	}

	// Verify the token
	result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
	if err == nil {
		t.Error("Expected error for empty BaseIssuerURL, got none")
	}

	if result != nil {
		t.Error("Expected result to be nil for empty BaseIssuerURL")
	}

	// Check that it's an InternalError, not a ValidationError
	if _, ok := err.(*errors.InternalError); !ok {
		t.Errorf("Expected InternalError, got %T", err)
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
		"sub":   "test-user",
		"iss":   fmt.Sprintf("https://example.com/%s", keyID.String()),
		"aud":   "test-audience",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"ver":   "japikey-v1",
		"iat":   time.Now().Unix(),
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

	keyFunc := func(_ context.Context, kid uuid.UUID) (crypto.PublicKey, error) {
		if kid != keyID {
			return nil, errors.NewKeyNotFoundError("key not found")
		}
		return &privateKey.PublicKey, nil
	}

	// Verify the token
	result, err := Verify(context.Background(), tokenString, verifyConfig, keyFunc)
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

// createTokenWithIssuer creates a token with a specific issuer for testing
func createTokenWithIssuer(issuer string, keyID uuid.UUID) (string, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, err
	}

	claims := jwt.MapClaims{
		"sub": "test-user",
		"iss": issuer,
		"aud": "test-audience",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"ver": "japikey-v1",
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID.String()
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", nil, err
	}

	return tokenString, &privateKey.PublicKey, nil
}

func TestVerifyIssuerPathTraversal(t *testing.T) {
	// Test path traversal attacks
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	testCases := []struct {
		name    string
		issuer  string
		baseURL string
	}{
		{
			name:    "path traversal with ../",
			issuer:  "https://example.com/../evil.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL: "https://example.com/",
		},
		{
			name:    "path traversal with ..",
			issuer:  "https://example.com/..//evil.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL: "https://example.com/",
		},
		{
			name:    "path traversal with multiple ../",
			issuer:  "https://example.com/../../evil.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL: "https://example.com/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, pubKey, err := createTokenWithIssuer(tc.issuer, keyID)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			config := VerifyConfig{
				BaseIssuerURL: tc.baseURL,
				Timeout:       5 * time.Second,
			}

			result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
			if err == nil {
				t.Error("Expected error for path traversal attack, got none")
			}
			if result != nil {
				t.Error("Expected result to be nil for path traversal attack")
			}
			if !isUnauthorizedBecause[*errors.ValidationError](err) {
				t.Errorf("Expected ValidationError, got %T", err)
			}
		})
	}
}

func TestVerifyIssuerURLEncoding(t *testing.T) {
	// Test URL encoding attacks
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	testCases := []struct {
		name    string
		issuer  string
		baseURL string
	}{
		{
			name:    "URL encoded slash",
			issuer:  "https://example.com%2Fevil.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL: "https://example.com/",
		},
		{
			name:    "URL encoded double slash",
			issuer:  "https://example.com%2F%2Fevil.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL: "https://example.com/",
		},
		{
			name:    "URL encoded path traversal",
			issuer:  "https://example.com%2F..%2Fevil.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL: "https://example.com/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, pubKey, err := createTokenWithIssuer(tc.issuer, keyID)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			config := VerifyConfig{
				BaseIssuerURL: tc.baseURL,
				Timeout:       5 * time.Second,
			}

			result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
			if err == nil {
				t.Error("Expected error for URL encoding attack, got none")
			}
			if result != nil {
				t.Error("Expected result to be nil for URL encoding attack")
			}
		})
	}
}

func TestVerifyIssuerCaseSensitivity(t *testing.T) {
	// Test case sensitivity - issuer should match baseIssuer exactly (case-sensitive)
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	testCases := []struct {
		name       string
		issuer     string
		baseURL    string
		shouldPass bool
	}{
		{
			name:       "uppercase scheme",
			issuer:     "HTTPS://example.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/",
			shouldPass: false,
		},
		{
			name:       "uppercase domain",
			issuer:     "https://EXAMPLE.COM/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/",
			shouldPass: false,
		},
		{
			name:       "mixed case",
			issuer:     "https://ExAmPlE.CoM/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/",
			shouldPass: false,
		},
		{
			name:       "correct case",
			issuer:     "https://example.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/",
			shouldPass: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, pubKey, err := createTokenWithIssuer(tc.issuer, keyID)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			config := VerifyConfig{
				BaseIssuerURL: tc.baseURL,
				Timeout:       5 * time.Second,
			}

			result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
			if tc.shouldPass {
				if err != nil {
					t.Errorf("Expected no error for valid issuer, got: %v", err)
				}
				if result == nil {
					t.Error("Expected result to not be nil for valid issuer")
				}
			} else {
				if err == nil {
					t.Error("Expected error for case mismatch, got none")
				}
				if result != nil {
					t.Error("Expected result to be nil for case mismatch")
				}
			}
		})
	}
}

func TestVerifyIssuerTrailingSlashes(t *testing.T) {
	// Test trailing slash handling
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	testCases := []struct {
		name       string
		issuer     string
		baseURL    string
		shouldPass bool
	}{
		{
			name:       "baseURL without trailing slash, issuer without trailing slash",
			issuer:     "https://example.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com",
			shouldPass: true,
		},
		{
			name:       "baseURL with trailing slash, issuer without trailing slash",
			issuer:     "https://example.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/",
			shouldPass: true,
		},
		{
			name:       "issuer with double slash",
			issuer:     "https://example.com//123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/",
			shouldPass: false, // Should fail - double slash means extra path component, must be exactly baseIssuer/uuid
		},
		{
			name:       "issuer with trailing slash after UUID",
			issuer:     "https://example.com/123e4567-e89b-12d3-a456-426614174000/",
			baseURL:    "https://example.com/",
			shouldPass: false, // UUID parsing should fail on empty string
		},
		{
			name:       "issuer with multiple trailing slashes",
			issuer:     "https://example.com/123e4567-e89b-12d3-a456-426614174000///",
			baseURL:    "https://example.com/",
			shouldPass: false, // UUID parsing should fail on empty string
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, pubKey, err := createTokenWithIssuer(tc.issuer, keyID)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			config := VerifyConfig{
				BaseIssuerURL: tc.baseURL,
				Timeout:       5 * time.Second,
			}

			result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
			if tc.shouldPass {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if result == nil {
					t.Error("Expected result to not be nil")
				}
			} else {
				if err == nil {
					t.Error("Expected error, got none")
				}
				if result != nil {
					t.Error("Expected result to be nil")
				}
			}
		})
	}
}

func TestVerifyIssuerPathComponents(t *testing.T) {
	// Test issuer with path components
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	testCases := []struct {
		name       string
		issuer     string
		baseURL    string
		shouldPass bool
	}{
		{
			name:       "baseURL with path, issuer with matching path",
			issuer:     "https://example.com/api/v1/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/api/v1/",
			shouldPass: true,
		},
		{
			name:       "baseURL with path, issuer without matching path",
			issuer:     "https://example.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/api/v1/",
			shouldPass: false,
		},
		{
			name:       "baseURL without path, issuer with extra path",
			issuer:     "https://example.com/path/to/resource/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/",
			shouldPass: false, // Should fail - extra path components not allowed, must be exactly baseIssuer/uuid
		},
		{
			name:       "baseURL with path, issuer with extra path",
			issuer:     "https://example.com/api/v1/extra/path/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/api/v1/",
			shouldPass: false, // Should fail - extra path components not allowed, must be exactly baseIssuer/uuid
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, pubKey, err := createTokenWithIssuer(tc.issuer, keyID)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			config := VerifyConfig{
				BaseIssuerURL: tc.baseURL,
				Timeout:       5 * time.Second,
			}

			result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
			if tc.shouldPass {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if result == nil {
					t.Error("Expected result to not be nil")
				}
			} else {
				if err == nil {
					t.Error("Expected error, got none")
				}
				if result != nil {
					t.Error("Expected result to be nil")
				}
			}
		})
	}
}

func TestVerifyIssuerMissingOrInvalidUUID(t *testing.T) {
	// Test issuer with missing or invalid UUID
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	testCases := []struct {
		name    string
		issuer  string
		baseURL string
	}{
		{
			name:    "issuer with no UUID",
			issuer:  "https://example.com/",
			baseURL: "https://example.com/",
		},
		{
			name:    "issuer with empty UUID",
			issuer:  "https://example.com/",
			baseURL: "https://example.com/",
		},
		{
			name:    "issuer with invalid UUID format",
			issuer:  "https://example.com/not-a-uuid",
			baseURL: "https://example.com/",
		},
		{
			name:    "issuer with malformed UUID",
			issuer:  "https://example.com/123e4567-e89b-12d3-a456",
			baseURL: "https://example.com/",
		},
		{
			name:    "issuer with UUID in middle",
			issuer:  "https://example.com/123e4567-e89b-12d3-a456-426614174000/extra",
			baseURL: "https://example.com/",
		},
		{
			name:    "issuer with multiple UUIDs",
			issuer:  "https://example.com/123e4567-e89b-12d3-a456-426614174000/987e6543-e21b-34d5-b789-123456789012",
			baseURL: "https://example.com/",
		},
		{
			name:    "issuer with non-UUID at end",
			issuer:  "https://example.com/path/not-a-uuid",
			baseURL: "https://example.com/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, pubKey, err := createTokenWithIssuer(tc.issuer, keyID)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			config := VerifyConfig{
				BaseIssuerURL: tc.baseURL,
				Timeout:       5 * time.Second,
			}

			result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
			if err == nil {
				t.Error("Expected error for invalid UUID, got none")
			}
			if result != nil {
				t.Error("Expected result to be nil for invalid UUID")
			}
			if !isUnauthorizedBecause[*errors.ValidationError](err) {
				t.Errorf("Expected ValidationError, got %T", err)
			}
		})
	}
}

func TestVerifyIssuerQueryParamsAndFragments(t *testing.T) {
	// Test issuer with query parameters or fragments
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	testCases := []struct {
		name       string
		issuer     string
		baseURL    string
		shouldPass bool
	}{
		{
			name:       "issuer with query params",
			issuer:     "https://example.com/123e4567-e89b-12d3-a456-426614174000?param=value",
			baseURL:    "https://example.com/",
			shouldPass: false, // UUID parsing should fail on string with query params
		},
		{
			name:       "issuer with fragment",
			issuer:     "https://example.com/123e4567-e89b-12d3-a456-426614174000#fragment",
			baseURL:    "https://example.com/",
			shouldPass: false, // UUID parsing should fail on string with fragment
		},
		{
			name:       "baseURL with query params",
			issuer:     "https://example.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/?param=value",
			shouldPass: false, // Issuer doesn't start with baseURL
		},
		{
			name:       "baseURL with fragment",
			issuer:     "https://example.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/#fragment",
			shouldPass: false, // Issuer doesn't start with baseURL
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, pubKey, err := createTokenWithIssuer(tc.issuer, keyID)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			config := VerifyConfig{
				BaseIssuerURL: tc.baseURL,
				Timeout:       5 * time.Second,
			}

			result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
			if tc.shouldPass {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if result == nil {
					t.Error("Expected result to not be nil")
				}
			} else {
				if err == nil {
					t.Error("Expected error, got none")
				}
				if result != nil {
					t.Error("Expected result to be nil")
				}
			}
		})
	}
}

func TestVerifyIssuerVeryLongString(t *testing.T) {
	// Test issuer with very long string
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	longPath := strings.Repeat("a", 1000)
	issuer := fmt.Sprintf("https://example.com/%s/123e4567-e89b-12d3-a456-426614174000", longPath)

	tokenString, pubKey, err := createTokenWithIssuer(issuer, keyID)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	config := VerifyConfig{
		BaseIssuerURL: "https://example.com/",
		Timeout:       5 * time.Second,
	}

	result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
	// Should fail - extra path components not allowed, must be exactly baseIssuer/uuid
	if err == nil {
		t.Error("Expected error for issuer with extra path components, got none")
	}
	if result != nil {
		t.Error("Expected result to be nil for issuer with extra path components")
	}
}

func TestVerifyIssuerControlCharacters(t *testing.T) {
	// Test issuer with control characters
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	testCases := []struct {
		name    string
		issuer  string
		baseURL string
	}{
		{
			name:    "issuer with newline",
			issuer:  "https://example.com/\n123e4567-e89b-12d3-a456-426614174000",
			baseURL: "https://example.com/",
		},
		{
			name:    "issuer with tab",
			issuer:  "https://example.com/\t123e4567-e89b-12d3-a456-426614174000",
			baseURL: "https://example.com/",
		},
		{
			name:    "issuer with null byte",
			issuer:  "https://example.com/\x00123e4567-e89b-12d3-a456-426614174000",
			baseURL: "https://example.com/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, pubKey, err := createTokenWithIssuer(tc.issuer, keyID)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			config := VerifyConfig{
				BaseIssuerURL: tc.baseURL,
				Timeout:       5 * time.Second,
			}

			result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
			// Control characters in issuer should cause validation to fail
			if err == nil {
				t.Error("Expected error for issuer with control characters, got none")
			}
			if result != nil {
				t.Error("Expected result to be nil for issuer with control characters")
			}
		})
	}
}

func TestVerifyIssuerSubdomainAttack(t *testing.T) {
	// Test subdomain attacks
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	testCases := []struct {
		name    string
		issuer  string
		baseURL string
	}{
		{
			name:    "subdomain attack",
			issuer:  "https://evil.example.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL: "https://example.com/",
		},
		{
			name:    "subdomain with path",
			issuer:  "https://evil.example.com/path/123e4567-e89b-12d3-a456-426614174000",
			baseURL: "https://example.com/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, pubKey, err := createTokenWithIssuer(tc.issuer, keyID)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			config := VerifyConfig{
				BaseIssuerURL: tc.baseURL,
				Timeout:       5 * time.Second,
			}

			result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
			if err == nil {
				t.Error("Expected error for subdomain attack, got none")
			}
			if result != nil {
				t.Error("Expected result to be nil for subdomain attack")
			}
		})
	}
}

func TestVerifyIssuerPrefixAttack(t *testing.T) {
	// Test prefix attacks - issuer that starts with baseIssuer but has malicious content
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	testCases := []struct {
		name       string
		issuer     string
		baseURL    string
		shouldPass bool
	}{
		{
			name:       "issuer with extra domain after base",
			issuer:     "https://example.com.evil.com/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/",
			shouldPass: false, // Should fail prefix check
		},
		{
			name:       "issuer that is prefix of base",
			issuer:     "https://example.co/123e4567-e89b-12d3-a456-426614174000",
			baseURL:    "https://example.com/",
			shouldPass: false, // Should fail prefix check
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, pubKey, err := createTokenWithIssuer(tc.issuer, keyID)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			config := VerifyConfig{
				BaseIssuerURL: tc.baseURL,
				Timeout:       5 * time.Second,
			}

			result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(pubKey))
			if tc.shouldPass {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if result == nil {
					t.Error("Expected result to not be nil")
				}
			} else {
				if err == nil {
					t.Error("Expected error, got none")
				}
				if result != nil {
					t.Error("Expected result to be nil")
				}
			}
		})
	}
}

func TestVerifyIssuerMissingClaim(t *testing.T) {
	// Test missing issuer claim
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	claims := jwt.MapClaims{
		"sub": "test-user",
		// Missing "iss" claim
		"aud": "test-audience",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"ver": "japikey-v1",
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID.String()
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	config := VerifyConfig{
		BaseIssuerURL: "https://example.com/",
		Timeout:       5 * time.Second,
	}

	result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(&privateKey.PublicKey))
	if err == nil {
		t.Error("Expected error for missing issuer claim, got none")
	}
	if result != nil {
		t.Error("Expected result to be nil for missing issuer claim")
	}
	if !isUnauthorizedBecause[*errors.ValidationError](err) {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestVerifyIssuerNonStringClaim(t *testing.T) {
	// Test non-string issuer claim
	keyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	testCases := []struct {
		name   string
		issuer interface{}
	}{
		{
			name:   "issuer as integer",
			issuer: 12345,
		},
		{
			name:   "issuer as map",
			issuer: map[string]interface{}{"url": "https://example.com/"},
		},
		{
			name:   "issuer as array",
			issuer: []string{"https://example.com/"},
		},
		{
			name:   "issuer as nil",
			issuer: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"sub": "test-user",
				"iss": tc.issuer,
				"aud": "test-audience",
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"ver": "japikey-v1",
				"iat": time.Now().Unix(),
			}

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = keyID.String()
			tokenString, err := token.SignedString(privateKey)
			if err != nil {
				t.Fatalf("Failed to sign token: %v", err)
			}

			config := VerifyConfig{
				BaseIssuerURL: "https://example.com/",
				Timeout:       5 * time.Second,
			}

			result, err := Verify(context.Background(), tokenString, config, mockKeyFunc(&privateKey.PublicKey))
			if err == nil {
				t.Error("Expected error for non-string issuer claim, got none")
			}
			if result != nil {
				t.Error("Expected result to be nil for non-string issuer claim")
			}
			if !isUnauthorizedBecause[*errors.ValidationError](err) {
				t.Errorf("Expected ValidationError, got %T", err)
			}
		})
	}
}

func TestVerifyCallbackReturnsNilKey(t *testing.T) {
	tokenString, _, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}
	config := VerifyConfig{BaseIssuerURL: "https://example.com/", Timeout: 5 * time.Second}

	// (nil, nil) previously caused a nil pointer dereference panic.
	result, err := Verify(context.Background(), tokenString, config, func(context.Context, uuid.UUID) (crypto.PublicKey, error) {
		return nil, nil
	})
	if result != nil {
		t.Error("Expected nil result when callback returns nil key")
	}
	if !isUnauthorizedBecause[*errors.KeyNotFoundError](err) {
		t.Errorf("Expected *KeyNotFoundError, got %T: %v", err, err)
	}

	// A key with a nil modulus is equally unusable.
	_, err = Verify(context.Background(), tokenString, config, func(context.Context, uuid.UUID) (crypto.PublicKey, error) {
		return &rsa.PublicKey{E: 65537}, nil
	})
	if !isUnauthorizedBecause[*errors.KeyNotFoundError](err) {
		t.Errorf("Expected *KeyNotFoundError for nil modulus, got %T: %v", err, err)
	}
}

func TestVerifyNilCallback(t *testing.T) {
	tokenString, _, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}
	config := VerifyConfig{BaseIssuerURL: "https://example.com/", Timeout: 5 * time.Second}

	_, err = Verify(context.Background(), tokenString, config, nil)
	if _, ok := err.(*errors.InternalError); !ok {
		t.Errorf("Expected *InternalError for nil callback, got %T: %v", err, err)
	}
}

func TestVerifyCallbackErrorMapping(t *testing.T) {
	tokenString, _, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}
	config := VerifyConfig{BaseIssuerURL: "https://example.com/", Timeout: 5 * time.Second}

	tests := []struct {
		name    string
		cbErr   error
		checkFn func(error) bool
	}{
		{"key not found is unauthorized", errors.NewKeyNotFoundError("nf"), isUnauthorizedBecause[*errors.KeyNotFoundError]},
		{"wrapped key not found is unauthorized", fmt.Errorf("lookup: %w", errors.NewKeyNotFoundError("nf")), isUnauthorizedBecause[*errors.KeyNotFoundError]},
		{"generic error is not key-not-found", fmt.Errorf("db exploded: secret-dsn"), func(e error) bool { _, ok := e.(*errors.InternalError); return ok }},
		{"callback deadline error", context.DeadlineExceeded, func(e error) bool { _, ok := e.(*errors.DatabaseTimeoutError); return ok }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(context.Background(), tokenString, config, func(context.Context, uuid.UUID) (crypto.PublicKey, error) {
				return nil, tt.cbErr
			})
			if err == nil || !tt.checkFn(err) {
				t.Errorf("Unexpected error type %T: %v", err, err)
			}
			if err != nil && strings.Contains(err.Error(), "secret-dsn") {
				t.Errorf("Callback error text leaked: %v", err)
			}
		})
	}
}

func TestVerifyTimeoutEnforced(t *testing.T) {
	tokenString, _, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}
	config := VerifyConfig{BaseIssuerURL: "https://example.com/", Timeout: 50 * time.Millisecond}

	var deadlineSeen bool
	start := time.Now()
	// A well-behaved callback blocks on its context, as a database driver would.
	_, err = Verify(context.Background(), tokenString, config, func(ctx context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
		_, deadlineSeen = ctx.Deadline()
		<-ctx.Done()
		return nil, ctx.Err()
	})
	elapsed := time.Since(start)

	if _, ok := err.(*errors.DatabaseTimeoutError); !ok {
		t.Errorf("Expected *DatabaseTimeoutError, got %T: %v", err, err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Verify did not honor timeout, took %v", elapsed)
	}
	if !deadlineSeen {
		t.Error("Expected callback context to carry a deadline")
	}
}

func TestVerifyContextCancellation(t *testing.T) {
	tokenString, _, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}
	config := VerifyConfig{BaseIssuerURL: "https://example.com/", Timeout: time.Minute}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, err = Verify(ctx, tokenString, config, func(ctx context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if _, ok := err.(*errors.DatabaseTimeoutError); !ok {
		t.Errorf("Expected *DatabaseTimeoutError on cancellation, got %T: %v", err, err)
	}
}

// A callback that returns a result only after the deadline must not be
// trusted: the late result is reported as a timeout.
func TestVerifyLateCallbackResultIsTimeout(t *testing.T) {
	tokenString, pubKey, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}
	config := VerifyConfig{BaseIssuerURL: "https://example.com/", Timeout: 20 * time.Millisecond}

	_, err = Verify(context.Background(), tokenString, config, func(ctx context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
		time.Sleep(60 * time.Millisecond) // ignores ctx, returns a good key too late
		return pubKey, nil
	})
	if _, ok := err.(*errors.DatabaseTimeoutError); !ok {
		t.Errorf("Expected *DatabaseTimeoutError for late result, got %T: %v", err, err)
	}
}

// Verify runs the callback synchronously: once every Verify call has returned,
// no goroutine is left behind, even for forged tokens that reach the callback.
func TestVerifyLeavesNoGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()

	const n = 50
	for i := 0; i < n; i++ {
		keyID := uuid.New().String()
		// Forged: valid header and claims for the issuer, garbage signature
		tokenString, _ := signTestToken(t, baseTestClaims(keyID), keyID)
		parts := strings.Split(tokenString, ".")
		forged := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-4] + "AAAA"

		_, _ = Verify(context.Background(), forged, VerifyConfig{BaseIssuerURL: "https://example.com/"},
			func(ctx context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
				return nil, errors.NewKeyNotFoundError("nf")
			})
	}

	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutines grew from %d to %d after %d Verify calls", before, after, n)
	}
}

func TestVerifyCallbackPanicRecovered(t *testing.T) {
	tokenString, _, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}
	config := VerifyConfig{BaseIssuerURL: "https://example.com/", Timeout: 5 * time.Second}

	_, err = Verify(context.Background(), tokenString, config, func(context.Context, uuid.UUID) (crypto.PublicKey, error) {
		panic("boom")
	})
	if _, ok := err.(*errors.InternalError); !ok {
		t.Errorf("Expected *InternalError for panicking callback, got %T: %v", err, err)
	}
}

func TestVerifyDefaultTimeoutApplied(t *testing.T) {
	tokenString, _, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}
	// Timeout unset: a deadline must still be present on the callback context.
	var sawDeadline bool
	_, _ = Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, func(ctx context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
		_, sawDeadline = ctx.Deadline()
		return nil, errors.NewKeyNotFoundError("nf")
	})
	if !sawDeadline {
		t.Error("Expected default timeout deadline on callback context")
	}
}

// signTestToken signs the claims with a fresh key and the given kid header, returning the token and public key
func signTestToken(t *testing.T, claims jwt.MapClaims, kid string) (string, *rsa.PublicKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	return tokenString, &privateKey.PublicKey
}

func baseTestClaims(keyID string) jwt.MapClaims {
	return jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://example.com/" + keyID,
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"ver": "japikey-v1",
	}
}

func TestVerifyRejectsNilUUIDKeyIDWithoutLookup(t *testing.T) {
	nilID := uuid.Nil().String()
	tokenString, pubKey := signTestToken(t, baseTestClaims(nilID), nilID)

	called := false
	keyFunc := func(ctx context.Context, keyID uuid.UUID) (crypto.PublicKey, error) {
		called = true
		return pubKey, nil
	}

	_, err := Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, keyFunc)
	if !isUnauthorizedBecause[*errors.ValidationError](err) {
		t.Fatalf("Expected ValidationError for nil UUID kid, got %T: %v", err, err)
	}
	if called {
		t.Error("Key callback must not be invoked for the nil UUID")
	}
	if ShouldVerify(tokenString, "https://example.com/") {
		t.Error("ShouldVerify must return false for the nil UUID kid")
	}
}

func TestVerifyIssuedAtValidation(t *testing.T) {
	keyID := "123e4567-e89b-12d3-a456-426614174000"
	tests := []struct {
		name    string
		mutate  func(c jwt.MapClaims)
		wantErr bool
	}{
		{"present and valid", func(c jwt.MapClaims) {}, false},
		{"missing", func(c jwt.MapClaims) { delete(c, "iat") }, true},
		{"empty string", func(c jwt.MapClaims) { c["iat"] = "" }, true},
		{"non-numeric string", func(c jwt.MapClaims) { c["iat"] = "yesterday" }, true},
		{"null", func(c jwt.MapClaims) { c["iat"] = nil }, true},
		{"boolean", func(c jwt.MapClaims) { c["iat"] = true }, true},
		{"in the future", func(c jwt.MapClaims) { c["iat"] = time.Now().Add(time.Hour).Unix() }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := baseTestClaims(keyID)
			tt.mutate(claims)
			tokenString, pubKey := signTestToken(t, claims, keyID)

			_, err := Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, func(ctx context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
				return pubKey, nil
			})
			if tt.wantErr {
				if !isUnauthorizedBecause[*errors.ValidationError](err) {
					t.Errorf("Expected ValidationError, got %T: %v", err, err)
				}
			} else if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestVerifyAudience(t *testing.T) {
	keyID := "123e4567-e89b-12d3-a456-426614174000"
	tokenString, pubKey := signTestToken(t, baseTestClaims(keyID), keyID)
	keyFunc := func(ctx context.Context, _ uuid.UUID) (crypto.PublicKey, error) { return pubKey, nil }

	tests := []struct {
		name     string
		audience string
		wantErr  bool
	}{
		{"matching audience", "test-audience", false},
		{"different audience", "other-service", true},
		{"audience not configured", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/", Audience: tt.audience}, keyFunc)
			if tt.wantErr {
				if !isUnauthorizedBecause[*errors.ValidationError](err) {
					t.Errorf("Expected ValidationError, got %T: %v", err, err)
				}
			} else if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestVerifyErrorsDoNotEchoTokenContents(t *testing.T) {
	keyID := "123e4567-e89b-12d3-a456-426614174000"
	marker := "ATTACKER\nINJECTED-MARKER"

	badVersion := baseTestClaims(keyID)
	badVersion["ver"] = marker
	badIssuer := baseTestClaims(keyID)
	badIssuer["iss"] = marker

	for name, claims := range map[string]jwt.MapClaims{"version": badVersion, "issuer": badIssuer} {
		t.Run(name, func(t *testing.T) {
			tokenString, pubKey := signTestToken(t, claims, keyID)
			_, err := Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, func(ctx context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
				return pubKey, nil
			})
			if err == nil {
				t.Fatal("Expected error")
			}
			if strings.Contains(err.Error(), "INJECTED-MARKER") || strings.Contains(err.Error(), "\n") {
				t.Errorf("Error message must not echo token contents, got %q", err.Error())
			}
		})
	}
}

func TestVerifyMintedKeyIssuedAtAccepted(t *testing.T) {
	// NewJAPIKey must emit an iat that Verify accepts; the issuer is built to match the key ID
	result, err := NewJAPIKey(Config{Subject: "s", Issuer: "https://placeholder.example", Audience: "a", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(result.JWT, claims); err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	if err := validateIssuedAt(claims, time.Now()); err != nil {
		t.Errorf("Minted token has invalid iat: %v", err)
	}
}

// Expired and not-yet-valid tokens must not cause a key lookup.
func TestVerifyTimeClaimsRejectedBeforeKeyLookup(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c jwt.MapClaims)
		cause  func(error) bool
	}{
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, isUnauthorizedBecause[*errors.TokenExpiredError]},
		{"missing exp", func(c jwt.MapClaims) { delete(c, "exp") }, isUnauthorizedBecause[*errors.ValidationError]},
		{"non-numeric exp", func(c jwt.MapClaims) { c["exp"] = "tomorrow" }, isUnauthorizedBecause[*errors.ValidationError]},
		{"nbf in future", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, isUnauthorizedBecause[*errors.ValidationError]},
		{"non-numeric nbf", func(c jwt.MapClaims) { c["nbf"] = "soon" }, isUnauthorizedBecause[*errors.ValidationError]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := baseTestClaims(hardeningKeyID)
			tt.mutate(claims)
			tokenString, pubKey := signTestToken(t, claims, hardeningKeyID)

			var calls atomic.Int32
			_, err := Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, countingKeyFunc(pubKey, &calls))
			if !tt.cause(err) {
				t.Errorf("unexpected error %T: %v", err, err)
			}
			if n := calls.Load(); n != 0 {
				t.Errorf("key callback invoked %d times", n)
			}
			// ShouldVerify only routes tokens; it must keep accepting an expired one
			if tt.name == "expired" && !ShouldVerify(tokenString, "https://example.com/") {
				t.Error("ShouldVerify must not reject a token just for being expired")
			}
		})
	}
}

// iat tolerates small clock skew, but nothing else does.
func TestVerifyIssuedAtLeeway(t *testing.T) {
	tests := []struct {
		name    string
		offset  time.Duration
		wantErr bool
	}{
		{"now", 0, false},
		{"slightly ahead", 5 * time.Second, false},
		{"just inside leeway", IssuedAtLeeway - 5*time.Second, false},
		{"beyond leeway", IssuedAtLeeway + 10*time.Second, true},
		{"far future", time.Hour, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := baseTestClaims(hardeningKeyID)
			claims["iat"] = time.Now().Add(tt.offset).Unix()
			tokenString, pubKey := signTestToken(t, claims, hardeningKeyID)
			_, err := Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, mockKeyFunc(pubKey))
			if tt.wantErr {
				if !isUnauthorizedBecause[*errors.ValidationError](err) {
					t.Errorf("expected rejection, got %T: %v", err, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}

	// The leeway must not leak onto nbf or exp
	claims := baseTestClaims(hardeningKeyID)
	claims["nbf"] = time.Now().Add(5 * time.Second).Unix()
	tokenString, pubKey := signTestToken(t, claims, hardeningKeyID)
	if _, err := Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, mockKeyFunc(pubKey)); err == nil {
		t.Error("nbf 5s ahead was accepted: leeway must apply to iat only")
	}
	claims = baseTestClaims(hardeningKeyID)
	claims["exp"] = time.Now().Add(-5 * time.Second).Unix()
	tokenString, pubKey = signTestToken(t, claims, hardeningKeyID)
	if _, err := Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, mockKeyFunc(pubKey)); err == nil {
		t.Error("exp 5s ago was accepted: leeway must apply to iat only")
	}
}

// A token minted just now must verify on a host whose clock is a bit behind.
func TestVerifyIssuedAtLeewayAfterMint(t *testing.T) {
	k, err := NewJAPIKey(Config{Subject: "s", Issuer: "https://example.com", Audience: "a", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), k.JWT, VerifyConfig{BaseIssuerURL: "https://example.com"}, mockKeyFunc(k.PublicKey)); err != nil {
		t.Errorf("freshly minted key rejected: %v", err)
	}
}

func TestBaseIssuerURLPathCleanliness(t *testing.T) {
	tests := []struct {
		base  string
		valid bool
	}{
		{"https://example.com/keys", true},
		{"https://example.com/keys/", true},
		{"https://example.com/a/b/c", true},
		{"https://example.com/a-b_c.d", true},
		{"https://example.com//keys", false},
		{"https://example.com/a//b", false},
		{"https://example.com/./keys", false},
		{"https://example.com/keys/.", false},
		{"https://example.com/x/../keys", false},
		{"https://example.com/keys/..", false},
		{"https://example.com/k%65ys", false},
		{"https://example.com/a%2Fb", false},
		{"https://example.com/%2e%2e/keys", false},
	}
	for _, tt := range tests {
		t.Run(tt.base, func(t *testing.T) {
			err := validateBaseIssuerURL(tt.base, false)
			if tt.valid && err != nil {
				t.Errorf("rejected: %v", err)
			}
			if !tt.valid {
				if _, ok := err.(*errors.ValidationError); !ok {
					t.Errorf("accepted (err=%v)", err)
				}
			}
			if err != nil && strings.Contains(err.Error(), tt.base) {
				t.Errorf("error echoes input: %v", err)
			}
		})
	}
}

// Common "not found" sentinels returned unwrapped must be treated as a missing
// key (401), not an internal failure.
func TestVerifyCallbackStdlibNotFoundIsUnauthorized(t *testing.T) {
	tokenString, _, _, err := createValidToken()
	if err != nil {
		t.Fatal(err)
	}
	for name, cbErr := range map[string]error{
		"sql.ErrNoRows":         sql.ErrNoRows,
		"wrapped sql.ErrNoRows": fmt.Errorf("query: %w", sql.ErrNoRows),
		"fs.ErrNotExist":        fs.ErrNotExist,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, func(context.Context, uuid.UUID) (crypto.PublicKey, error) {
				return nil, cbErr
			})
			if !isUnauthorizedBecause[*errors.KeyNotFoundError](err) {
				t.Errorf("expected UnauthorizedError(KeyNotFoundError), got %T: %v", err, err)
			}
		})
	}
}

// A context that is already done must not start a lookup.
func TestVerifyCancelledContextDoesNotCallCallback(t *testing.T) {
	tokenString, pubKey, _, err := createValidToken()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var calls atomic.Int32
	_, err = Verify(ctx, tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, countingKeyFunc(pubKey, &calls))
	if _, ok := err.(*errors.DatabaseTimeoutError); !ok {
		t.Errorf("expected *DatabaseTimeoutError, got %T: %v", err, err)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("callback invoked %d times with a cancelled context", n)
	}
}

// A callback panic is reported as an InternalError, with the panic value and a
// stack logged but never returned.
func TestVerifyCallbackPanicIsLogged(t *testing.T) {
	tokenString, _, _, err := createValidToken()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	_, err = Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, func(context.Context, uuid.UUID) (crypto.PublicKey, error) {
		panic("kaboom-secret")
	})
	if _, ok := err.(*errors.InternalError); !ok {
		t.Fatalf("expected *InternalError, got %T: %v", err, err)
	}
	if strings.Contains(err.Error(), "kaboom-secret") {
		t.Errorf("panic value leaked into the returned error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "kaboom-secret") || !strings.Contains(out, "goroutine") {
		t.Errorf("expected panic value and stack in the log, got %q", out)
	}
}

// Tokens whose header carries "crit" must be rejected without a lookup.
func TestVerifyRejectsCritHeader(t *testing.T) {
	claims := baseTestClaims(hardeningKeyID)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = hardeningKeyID
	token.Header["crit"] = []string{"x-unknown"}
	token.Header["x-unknown"] = 1
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	tokenString, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	_, err = Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, countingKeyFunc(pub, &calls))
	if !isUnauthorizedBecause[*errors.ValidationError](err) {
		t.Errorf("expected UnauthorizedError(ValidationError), got %T: %v", err, err)
	}
	if calls.Load() != 0 {
		t.Error("callback invoked for a token with a crit header")
	}
	if ShouldVerify(tokenString, "https://example.com/") {
		t.Error("ShouldVerify accepted a token with a crit header")
	}
}
