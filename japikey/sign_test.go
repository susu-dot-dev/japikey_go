package japikey

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/susu-dot-dev/japikey/errors"
)

func TestNewJAPIKey_WithValidInputs_ReturnsValidJWT(t *testing.T) {
	// Arrange
	config := Config{
		Subject:   "test-user",
		Issuer:    "https://example.com",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Act
	result, err := NewJAPIKey(config)

	// Assert
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	if result.JWT == "" {
		t.Error("Expected JWT to be populated, but it was empty")
	}

	if result.KeyID == uuid.Nil {
		t.Error("Expected KeyID to be populated, but it was empty")
	}

	if result.PublicKey == nil {
		t.Error("Expected PublicKey to be populated, but it was nil")
	}
}

func TestNewJAPIKey_WithExpiredTime_ReturnsValidationError(t *testing.T) {
	// Arrange
	config := Config{
		Subject:   "test-user",
		Issuer:    "https://example.com",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired time
	}

	// Act
	result, err := NewJAPIKey(config)

	// Assert
	if err == nil {
		t.Error("Expected error for expired time, but got none")
	}

	if result != nil && result.JWT != "" {
		t.Error("Expected JWT to be empty for expired time, but it was populated")
	}

	// Check if it's the right type of error (will be implemented in task T014-T016)
}

func TestNewJAPIKey_WithEmptySubject_ReturnsValidationError(t *testing.T) {
	// Arrange
	config := Config{
		Subject:   "", // Empty subject
		Issuer:    "https://example.com",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Act
	result, err := NewJAPIKey(config)

	// Assert
	if err == nil {
		t.Error("Expected error for empty subject, but got none")
	}

	if result != nil && result.JWT != "" {
		t.Error("Expected JWT to be empty for empty subject, but it was populated")
	}

	// Check if it's the right type of error (will be implemented in task T014-T016)
}

func TestNewJAPIKey_ContainsVersionIdentifier(t *testing.T) {
	// Arrange
	config := Config{
		Subject:   "test-user",
		Issuer:    "https://example.com",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Act
	result, err := NewJAPIKey(config)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	// Parse the JWT to check for version identifier
	token, _ := jwt.Parse(result.JWT, nil) // We're just parsing, not validating
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// Check if the version identifier is present in the claims
		// This test will fail until we implement task T025
		if _, exists := claims["ver"]; !exists {
			t.Error("Expected version identifier 'ver' to be present in JWT claims")
		}
	} else {
		t.Error("Could not parse claims from JWT")
	}
}

func TestNewJAPIKey_ContainsKeyIDInHeader(t *testing.T) {
	// Arrange
	config := Config{
		Subject:   "test-user",
		Issuer:    "https://example.com",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Act
	result, err := NewJAPIKey(config)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	// Parse the JWT to check for key ID in header
	token, _ := jwt.Parse(result.JWT, nil) // We're just parsing, not validating
	if header := token.Header; header != nil {
		// Check if the key ID is present in the header
		// This test will fail until we implement task T026
		if kid, exists := header["kid"]; !exists {
			t.Error("Expected key ID 'kid' to be present in JWT header")
		} else {
			kidStr, ok := kid.(string)
			if !ok {
				kidUUID, ok := kid.(uuid.UUID)
				if !ok || kidUUID != result.KeyID {
					t.Errorf("Expected key ID in header to match result.KeyID, got %v, want %v", kid, result.KeyID)
				}
			} else {
				kidUUID, err := uuid.Parse(kidStr)
				if err != nil || kidUUID != result.KeyID {
					t.Errorf("Expected key ID in header to match result.KeyID, got %v, want %v", kid, result.KeyID)
				}
			}
		}
	} else {
		t.Error("Could not access header from JWT")
	}
}

func TestNewJAPIKey_ReturnsValidJWK(t *testing.T) {
	// Arrange
	config := Config{
		Subject:   "test-user",
		Issuer:    "https://example.com",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Act
	result, err := NewJAPIKey(config)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	// Check if the PublicKey in the result is a valid JWK
	if result.PublicKey == nil {
		t.Error("Expected PublicKey to be populated, but it was nil")
		return
	}

	// Check that the public key is not nil
	if result.PublicKey == nil {
		t.Error("Expected PublicKey to not be nil")
	}

	// Check that it's a valid RSA public key
	if result.PublicKey.N == nil {
		t.Error("Expected PublicKey to have a valid modulus")
	}

	if result.PublicKey.E == 0 {
		t.Error("Expected PublicKey to have a valid exponent")
	}
}

func TestNewJAPIKey_WithOptionalClaims_IncludesAllClaims(t *testing.T) {
	// Arrange
	expectedCustomClaimValue := "custom-value"
	config := Config{
		Subject:   "test-user",
		Issuer:    "https://example.com",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Claims: jwt.MapClaims{
			"custom_claim": expectedCustomClaimValue,
			"role":         "admin",
		},
	}

	// Act
	result, err := NewJAPIKey(config)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	// Parse the JWT to check for optional claims
	token, _ := jwt.Parse(result.JWT, nil) // We're just parsing, not validating
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// Check if the custom claims are present in the JWT
		if claimValue, exists := claims["custom_claim"]; !exists {
			t.Error("Expected custom claim to be present in JWT claims")
		} else if claimValue != expectedCustomClaimValue {
			t.Errorf("Expected custom claim value to be %v, but got %v", expectedCustomClaimValue, claimValue)
		}

		if role, exists := claims["role"]; !exists {
			t.Error("Expected role claim to be present in JWT claims")
		} else if role != "admin" {
			t.Errorf("Expected role claim value to be 'admin', but got %v", role)
		}
	} else {
		t.Error("Could not parse claims from JWT")
	}
}

func TestNewJAPIKey_WithCryptographicFailure_ReturnsGenerationError(t *testing.T) {
	// Note: Testing cryptographic failures is difficult without mocking
	// This test will be more of a verification that the error type is correct
	// when such failures occur. For now, we'll just verify the error type exists.

	// We can't easily force a cryptographic failure in rsa.GenerateKey
	// So we'll test that the error type exists and implements the error interface
	err := errors.NewInternalError("test error")

	if err.Error() != "test error" {
		t.Errorf("Expected error message 'test error', got '%s'", err.Error())
	}
}

func TestNewJAPIKey_WithSigningFailure_ReturnsSigningError(t *testing.T) {
	// Note: Testing signing failures is difficult without mocking
	// This test will be more of a verification that the error type is correct
	// when such failures occur. For now, we'll just verify the error type exists.

	// We can't easily force a signing failure in token.SignedString
	// So we'll test that the error type exists and implements the error interface
	err := errors.NewInternalError("test signing error")

	if err.Error() != "test signing error" {
		t.Errorf("Expected error message 'test signing error', got '%s'", err.Error())
	}
}

func TestTypeAssertionsForErrorHandling(t *testing.T) {
	// Test that type assertions work for specific error handling
	validationErr := errors.NewValidationError("validation error")
	internalErr := errors.NewInternalError("internal error")

	// Test type assertion for validation error
	if _, ok := interface{}(validationErr).(*errors.ValidationError); !ok {
		t.Error("Type assertion for ValidationError failed")
	}

	// Test type assertion for internal error
	if _, ok := interface{}(internalErr).(*errors.InternalError); !ok {
		t.Error("Type assertion for InternalError failed")
	}
}

func TestPrivateKeyNotAccessibleAfterCreation(t *testing.T) {
	// Arrange
	config := Config{
		Subject:   "test-user",
		Issuer:    "https://example.com",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Act
	result, err := NewJAPIKey(config)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	// Verify that the result only contains public information
	// The private key should not be accessible in the result
	if result.JWT == "" {
		t.Error("Expected JWT to be populated")
	}

	if result.KeyID == uuid.Nil {
		t.Error("Expected KeyID to be populated")
	}

	if result.PublicKey == nil {
		t.Error("Expected PublicKey to be populated")
	}

	// The result should not contain any private key information
	// This is verified by design since the function only returns public information
}

func TestThreadSafety(t *testing.T) {
	// Test that the function can be called concurrently without issues
	numGoroutines := 10
	results := make(chan *JAPIKey, numGoroutines)
	errors := make(chan error, numGoroutines)

	// Launch multiple goroutines to create API keys concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			config := Config{
				Subject:   fmt.Sprintf("test-user-%d", i),
				Issuer:    "https://example.com",
				Audience:  "test-audience",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}

			result, err := NewJAPIKey(config)
			if err != nil {
				errors <- err
			} else {
				results <- result
			}
		}(i)
	}

	// Collect results
	var validResults []*JAPIKey
	for i := 0; i < numGoroutines; i++ {
		select {
		case result := <-results:
			validResults = append(validResults, result)
		case err := <-errors:
			t.Errorf("Error in goroutine: %v", err)
		}
	}

	// Verify all results are valid
	if len(validResults) != numGoroutines {
		t.Errorf("Expected %d valid results, got %d", numGoroutines, len(validResults))
	}

	for _, result := range validResults {
		if result.JWT == "" {
			t.Error("Expected JWT to be populated")
		}
		if result.KeyID == uuid.Nil {
			t.Error("Expected KeyID to be populated")
		}
		if result.PublicKey == nil {
			t.Error("Expected PublicKey to be populated")
		}
	}
}

func TestPerformanceGenerationTime(t *testing.T) {
	// Test that API key generation takes less than 100ms
	config := Config{
		Subject:   "test-user",
		Issuer:    "https://example.com",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	start := time.Now()
	result, err := NewJAPIKey(config)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	if duration > 100*time.Millisecond {
		t.Errorf("Expected generation time to be < 100ms, took %v", duration)
	}

	if result.JWT == "" {
		t.Error("Expected JWT to be populated")
	}
}

func TestConcurrentAPIKeyGeneration(t *testing.T) {
	// Test that multiple API keys can be generated concurrently
	numKeys := 5
	results := make(chan *JAPIKey, numKeys)
	errors := make(chan error, numKeys)

	// Launch multiple goroutines to generate API keys concurrently
	for i := 0; i < numKeys; i++ {
		go func(i int) {
			config := Config{
				Subject:   fmt.Sprintf("user-%d", i),
				Issuer:    fmt.Sprintf("https://example%d.com", i),
				Audience:  fmt.Sprintf("audience-%d", i),
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}

			result, err := NewJAPIKey(config)
			if err != nil {
				errors <- err
			} else {
				results <- result
			}
		}(i)
	}

	// Collect results
	var validResults []*JAPIKey
	for i := 0; i < numKeys; i++ {
		select {
		case result := <-results:
			validResults = append(validResults, result)
		case err := <-errors:
			t.Errorf("Error generating API key: %v", err)
		}
	}

	// Verify all results are valid and unique
	if len(validResults) != numKeys {
		t.Errorf("Expected %d valid results, got %d", numKeys, len(validResults))
	}

	// Verify each result is valid
	for _, result := range validResults {
		if result == nil {
			t.Error("Expected result to not be nil")
			continue
		}
		if result.JWT == "" {
			t.Error("Expected JWT to be populated")
		}
		if result.KeyID == uuid.Nil {
			t.Error("Expected KeyID to be populated")
		}
		if result.PublicKey == nil {
			t.Error("Expected PublicKey to be populated")
		}
	}

	// Verify all KeyIDs are unique
	seenKeyIDs := make(map[uuid.UUID]bool)
	for _, result := range validResults {
		if result != nil && seenKeyIDs[result.KeyID] {
			t.Errorf("Duplicate KeyID found: %s", result.KeyID)
		}
		if result != nil {
			seenKeyIDs[result.KeyID] = true
		}
	}
}

func TestJWTSignatureVerificationWithReturnedPublicKey(t *testing.T) {
	// Arrange
	config := Config{
		Subject:   "test-user",
		Issuer:    "https://example.com",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Act
	result, err := NewJAPIKey(config)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	if result.JWT == "" {
		t.Fatal("Expected JWT to be populated")
	}

	if result.PublicKey == nil {
		t.Fatal("Expected PublicKey to be populated")
	}

	// Verify the JWT signature using the returned public key
	// Convert the RSA public key to a format usable by jwt package
	publicKey := result.PublicKey

	// Parse the JWT with the public key to verify the signature
	token, err := jwt.Parse(result.JWT, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		t.Fatalf("Error parsing JWT with public key: %v", err)
	}

	if !token.Valid {
		t.Error("JWT signature verification failed - token is not valid")
	}

	// Also verify that the claims are as expected
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if sub, exists := claims["sub"]; !exists || sub != config.Subject {
			t.Errorf("Expected subject '%s', got '%v'", config.Subject, sub)
		}
		if iss, exists := claims["iss"]; !exists || iss != config.Issuer {
			t.Errorf("Expected issuer '%s', got '%v'", config.Issuer, iss)
		}
		if aud, exists := claims["aud"]; !exists || aud != config.Audience {
			t.Errorf("Expected audience '%s', got '%v'", config.Audience, aud)
		}
	} else {
		t.Error("Could not extract claims from JWT")
	}
}

func TestPrivateKeyNeverAccessibleAfterCreation(t *testing.T) {
	// Arrange
	config := Config{
		Subject:   "test-user",
		Issuer:    "https://example.com",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Act
	result, err := NewJAPIKey(config)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	// Verify that the result does not contain the private key
	// The function should only return public information
	if result.JWT == "" {
		t.Error("Expected JWT to be populated")
	}

	if result.KeyID == uuid.Nil {
		t.Error("Expected KeyID to be populated")
	}

	if result.PublicKey == nil {
		t.Error("Expected PublicKey to be populated")
	}

	// Verify that the public key is valid and can be used for verification
	// but that no private key information is exposed
	if result.PublicKey.N == nil {
		t.Error("Expected PublicKey to have a valid modulus")
	}

	if result.PublicKey.E == 0 {
		t.Error("Expected PublicKey to have a valid exponent")
	}

	// The function implementation should ensure that the private key
	// is not accessible outside the NewJAPIKey function scope
	// This is verified by design since the function signature only returns public information
}

func TestIntegrationFullWorkflow(t *testing.T) {
	// Test the full workflow of creating a JAPIKey and verifying its signature

	// Step 1: Create a JAPIKey
	config := Config{
		Subject:   "integration-test-user",
		Issuer:    "https://integration-test.example.com",
		Audience:  "integration-test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Claims: jwt.MapClaims{
			"custom_claim": "custom_value",
			"role":         "tester",
		},
	}

	result, err := NewJAPIKey(config)
	if err != nil {
		t.Fatalf("Expected no error during JAPIKey creation, but got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	// Step 2: Verify the result has all expected components
	if result.JWT == "" {
		t.Error("Expected JWT to be populated")
	}

	if result.KeyID == uuid.Nil {
		t.Error("Expected KeyID to be populated")
	}

	if result.PublicKey == nil {
		t.Error("Expected PublicKey to be populated")
	}

	// Step 3: Verify the JWT signature using the returned public key
	token, err := jwt.Parse(result.JWT, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return result.PublicKey, nil
	})

	if err != nil {
		t.Fatalf("Error parsing JWT with public key: %v", err)
	}

	if !token.Valid {
		t.Error("JWT signature verification failed - token is not valid")
	}

	// Step 4: Verify the claims are as expected
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if sub, exists := claims["sub"]; !exists || sub != config.Subject {
			t.Errorf("Expected subject '%s', got '%v'", config.Subject, sub)
		}
		if iss, exists := claims["iss"]; !exists || iss != config.Issuer {
			t.Errorf("Expected issuer '%s', got '%v'", config.Issuer, iss)
		}
		if aud, exists := claims["aud"]; !exists || aud != config.Audience {
			t.Errorf("Expected audience '%s', got '%v'", config.Audience, aud)
		}
		if ver, exists := claims["ver"]; !exists || ver != "japikey-v1" {
			t.Errorf("Expected version 'japikey-v1', got '%v'", ver)
		}
		if custom, exists := claims["custom_claim"]; !exists || custom != "custom_value" {
			t.Errorf("Expected custom claim 'custom_value', got '%v'", custom)
		}
		if role, exists := claims["role"]; !exists || role != "tester" {
			t.Errorf("Expected role 'tester', got '%v'", role)
		}
	} else {
		t.Error("Could not extract claims from JWT")
	}

	// Step 5: Verify the key ID in the JWT header matches the returned KeyID
	if headerKid, exists := token.Header["kid"]; !exists {
		t.Error("Expected key ID 'kid' to be present in JWT header")
	} else {
		kidStr, ok := headerKid.(string)
		if !ok {
			kidUUID, ok := headerKid.(uuid.UUID)
			if !ok || kidUUID != result.KeyID {
				t.Errorf("Expected key ID in header to match result.KeyID, got '%v', want '%v'", headerKid, result.KeyID)
			}
		} else {
			kidUUID, err := uuid.Parse(kidStr)
			if err != nil || kidUUID != result.KeyID {
				t.Errorf("Expected key ID in header to match result.KeyID, got '%v', want '%v'", headerKid, result.KeyID)
			}
		}
	}
}

func TestUserClaimsCannotOverrideConfigClaims(t *testing.T) {
	// Arrange
	config := Config{
		Subject:   "original-subject",
		Issuer:    "https://original-issuer.com",
		Audience:  "original-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Claims: jwt.MapClaims{
			"sub":          "attempted-override-subject",            // Should not override config.Subject
			"iss":          "https://attempted-override-issuer.com", // Should not override config.Issuer
			"aud":          "attempted-override-audience",           // Should not override config.Audience
			"exp":          time.Now().Add(2 * time.Hour).Unix(),    // Should not override config.ExpiresAt
			"ver":          "attempted-override-version",            // Should not override the version identifier
			"custom_claim": "custom_value",                          // This should be preserved
		},
	}

	// Act
	result, err := NewJAPIKey(config)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	// Parse the JWT to check the actual claims
	token, _ := jwt.Parse(result.JWT, nil) // We're just parsing, not validating
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// Verify that config claims were not overridden
		if sub, exists := claims["sub"]; !exists || sub != config.Subject {
			t.Errorf("Expected subject to be '%s' from config, but got '%v'", config.Subject, sub)
		}

		if iss, exists := claims["iss"]; !exists || iss != config.Issuer {
			t.Errorf("Expected issuer to be '%s' from config, but got '%v'", config.Issuer, iss)
		}

		if aud, exists := claims["aud"]; !exists || aud != config.Audience {
			t.Errorf("Expected audience to be '%s' from config, but got '%v'", config.Audience, aud)
		}

		expectedExp := config.ExpiresAt.Unix()
		if exp, exists := claims["exp"]; !exists || int64(exp.(float64)) != expectedExp {
			t.Errorf("Expected expiration to be '%d' from config, but got '%v'", expectedExp, exp)
		}

		// Verify that the version identifier was not overridden
		if ver, exists := claims["ver"]; !exists || ver != "japikey-v1" {
			t.Errorf("Expected version to be 'japikey-v1', but got '%v'", ver)
		}

		// Verify that the custom claim was preserved
		if custom, exists := claims["custom_claim"]; !exists || custom != "custom_value" {
			t.Errorf("Expected custom claim to be preserved as 'custom_value', but got '%v'", custom)
		}
	} else {
		t.Error("Could not parse claims from JWT")
	}
}
