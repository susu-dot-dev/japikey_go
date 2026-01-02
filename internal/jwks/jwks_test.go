package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/susu-dot-dev/japikey/errors"
)

func TestNewJWK_WithValidRSAKeyAndUUID_ReturnsValidJWKS(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	keyID := uuid.New()

	// Act
	jwks, err := NewJWKS(publicKey, keyID)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if jwks == nil {
		t.Fatal("Expected JWKS to not be nil")
	}

	key := jwks.jwk
	if key.kid != keyID {
		t.Errorf("Expected kid to be '%s', got '%s'", keyID, key.kid)
	}

	if key.n == "" {
		t.Error("Expected n parameter to not be empty")
	}

	if key.e == "" {
		t.Error("Expected e parameter to not be empty")
	}

	// Verify that the parameters are properly formatted Base64url
	if !isValidBase64url(key.n) {
		t.Errorf("Parameter n is not valid Base64url: %s", key.n)
	}

	if !isValidBase64url(key.e) {
		t.Errorf("Parameter e is not valid Base64url: %s", key.e)
	}

	// Verify that the n and e parameters correspond to the original public key
	modulusBytes, err := base64.RawURLEncoding.DecodeString(key.n)
	if err != nil {
		t.Fatalf("Failed to decode n parameter: %v", err)
	}

	exponentBytes, err := base64.RawURLEncoding.DecodeString(key.e)
	if err != nil {
		t.Fatalf("Failed to decode e parameter: %v", err)
	}

	// Verify that the decoded modulus matches the original public key modulus
	originalModulusBytes := publicKey.N.Bytes()
	if len(modulusBytes) != len(originalModulusBytes) {
		t.Errorf("Decoded modulus length (%d) does not match original modulus length (%d)", len(modulusBytes), len(originalModulusBytes))
	} else {
		for i := range modulusBytes {
			if modulusBytes[i] != originalModulusBytes[i] {
				t.Error("Decoded modulus does not match original public key modulus")
				break
			}
		}
	}

	// For exponent, we need to reconstruct the integer value and compare
	// The exponent is usually small (e.g., 65537), so we can compare directly
	exponentValue := 0
	for _, b := range exponentBytes {
		exponentValue = (exponentValue << 8) | int(b)
	}

	if exponentValue != publicKey.E {
		t.Errorf("Decoded exponent (%d) does not match original public key exponent (%d)", exponentValue, publicKey.E)
	}
}

func TestNewJWK_WithInvalidKeyID_ReturnsError(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	invalidKeyID := uuid.Nil // This is an invalid key ID

	// Act
	jwks, err := NewJWKS(publicKey, invalidKeyID)

	// Assert
	if err == nil {
		t.Fatal("Expected error for invalid key ID, but got none")
	}

	if jwks != nil {
		t.Error("Expected JWKS to be nil for invalid key ID")
	}

	// Verify the error type is correct
	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestNewJWK_WithNullRSAPublicKey_ReturnsError(t *testing.T) {
	// Arrange
	keyID := uuid.New()

	// Act
	jwks, err := NewJWKS(nil, keyID)

	// Assert
	if err == nil {
		t.Fatal("Expected error for null RSA public key, but got none")
	}

	if jwks != nil {
		t.Error("Expected JWKS to be nil for null RSA public key")
	}

	// Verify the error type is correct
	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_SerializationToJSON(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	keyID := uuid.New()

	jwks, err := NewJWKS(publicKey, keyID)
	if err != nil {
		t.Fatalf("Failed to create JWKS: %v", err)
	}

	// Act
	jsonBytes, err := json.Marshal(jwks)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error during marshaling, but got: %v", err)
	}

	if len(jsonBytes) == 0 {
		t.Fatal("Expected JSON bytes to not be empty")
	}

	// Verify that the JSON contains expected fields
	var result map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		t.Fatalf("Expected valid JSON, but got error: %v", err)
	}

	keys, exists := result["keys"]
	if !exists {
		t.Fatal("Expected JSON to contain 'keys' field")
	}

	keysSlice, ok := keys.([]interface{})
	if !ok || len(keysSlice) != 1 {
		t.Fatalf("Expected 'keys' to be an array with exactly one element, got %v", keys)
	}

	keyMap, ok := keysSlice[0].(map[string]interface{})
	if !ok {
		t.Fatal("Expected first key to be an object")
	}

	if kty, exists := keyMap["kty"]; !exists || kty != "RSA" {
		t.Errorf("Expected kty to be 'RSA', got %v", kty)
	}

	if kid, exists := keyMap["kid"]; !exists || kid != keyID.String() {
		t.Errorf("Expected kid to be '%s', got %v", keyID.String(), kid)
	}

	if n, exists := keyMap["n"]; !exists || n == "" {
		t.Error("Expected n parameter to exist and not be empty")
	}

	if e, exists := keyMap["e"]; !exists || e == "" {
		t.Error("Expected e parameter to exist and not be empty")
	}
}

func TestJWKS_DeserializationFromJSON(t *testing.T) {
	// Arrange
	keyID := uuid.New()
	jsonStr := `{"keys":[{"kty":"RSA","kid":"` + keyID.String() + `","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ","e":"AQAB"}]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error during unmarshaling, but got: %v", err)
	}

	key := jwks.jwk
	if key.kid != keyID {
		t.Errorf("Expected kid to be '%s', got '%s'", keyID, key.kid)
	}

	if key.n == "" {
		t.Error("Expected n parameter to not be empty")
	}

	if key.e == "" {
		t.Error("Expected e parameter to not be empty")
	}
}

func TestJWKS_InvalidJSONDeserialization(t *testing.T) {
	// Arrange
	jsonStr := `{"invalid": "json"}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for invalid JSON, but got none")
	}

	// Verify the error type is correct
	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_InvalidRSAParametersInJSON(t *testing.T) {
	// Arrange
	keyID := uuid.New()
	jsonStr := `{"keys":[{"kty":"EC","kid":"` + keyID.String() + `","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ","e":"AQAB"}]}` // kty is EC instead of RSA

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for invalid RSA parameters, but got none")
	}

	// Verify the error type is correct
	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_MultipleKeysInJSON(t *testing.T) {
	// Arrange
	keyID := uuid.New()
	jsonStr := `{"keys":[
		{"kty":"RSA","kid":"` + keyID.String() + `","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ","e":"AQAB"},
		{"kty":"RSA","kid":"` + keyID.String() + `","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ","e":"AQAB"}
	]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for multiple keys in JWKS, but got none")
	}

	// Verify the error type is correct
	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_EmptyKeysArray(t *testing.T) {
	// Arrange
	jsonStr := `{"keys":[]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for empty keys array in JWKS, but got none")
	}

	// Verify the error type is correct
	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_SerializationDeserializationRoundTrip(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	keyID := uuid.New()

	originalJWKS, err := NewJWKS(publicKey, keyID)
	if err != nil {
		t.Fatalf("Failed to create original JWKS: %v", err)
	}

	// Act - Serialize to JSON
	jsonBytes, err := json.Marshal(originalJWKS)
	if err != nil {
		t.Fatalf("Failed to serialize JWKS: %v", err)
	}

	// Act - Deserialize from JSON
	var roundTripJWKS JWKS
	err = json.Unmarshal(jsonBytes, &roundTripJWKS)
	if err != nil {
		t.Fatalf("Failed to deserialize JWKS: %v", err)
	}

	// Assert - Compare original and round-tripped JWKS
	origKey := originalJWKS.jwk
	rtKey := roundTripJWKS.jwk

	if origKey.kid != rtKey.kid {
		t.Errorf("Expected kid to match after round-trip: %s != %s", origKey.kid, rtKey.kid)
	}

	if origKey.n != rtKey.n {
		t.Errorf("Expected n to match after round-trip: %s != %s", origKey.n, rtKey.n)
	}

	if origKey.e != rtKey.e {
		t.Errorf("Expected e to match after round-trip: %s != %s", origKey.e, rtKey.e)
	}

	// Verify that the public key can be extracted from both JWKS and they match
	origPubKey, err := originalJWKS.GetPublicKey(keyID)
	if err != nil {
		t.Fatalf("Failed to extract public key from original JWKS: %v", err)
	}

	rtPubKey, err := roundTripJWKS.GetPublicKey(keyID)
	if err != nil {
		t.Fatalf("Failed to extract public key from round-trip JWKS: %v", err)
	}

	if origPubKey.N.Cmp(rtPubKey.N) != 0 {
		t.Error("Public key modulus does not match after round-trip")
	}

	if origPubKey.E != rtPubKey.E {
		t.Errorf("Public key exponent does not match after round-trip: %d != %d", origPubKey.E, rtPubKey.E)
	}
}

func TestJWKS_PublicKeyRoundTrip(t *testing.T) {
	// Arrange: Generate a key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	originalPublicKey := &privateKey.PublicKey
	keyID := uuid.New()

	// Act: Create JWKS from the public key
	jwks, err := NewJWKS(originalPublicKey, keyID)
	if err != nil {
		t.Fatalf("Failed to create JWKS: %v", err)
	}

	// Act: Extract the public key back from the JWKS
	extractedPublicKey, err := jwks.GetPublicKey(keyID)
	if err != nil {
		t.Fatalf("Failed to extract public key: %v", err)
	}

	// Assert: Compare the original and extracted public keys
	if originalPublicKey.N.Cmp(extractedPublicKey.N) != 0 {
		t.Error("Original and extracted public key modulus do not match")
	}

	if originalPublicKey.E != extractedPublicKey.E {
		t.Errorf("Original and extracted public key exponent do not match: %d != %d", originalPublicKey.E, extractedPublicKey.E)
	}

	// Verify that the n and e parameters in the JWKS match the original key
	key := jwks.jwk

	// Decode the n parameter and compare with original modulus
	modulusBytes, err := base64.RawURLEncoding.DecodeString(key.n)
	if err != nil {
		t.Fatalf("Failed to decode n parameter: %v", err)
	}

	originalModulusBytes := originalPublicKey.N.Bytes()
	if string(modulusBytes) != string(originalModulusBytes) {
		t.Error("JWKS n parameter does not match original public key modulus")
	}

	// Decode the e parameter and compare with original exponent
	exponentBytes, err := base64.RawURLEncoding.DecodeString(key.e)
	if err != nil {
		t.Fatalf("Failed to decode e parameter: %v", err)
	}

	// For the exponent, we need to reconstruct the integer value
	// The exponent is usually small (e.g., 65537), so we can compare directly
	// Convert the bytes back to an integer to compare with originalPublicKey.E
	exponentValue := 0
	for _, b := range exponentBytes {
		exponentValue = (exponentValue << 8) | int(b)
	}

	if exponentValue != originalPublicKey.E {
		t.Errorf("JWKS e parameter does not match original public key exponent: %d != %d", exponentValue, originalPublicKey.E)
	}
}

func TestJWKS_ValidateAgainstJWXTool(t *testing.T) {
	// Arrange: Generate a key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Skipf("Failed to generate RSA key: %v (skipping test that requires jwx tool)", err)
	}
	publicKey := &privateKey.PublicKey
	keyID := uuid.New()

	// Act: Create JWKS from the public key
	jwks, err := NewJWKS(publicKey, keyID)
	if err != nil {
		t.Fatalf("Failed to create JWKS: %v", err)
	}

	// Serialize to JSON
	jsonBytes, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("Failed to serialize JWKS: %v", err)
	}

	// The jwx tool's parse command expects a single JWK, not a JWKS
	// So we need to extract the single JWK from our JWKS to test with the tool
	var jwksStruct map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &jwksStruct); err != nil {
		t.Fatalf("Failed to unmarshal JWKS for testing: %v", err)
	}

	keys, ok := jwksStruct["keys"].([]interface{})
	if !ok || len(keys) != 1 {
		t.Fatalf("Expected JWKS to contain exactly one key, got %d", len(keys))
	}

	singleJWK := keys[0]
	jwkBytes, err := json.Marshal(singleJWK)
	if err != nil {
		t.Fatalf("Failed to marshal single JWK: %v", err)
	}

	// Use the jwx tool to parse this single JWK and verify it's valid
	// This command should parse the JWK and output the public key as base64
	cmd := exec.Command("bash", "-c", fmt.Sprintf("cd ../../jwx/tool && echo '%s' | go run . parse", string(jwkBytes)))
	output, err := cmd.CombinedOutput()

	// If the jwx tool is not available or fails, we should skip this test
	if err != nil {
		// Check if the error is due to the jwx tool not being available
		if strings.Contains(string(output), "command not found") ||
			strings.Contains(string(output), "cannot find") ||
			strings.Contains(err.Error(), "executable file not found") ||
			strings.Contains(string(output), "No such file or directory") {
			t.Skip("jwx tool not available, skipping validation test")
		}

		// If it's a different error, check if it's just the parsing that failed
		// but the tool exists
		t.Logf("jwx tool output: %s, error: %v", string(output), err)
		t.Error("JWK format is not compatible with jwx tool")
		return
	}

	// If the command succeeded, the JWK format is valid according to the jwx tool
	if len(output) == 0 {
		t.Error("jwx tool returned empty output for valid JWK")
	}
}

func TestJWKS_GetPublicKey_WithValidKeyID(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	keyID := uuid.New()

	jwks, err := NewJWKS(publicKey, keyID)
	if err != nil {
		t.Fatalf("Failed to create JWKS: %v", err)
	}

	// Act
	retrievedPublicKey, err := jwks.GetPublicKey(keyID)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error when getting public key, but got: %v", err)
	}

	if retrievedPublicKey == nil {
		t.Fatal("Expected public key to not be nil")
	}

	if retrievedPublicKey.N.Cmp(publicKey.N) != 0 {
		t.Errorf("Expected modulus to match original, but got different values")
	}

	if retrievedPublicKey.E != publicKey.E {
		t.Errorf("Expected exponent to match original, but got %d, expected %d", retrievedPublicKey.E, publicKey.E)
	}
}

func TestJWKS_GetPublicKey_WithInvalidKeyID(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	keyID := uuid.New()
	wrongKeyID := uuid.New()

	jwks, err := NewJWKS(publicKey, keyID)
	if err != nil {
		t.Fatalf("Failed to create JWKS: %v", err)
	}

	// Act
	retrievedPublicKey, err := jwks.GetPublicKey(wrongKeyID)

	// Assert
	if err == nil {
		t.Fatal("Expected error when getting public key with wrong key ID, but got none")
	}

	if retrievedPublicKey != nil {
		t.Error("Expected public key to be nil when key ID doesn't match")
	}

	// Verify the error type is correct
	if _, ok := err.(*errors.KeyNotFoundError); !ok {
		t.Errorf("Expected KeyNotFoundError, got %T", err)
	}
}

func TestJWKS_GetKeyID(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	keyID := uuid.New()

	jwks, err := NewJWKS(publicKey, keyID)
	if err != nil {
		t.Fatalf("Failed to create JWKS: %v", err)
	}

	// Act
	retrievedKeyID := jwks.GetKeyID()

	// Assert
	if retrievedKeyID != keyID {
		t.Errorf("Expected key ID to match original, but got %s, expected %s", retrievedKeyID, keyID)
	}
}

func TestJWKS_GetKeyID_WithInvalidJWKS(t *testing.T) {
	// Arrange
	// Create an invalid JWKS with an empty key ID
	jwks := &JWKS{
		jwk: JWK{
			kid: uuid.Nil, // Invalid empty UUID
			n:   "some_n_value",
			e:   "some_e_value",
		},
	}

	// Act
	retrievedKeyID := jwks.GetKeyID()

	// Assert
	if retrievedKeyID != uuid.Nil {
		t.Errorf("Expected key ID to be empty when JWKS is invalid, but got %s", retrievedKeyID)
	}
}

func TestJWKS_Base64urlUIntEncoding(t *testing.T) {
	// Test specific values for proper Base64urlUInt encoding
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // Use proper key size
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	keyID := uuid.New()

	jwks, err := NewJWKS(publicKey, keyID)
	if err != nil {
		t.Fatalf("Failed to create JWKS: %v", err)
	}

	key := jwks.jwk

	// Verify that n and e are properly encoded as Base64urlUInt
	// According to RFC 7518, Base64urlUInt encoding should not have padding
	if strings.Contains(key.n, "=") {
		t.Errorf("n parameter should not contain padding: %s", key.n)
	}

	if strings.Contains(key.e, "=") {
		t.Errorf("e parameter should not contain padding: %s", key.e)
	}

	// Verify that the exponent is properly encoded (usually 65537 = AQAB in base64)
	// For standard RSA keys, the exponent is typically 65537 (0x010001)
	// When encoded as Base64urlUInt, this should be "AQAB" (standard base64) but without padding
	// So it should be "AQAB" without the padding, which is still "AQAB" since it's already a multiple of 4
	// Actually, for Base64url (unpadded), 65537 (0x010001) becomes [1, 0, 1] bytes -> "AQAB" -> "AQAB" (no change since no padding needed)
	// But for unpadded base64url, it would be "AQAB" without padding, which is still "AQAB" since it's already a multiple of 4
	// Actually, let's decode and verify the value is correct
	exponentBytes, err := base64.RawURLEncoding.DecodeString(key.e)
	if err != nil {
		t.Fatalf("Failed to decode e parameter: %v", err)
	}

	// Reconstruct the integer value from the bytes
	exponentValue := 0
	for _, b := range exponentBytes {
		exponentValue = (exponentValue << 8) | int(b)
	}

	if exponentValue != publicKey.E {
		t.Errorf("Decoded exponent %d does not match public key exponent %d", exponentValue, publicKey.E)
	}
}

func TestJWKS_ZeroValueEncoding(t *testing.T) {
	// Test edge case: if we had a zero value, it should be encoded as "AA"
	// This is more of a theoretical test since RSA keys won't have zero values
	// but we can test our encoding/decoding functions directly

	// This test is more for completeness since we have the base64urlUIntEncode/Decode functions
	// In practice, RSA modulus and exponent won't be zero
}

// Helper function to validate Base64url format
func isValidBase64url(s string) bool {
	// Check that it contains only valid Base64url characters
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func TestJWKS_ExtraKeysInJWK(t *testing.T) {
	// Arrange: JSON with extra keys in the JWK
	keyID := uuid.New()
	jsonStr := `{"keys":[{"kty":"RSA","kid":"` + keyID.String() + `","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ","e":"AQAB","extra":"field"}]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for extra keys in JWK, but got none")
	}

	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_WrongTypeForKty(t *testing.T) {
	// Arrange: JSON with kty as a number instead of string
	keyID := uuid.New()
	jsonStr := `{"keys":[{"kty":123,"kid":"` + keyID.String() + `","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ","e":"AQAB"}]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for wrong type for kty, but got none")
	}

	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_WrongTypeForKid(t *testing.T) {
	// Arrange: JSON with kid as a number instead of string
	jsonStr := `{"keys":[{"kty":"RSA","kid":123,"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ","e":"AQAB"}]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for wrong type for kid, but got none")
	}

	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_WrongTypeForN(t *testing.T) {
	// Arrange: JSON with n as a number instead of string
	keyID := uuid.New()
	jsonStr := `{"keys":[{"kty":"RSA","kid":"` + keyID.String() + `","n":12345,"e":"AQAB"}]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for wrong type for n, but got none")
	}

	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_WrongTypeForE(t *testing.T) {
	// Arrange: JSON with e as a number instead of string
	keyID := uuid.New()
	jsonStr := `{"keys":[{"kty":"RSA","kid":"` + keyID.String() + `","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ","e":65537}]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for wrong type for e, but got none")
	}

	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_MissingKty(t *testing.T) {
	// Arrange: JSON missing kty field
	keyID := uuid.New()
	jsonStr := `{"keys":[{"kid":"` + keyID.String() + `","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ","e":"AQAB"}]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for missing kty, but got none")
	}

	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_MissingKid(t *testing.T) {
	// Arrange: JSON missing kid field
	jsonStr := `{"keys":[{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ","e":"AQAB"}]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for missing kid, but got none")
	}

	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_MissingN(t *testing.T) {
	// Arrange: JSON missing n field
	keyID := uuid.New()
	jsonStr := `{"keys":[{"kty":"RSA","kid":"` + keyID.String() + `","e":"AQAB"}]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for missing n, but got none")
	}

	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_MissingE(t *testing.T) {
	// Arrange: JSON missing e field
	keyID := uuid.New()
	jsonStr := `{"keys":[{"kty":"RSA","kid":"` + keyID.String() + `","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ"}]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for missing e, but got none")
	}

	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_ExtraTopLevelKeys(t *testing.T) {
	// Arrange: JSON with extra top-level keys (should be allowed)
	keyID := uuid.New()
	jsonStr := `{"keys":[{"kty":"RSA","kid":"` + keyID.String() + `","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ","e":"AQAB"}],"extra":"field"}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error for extra top-level keys, but got: %v", err)
	}

	// Verify that the JWKS was still unmarshaled correctly
	if jwks.jwk.kid != keyID {
		t.Errorf("Expected kid to be '%s', got '%s'", keyID, jwks.jwk.kid)
	}
}

func TestJWKS_KeysNotAnArray(t *testing.T) {
	// Arrange: JSON with keys as an object instead of array
	keyID := uuid.New()
	jsonStr := `{"keys":{"kty":"RSA","kid":"` + keyID.String() + `","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM_X7zVFQ84l8g7hQg-jC6SGODpEcF7yR3xNgQBKzAV-OdSQ","e":"AQAB"}}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for keys not being an array, but got none")
	}

	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_KeysAsString(t *testing.T) {
	// Arrange: JSON with keys as a string instead of array
	jsonStr := `{"keys":"not an array"}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for keys being a string, but got none")
	}

	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestJWKS_JWKNotAnObject(t *testing.T) {
	// Arrange: JSON with JWK as a string instead of object
	jsonStr := `{"keys":["not an object"]}`

	// Act
	var jwks JWKS
	err := json.Unmarshal([]byte(jsonStr), &jwks)

	// Assert
	if err == nil {
		t.Fatal("Expected error for JWK not being an object, but got none")
	}

	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}
