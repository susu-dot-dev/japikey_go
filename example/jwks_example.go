package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/susu-dot-dev/japikey"
)

func main() {
	fmt.Println("=== JWKS Example ===")
	fmt.Println()

	// Example 1: Create a JAPIKey and convert it to JWKS
	fmt.Println("Example 1: Creating JAPIKey and converting to JWKS")
	config := japikey.Config{
		Subject:   "user-123",
		Issuer:    "https://myapp.com",
		Audience:  "myapp-users",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	japikeyResult, err := japikey.NewJAPIKey(config)
	if err != nil {
		log.Fatalf("Failed to create JAPIKey: %v", err)
	}

	fmt.Printf("Created JAPIKey with KeyID: %s\n", japikeyResult.KeyID)

	// Convert JAPIKey to JWKS
	jwks, err := japikeyResult.ToJWKS()
	if err != nil {
		log.Fatalf("Failed to convert JAPIKey to JWKS: %v", err)
	}

	// Serialize JWKS to JSON
	jwksJSON, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JWKS: %v", err)
	}

	fmt.Println("JWKS JSON:")
	fmt.Println(string(jwksJSON))
	fmt.Println()

	// Example 2: Create JWKS directly from RSA public key
	fmt.Println("Example 2: Creating JWKS directly from RSA public key")
	keyID := japikeyResult.KeyID
	publicKey := japikeyResult.PublicKey

	jwks2, err := japikey.NewJWKS(publicKey, keyID)
	if err != nil {
		log.Fatalf("Failed to create JWKS: %v", err)
	}

	// Get the key ID from JWKS
	retrievedKeyID := jwks2.GetKeyID()
	fmt.Printf("Retrieved KeyID from JWKS: %s\n", retrievedKeyID)

	// Get the public key from JWKS
	retrievedPublicKey, err := jwks2.GetPublicKey(keyID)
	if err != nil {
		log.Fatalf("Failed to get public key from JWKS: %v", err)
	}

	fmt.Printf("Retrieved public key modulus size: %d bits\n", retrievedPublicKey.N.BitLen())
	fmt.Println()

	// Example 3: Deserialize JWKS from JSON
	fmt.Println("Example 3: Deserializing JWKS from JSON")
	jsonStr := string(jwksJSON)
	var jwks3 japikey.JWKS
	err = json.Unmarshal([]byte(jsonStr), &jwks3)
	if err != nil {
		log.Fatalf("Failed to unmarshal JWKS: %v", err)
	}

	// Verify the deserialized JWKS
	deserializedKeyID := jwks3.GetKeyID()
	fmt.Printf("Deserialized KeyID: %s\n", deserializedKeyID)

	if deserializedKeyID != keyID {
		log.Fatalf("KeyID mismatch: expected %s, got %s", keyID, deserializedKeyID)
	}

	deserializedPublicKey, err := jwks3.GetPublicKey(keyID)
	if err != nil {
		log.Fatalf("Failed to get public key from deserialized JWKS: %v", err)
	}

	if deserializedPublicKey.N.Cmp(publicKey.N) != 0 {
		log.Fatal("Public key modulus mismatch after deserialization")
	}

	if deserializedPublicKey.E != publicKey.E {
		log.Fatalf("Public key exponent mismatch: expected %d, got %d", publicKey.E, deserializedPublicKey.E)
	}

	fmt.Println("Successfully deserialized and verified JWKS!")
	fmt.Println()

	// Example 4: Error handling
	fmt.Println("Example 4: Error handling")
	var invalidJWKS japikey.JWKS
	invalidJSON := `{"keys":[{"kty":"RSA","kid":"invalid-uuid","n":"...","e":"..."}]}`
	err = json.Unmarshal([]byte(invalidJSON), &invalidJWKS)
	if err != nil {
		fmt.Printf("Expected error for invalid JSON: %v\n", err)
		if validationErr, ok := err.(*japikey.ValidationError); ok {
			fmt.Printf("Error type: ValidationError\n")
			fmt.Printf("Error message: %s\n", validationErr.Error())
		}
	}

	fmt.Println()
	fmt.Println("=== All examples completed successfully! ===")
}

