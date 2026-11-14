package main

import (
	"fmt"
	"log"
	"time"

	"github.com/susu-dot-dev/japikey"
)

func main() {
	// Create a config with required fields
	config := japikey.Config{
		Subject:   "user-123",
		Issuer:    "https://myapp.com",
		Audience:  "myapp-users",
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hours from now
	}

	// Generate the JAPIKey
	result, err := japikey.NewJAPIKey(config)
	if err != nil {
		// Handle error appropriately
		if validationErr, ok := err.(*japikey.ValidationError); ok {
			fmt.Printf("Validation error: %s\n", validationErr.Error())
		} else if internalErr, ok := err.(*japikey.InternalError); ok {
			fmt.Printf("Internal error: %s\n", internalErr.Error())
		}
		log.Fatal(err)
	}

	// Use the generated JWT and public key
	fmt.Printf("Generated JWT: %s\n", result.JWT)
	fmt.Printf("Key ID: %s\n", result.KeyID)
	fmt.Printf("Public Key: %+v\n", result.PublicKey)

	// Example with optional claims
	configWithClaims := japikey.Config{
		Subject:   "user-456",
		Issuer:    "https://myapp.com",
		Audience:  "myapp-users",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Claims: map[string]interface{}{
			"role":         "admin",
			"permissions":  []string{"read", "write"},
			"custom_field": "custom_value",
		},
	}

	result2, err := japikey.NewJAPIKey(configWithClaims)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("JWT with custom claims: %s\n", result2.JWT)
}
