package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
)

// JWKS represents the structure of a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents the structure of a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// GenerateExampleKeys generates an example RSA key pair and returns the public key as base64
func GenerateExampleKeys() (string, error) {
	// Generate a new RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Get the public key
	publicKey := &privateKey.PublicKey

	// Convert the public key to base64
	publicKeyBytes := publicKey.N.Bytes()
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	return publicKeyBase64, nil
}

func generateAction(c *cli.Context) error {
	// Validate that we have the required argument (key ID)
	if c.NArg() != 1 {
		return fmt.Errorf("expected exactly one argument: KEY_ID")
	}

	keyID := c.Args().Get(0)

	// Validate that the key ID is a valid UUID
	if _, err := uuid.Parse(keyID); err != nil {
		return fmt.Errorf("invalid key ID format, must be a valid UUID: %w", err)
	}

	// Read base64 public key from stdin
	scanner := bufio.NewScanner(os.Stdin)
	publicKeyBase64 := ""
	for scanner.Scan() {
		publicKeyBase64 += scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading from stdin: %w", err)
	}

	// Check if input is empty
	if publicKeyBase64 == "" {
		return fmt.Errorf("no base64 public key provided")
	}

	// Decode the base64 public key to get the modulus
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return fmt.Errorf("failed to decode base64 public key: %w", err)
	}

	// Validate that the decoded bytes are not empty
	if len(publicKeyBytes) == 0 {
		return fmt.Errorf("decoded public key cannot be empty")
	}

	// Encode the modulus to Base64url format (as required by JWK spec)
	modulusBase64URL := base64.RawURLEncoding.EncodeToString(publicKeyBytes)

	// Create the JWK with default RSA exponent (65537 = 0x010001 = AQAB in base64)
	jwk := JWK{
		Kty: "RSA",
		Kid: keyID,
		N:   modulusBase64URL,
		E:   "AQAB", // Base64 encoding of 65537 (0x010001)
	}

	// Validate that the JWK has all required fields
	if jwk.Kty == "" || jwk.Kid == "" || jwk.N == "" || jwk.E == "" {
		return fmt.Errorf("generated JWK is missing required fields")
	}

	// Create the JWKS with the single JWK
	jwks := JWKS{
		Keys: []JWK{jwk},
	}

	// Validate that the JWKS has exactly one key
	if len(jwks.Keys) != 1 {
		return fmt.Errorf("JWKS must contain exactly one key, got %d", len(jwks.Keys))
	}

	// Output the JWKS as JSON
	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		return fmt.Errorf("failed to marshal JWKS to JSON: %w", err)
	}

	// Validate that the output is valid JSON
	var temp interface{}
	if err := json.Unmarshal(jwksJSON, &temp); err != nil {
		return fmt.Errorf("generated JWKS JSON is invalid: %w", err)
	}

	fmt.Println(string(jwksJSON))

	return nil
}