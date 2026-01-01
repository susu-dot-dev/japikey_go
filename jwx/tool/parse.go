package main

import (
	"bufio"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/urfave/cli/v2"
)

func parseAction(c *cli.Context) error {
	// Read JSON from stdin
	scanner := bufio.NewScanner(os.Stdin)
	input := ""
	for scanner.Scan() {
		input += scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading from stdin: %w", err)
	}

	// Check if input is empty
	if input == "" {
		return fmt.Errorf("no input provided to parse")
	}

	// Parse the JWK JSON
	var jwkObj map[string]interface{}
	if err := json.Unmarshal([]byte(input), &jwkObj); err != nil {
		return fmt.Errorf("invalid JWK JSON: %w", err)
	}

	// Validate required fields are present
	kty, ok := jwkObj["kty"].(string)
	if !ok || kty == "" {
		return fmt.Errorf("missing required field 'kty' in JWK")
	}

	n, ok := jwkObj["n"].(string)
	if !ok || n == "" {
		return fmt.Errorf("missing required field 'n' (modulus) in JWK")
	}

	e, ok := jwkObj["e"].(string)
	if !ok || e == "" {
		return fmt.Errorf("missing required field 'e' (exponent) in JWK")
	}

	// Validate that it's an RSA key
	if kty != "RSA" {
		return fmt.Errorf("key type must be RSA, got: %s", kty)
	}

	// Decode the modulus (n) and exponent (e) from Base64url
	modulusBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return fmt.Errorf("failed to decode modulus (n) from Base64url: %w", err)
	}

	exponentBytes, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return fmt.Errorf("failed to decode exponent (e) from Base64url: %w", err)
	}

	// Validate that the decoded values are not empty
	if len(modulusBytes) == 0 {
		return fmt.Errorf("modulus (n) cannot be empty after decoding")
	}

	if len(exponentBytes) == 0 {
		return fmt.Errorf("exponent (e) cannot be empty after decoding")
	}

	// Convert the exponent bytes to an integer
	// The exponent is typically small, so we can use a simple conversion
	exponent := 0
	for _, b := range exponentBytes {
		exponent = (exponent << 8) | int(b)
	}

	// Validate that the exponent is a reasonable value (e.g., not 0 or negative)
	if exponent <= 0 {
		return fmt.Errorf("exponent (e) must be a positive integer, got: %d", exponent)
	}

	// Convert the modulus bytes to a big integer
	modulus := new(big.Int).SetBytes(modulusBytes)

	// Validate that the modulus is a positive value
	if modulus.Sign() <= 0 {
		return fmt.Errorf("modulus (n) must be a positive integer")
	}

	// Output the public key as base64 (we'll encode the modulus as base64)
	publicKeyBase64 := base64.StdEncoding.EncodeToString(modulus.Bytes())
	fmt.Println(publicKeyBase64)

	return nil
}

// Alternative implementation using lestrrat-go/jwx/jwk for validation
func parseActionWithJWX(c *cli.Context) error {
	// Read JSON from stdin
	scanner := bufio.NewScanner(os.Stdin)
	input := ""
	for scanner.Scan() {
		input += scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading from stdin: %w", err)
	}

	// Parse the JWK using the jwx library
	set, err := jwk.ParseString(input)
	if err != nil {
		return fmt.Errorf("invalid JWK JSON: %w", err)
	}

	if set.Len() != 1 {
		return fmt.Errorf("expected exactly one key in JWK set, got: %d", set.Len())
	}

	// Get the first key
	key, ok := set.Key(0)
	if !ok {
		return fmt.Errorf("failed to get key from JWK set")
	}

	// Check that it's an RSA key
	if string(key.KeyType()) != "RSA" {
		return fmt.Errorf("key type must be RSA, got: %s", key.KeyType())
	}

	// Convert to raw key to get the public key
	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return fmt.Errorf("failed to get raw key: %w", err)
	}

	// Type assert to *rsa.PublicKey
	rsaKey, ok := rawKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to convert to RSA public key")
	}

	// Get the modulus as bytes and encode as base64
	modulusBytes := rsaKey.N.Bytes()
	publicKeyBase64 := base64.StdEncoding.EncodeToString(modulusBytes)
	fmt.Println(publicKeyBase64)

	return nil
}