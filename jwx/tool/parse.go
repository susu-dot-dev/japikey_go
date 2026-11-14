package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/urfave/cli/v3"
)

func parseAction(ctx context.Context, c *cli.Command) error {
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
