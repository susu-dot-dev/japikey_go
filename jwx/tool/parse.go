package main

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
)

const (
	// maxInputSize caps how much of stdin is read. A single RSA JWK (even 16384-bit)
	// is well under 4KB, so this leaves generous headroom while preventing
	// unbounded memory use from a large or endless stdin.
	maxInputSize = 16 * 1024

	// maxExponentBytes caps the decoded public exponent length. Real exponents
	// (65537) are 3 bytes; 4 bytes always fits in an int without overflow.
	maxExponentBytes = 4

	// p256CoordinateBytes is the fixed length of a P-256 coordinate (RFC 7518 6.2.1.2)
	p256CoordinateBytes = 32
)

// readLimited reads at most max bytes from r and returns an error if the
// input is larger, instead of silently truncating it.
func readLimited(r io.Reader, max int64) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return "", fmt.Errorf("error reading from stdin: %w", err)
	}
	if int64(len(data)) > max {
		return "", fmt.Errorf("input exceeds maximum allowed size of %d bytes", max)
	}
	return string(data), nil
}

func parseAction(ctx context.Context, c *cli.Command) error {
	// Read JSON from stdin (size-capped)
	input, err := readLimited(os.Stdin, maxInputSize)
	if err != nil {
		return err
	}
	input = strings.TrimSpace(input)

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

	switch kty {
	case "RSA":
	case "EC":
		return parseEC(jwkObj)
	default:
		return fmt.Errorf("key type must be RSA or EC, got: %s", kty)
	}

	n, ok := jwkObj["n"].(string)
	if !ok || n == "" {
		return fmt.Errorf("missing required field 'n' (modulus) in JWK")
	}

	e, ok := jwkObj["e"].(string)
	if !ok || e == "" {
		return fmt.Errorf("missing required field 'e' (exponent) in JWK")
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

	if len(exponentBytes) > maxExponentBytes {
		return fmt.Errorf("exponent (e) is too large: %d bytes, maximum is %d", len(exponentBytes), maxExponentBytes)
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

// parseEC handles a P-256 JWK: it checks the members and prints the public key
// as the base64 of the uncompressed SEC1 point (0x04 || X || Y).
func parseEC(jwkObj map[string]interface{}) error {
	if crv, _ := jwkObj["crv"].(string); crv != "P-256" {
		return fmt.Errorf("curve (crv) must be P-256")
	}
	coord := func(name string) ([]byte, error) {
		v, ok := jwkObj[name].(string)
		if !ok || v == "" {
			return nil, fmt.Errorf("missing required field '%s' in JWK", name)
		}
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("failed to decode %s from Base64url: %w", name, err)
		}
		if len(b) != p256CoordinateBytes {
			return nil, fmt.Errorf("%s must be exactly %d bytes", name, p256CoordinateBytes)
		}
		return b, nil
	}
	x, err := coord("x")
	if err != nil {
		return err
	}
	y, err := coord("y")
	if err != nil {
		return err
	}
	point := append([]byte{0x04}, append(x, y...)...)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return fmt.Errorf("x and y are not a valid P-256 point")
	}
	fmt.Println(base64.StdEncoding.EncodeToString(point))
	return nil
}
