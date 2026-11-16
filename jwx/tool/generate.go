package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"uuid"

	"github.com/urfave/cli/v3"
)

// JWKS represents the structure of a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents the structure of a JSON Web Key. RSA (version 1) keys set
// Kty, Kid, N and E. P-256 (version 2) keys set Kty, Kid, Crv, X, Y, Alg and
// Ver. Members that do not apply are omitted.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Alg string `json:"alg,omitempty"`
	Ver int    `json:"ver,omitempty"`
}

const (
	algRS256 = "RS256"
	algES256 = "ES256"
)

// uncompressedP256Bytes is the length of a SEC 1 uncompressed P-256 point:
// 0x04 || X (32 bytes) || Y (32 bytes).
const uncompressedP256Bytes = 1 + 2*p256CoordinateBytes

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

// GenerateExampleECKeys generates an example P-256 key pair and returns the
// public key as the base64 of its uncompressed point, the format `parse`
// prints for an EC JWK and `generate` reads.
func GenerateExampleECKeys() (string, error) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate EC key pair: %w", err)
	}
	return base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()), nil
}

// buildECJWK builds a version 2 JWK from an uncompressed P-256 point.
func buildECJWK(keyID string, point []byte) (JWK, error) {
	if len(point) != uncompressedP256Bytes || point[0] != 0x04 {
		return JWK{}, fmt.Errorf("an ES256 public key must be a %d-byte uncompressed P-256 point", uncompressedP256Bytes)
	}
	// Rejects points that are not on the curve (and the point at infinity)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return JWK{}, fmt.Errorf("public key is not a valid P-256 point")
	}
	return JWK{
		Kty: "EC",
		Kid: keyID,
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(point[1 : 1+p256CoordinateBytes]),
		Y:   base64.RawURLEncoding.EncodeToString(point[1+p256CoordinateBytes:]),
		Alg: algES256,
		Ver: 2,
	}, nil
}

// buildRSAJWK builds a version 1 JWK from an RSA modulus with the default
// public exponent (65537).
func buildRSAJWK(keyID string, modulus []byte) JWK {
	return JWK{
		Kty: "RSA",
		Kid: keyID,
		N:   base64.RawURLEncoding.EncodeToString(modulus), // Base64url, as the JWK spec requires
		E:   "AQAB",                                        // Base64 encoding of 65537 (0x010001)
	}
}

// selectAlg resolves the --alg flag against the decoded key. With no flag
// (auto), a 65-byte value starting with 0x04 is a P-256 point and anything
// else is an RSA modulus: valid RSA moduli are at least 2048 bits, so they can
// never be confused with a 65-byte point.
func selectAlg(flag string, decoded []byte) (string, error) {
	switch flag {
	case "", "auto":
		if len(decoded) == uncompressedP256Bytes && decoded[0] == 0x04 {
			return algES256, nil
		}
		return algRS256, nil
	case algES256, algRS256:
		return flag, nil
	default:
		return "", fmt.Errorf("unsupported --alg %q: use %s, %s or auto", flag, algES256, algRS256)
	}
}

func generateAction(ctx context.Context, c *cli.Command) error {
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
	publicKeyBase64, err := readLimited(os.Stdin, maxInputSize)
	if err != nil {
		return err
	}
	publicKeyBase64 = strings.TrimSpace(publicKeyBase64)

	// Check if input is empty
	if publicKeyBase64 == "" {
		return fmt.Errorf("no base64 public key provided")
	}

	// Decode the base64 public key (an RSA modulus, or a P-256 uncompressed point)
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return fmt.Errorf("failed to decode base64 public key: %w", err)
	}

	// Validate that the decoded bytes are not empty
	if len(publicKeyBytes) == 0 {
		return fmt.Errorf("decoded public key cannot be empty")
	}

	alg, err := selectAlg(c.String("alg"), publicKeyBytes)
	if err != nil {
		return err
	}

	var jwk JWK
	switch alg {
	case algES256:
		jwk, err = buildECJWK(keyID, publicKeyBytes)
		if err != nil {
			return err
		}
	default:
		jwk = buildRSAJWK(keyID, publicKeyBytes)
	}

	// Validate that the JWK has all required fields
	if jwk.Kty == "" || jwk.Kid == "" {
		return fmt.Errorf("generated JWK is missing required fields")
	}
	if jwk.Kty == "RSA" && (jwk.N == "" || jwk.E == "") {
		return fmt.Errorf("generated JWK is missing required fields")
	}
	if jwk.Kty == "EC" && (jwk.Crv == "" || jwk.X == "" || jwk.Y == "" || jwk.Alg == "" || jwk.Ver == 0) {
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
