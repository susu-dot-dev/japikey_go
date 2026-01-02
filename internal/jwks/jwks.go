package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"

	"github.com/google/uuid"
	"github.com/susu-dot-dev/japikey/errors"
)

// JWK represents the structure of a JSON Web Key
type JWK struct {
	kid       uuid.UUID      // The key identifier (UUID format)
	n         string         // The RSA modulus encoded as Base64urlUInt
	e         string         // The RSA exponent encoded as Base64urlUInt
	publicKey *rsa.PublicKey // The RSA public key
}

// JWKS represents the structure of a JSON Web Key Set
type JWKS struct {
	jwk JWK // Since our JWKS can only contain a single key, simplify the in-memory data type
}

// Represents the JSON on-disk format of a JWKS that we support
type encodedJWK struct {
	Kty string    `json:"kty"`
	Kid uuid.UUID `json:"kid"`
	N   string    `json:"n"`
	E   string    `json:"e"`
}
type encodedJWKS struct {
	Keys []encodedJWK `json:"keys"`
}

// NewJWKS creates a new JWKS containing exactly one RSA key from a public key and key ID
func NewJWKS(publicKey *rsa.PublicKey, kid uuid.UUID) (*JWKS, error) {
	// Validate that the public key is not nil
	if publicKey == nil {
		return nil, errors.NewValidationError("RSA public key cannot be nil")
	}

	// Validate that the key ID is not empty
	if kid == uuid.Nil {
		return nil, errors.NewValidationError("key ID cannot be empty")
	}

	// Encode the RSA modulus (n) and exponent (e) as Base64urlUInt
	modulusBase64 := base64urlUIntEncode(publicKey.N)
	exponentInt := big.NewInt(int64(publicKey.E))
	exponentBase64 := base64urlUIntEncode(exponentInt)

	// Create the JWK
	jwk := JWK{
		kid:       kid,
		n:         modulusBase64,
		e:         exponentBase64,
		publicKey: publicKey,
	}

	if jwk.kid == uuid.Nil {
		return nil, errors.NewValidationError("kid parameter cannot be empty")
	}

	// Create the JWKS with the single JWK
	JWKS := &JWKS{
		jwk,
	}

	return JWKS, nil
}

// GetPublicKey extracts the RSA public key from the JWKS for a given key ID
func (j *JWKS) GetPublicKey(kid uuid.UUID) (*rsa.PublicKey, error) {
	// Validate that the key ID matches the requested one
	if j.jwk.kid != kid {
		return nil, errors.NewKeyNotFoundError("key ID not found in JWKS")
	}

	return j.jwk.publicKey, nil
}

// GetKeyID retrieves the key ID present in the JWKS
func (j *JWKS) GetKeyID() uuid.UUID {
	return j.jwk.kid
}

// MarshalJSON implements custom JSON marshaling for JWKS
func (j *JWKS) MarshalJSON() ([]byte, error) {
	ejwks := encodedJWKS{
		Keys: []encodedJWK{
			{
				Kty: "RSA",
				Kid: j.jwk.kid,
				N:   j.jwk.n,
				E:   j.jwk.e,
			},
		},
	}
	return json.Marshal(ejwks)
}

// UnmarshalJSON implements custom JSON unmarshaling for JWKS
func (j *JWKS) UnmarshalJSON(data []byte) error {
	if err := j.validateJSONShape(data); err != nil {
		return err
	}
	ejwks := encodedJWKS{}
	if err := json.Unmarshal(data, &ejwks); err != nil {
		return errors.NewValidationError("invalid JWKS JSON format: " + err.Error())
	}
	ejwk := ejwks.Keys[0]
	if ejwk.Kty != "RSA" {
		return errors.NewValidationError("kty parameter must be 'RSA'")
	}
	modulus, err := base64urlUIntDecode(ejwk.N)
	if err != nil {
		return errors.NewValidationError("failed to decode modulus: " + err.Error())
	}

	exponent, err := base64urlUIntDecode(ejwk.E)
	if err != nil {
		return errors.NewValidationError("failed to decode exponent: " + err.Error())
	}

	// Create the RSA public key
	publicKey := &rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}

	// Create JWKS using NewJWKS constructor
	jwks, err := NewJWKS(publicKey, ejwk.Kid)
	if err != nil {
		return err
	}

	// Validate that the returned JWKS has the same n and e values
	if jwks.jwk.n != ejwk.N || jwks.jwk.e != ejwk.E {
		return errors.NewConversionError("round-trip validation failed: n values do not match")
	}
	j.jwk = jwks.jwk

	return nil
}

func (j *JWKS) validateJSONShape(data []byte) error {
	// In order to safely unmarshal the JWKS, ensuring that there are no
	// extra fields golang would otherwise ignore, we:
	// 1. Ensure that the keys[] element exists, and only contains one element
	// 2. Ensure that the keys[0] element contains exactly the 4 expected fields
	var jwksUntyped struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(data, &jwksUntyped); err != nil {
		return errors.NewValidationError("invalid JWKS JSON format: " + err.Error())
	}

	// Check that the array has exactly one element
	if len(jwksUntyped.Keys) != 1 {
		return errors.NewValidationError("JWKS must contain exactly one key")
	}

	// Get the single key element
	jwkUntyped := jwksUntyped.Keys[0]
	expectedFields := []string{"kty", "kid", "n", "e"}
	if len(jwkUntyped) != len(expectedFields) {
		return errors.NewValidationError("JWK must contain exactly 4 fields: kty, kid, n, e")
	}

	for _, field := range expectedFields {
		if _, exists := jwkUntyped[field]; !exists {
			return errors.NewValidationError("JWK must contain '" + field + "' field")
		}
	}
	return nil
}

// base64urlUIntEncode encodes a positive integer as Base64urlUInt according to RFC 7518
func base64urlUIntEncode(n *big.Int) string {
	if n == nil {
		return ""
	}

	// Handle zero case specially as per RFC
	if n.Sign() == 0 {
		return "AA" // BASE64URL(single zero-valued octet)
	}

	// Get the absolute value's bytes (big-endian representation)
	bytes := n.Bytes()

	// Use unpadded base64url encoding
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// base64urlUIntDecode decodes a Base64urlUInt string to a positive integer according to RFC 7518
func base64urlUIntDecode(s string) (*big.Int, error) {
	if s == "" {
		return nil, errors.NewValidationError("Base64urlUInt string cannot be empty")
	}

	// Handle the zero case specially as per RFC
	if s == "AA" {
		return big.NewInt(0), nil
	}

	// Decode using unpadded base64url encoding
	bytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.NewValidationError("invalid Base64urlUInt encoding: " + err.Error())
	}

	// Convert bytes to big integer
	result := new(big.Int).SetBytes(bytes)
	return result, nil
}
