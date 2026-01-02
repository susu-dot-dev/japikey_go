package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"

	"github.com/google/uuid"
)

// JWK represents the structure of a JSON Web Key
type JWK struct {
	kty string    // Always "RSA" to identify the key type
	kid uuid.UUID // The key identifier (UUID format)
	n   string    // The RSA modulus encoded as Base64urlUInt
	e   string    // The RSA exponent encoded as Base64urlUInt
}

// JWKS represents the structure of a JSON Web Key Set
type JWKS struct {
	keys []JWK // Array containing exactly one JWK
}

// NewJWK creates a new JWKS containing exactly one RSA key from a public key and key ID
func NewJWK(publicKey *rsa.PublicKey, kid uuid.UUID) (*JWKS, error) {
	// Validate that the public key is not nil
	if publicKey == nil {
		return nil, &UnexpectedConversionError{
			Message: "RSA public key cannot be nil",
			Code:    "UnexpectedConversionError",
		}
	}

	// Validate that the key ID is not empty
	if kid == uuid.Nil {
		return nil, &InvalidJWKError{
			Message: "key ID cannot be empty",
			Code:    "InvalidJWK",
		}
	}

	// Encode the RSA modulus (n) and exponent (e) as Base64urlUInt
	modulusBase64 := base64urlUIntEncode(publicKey.N)
	exponentInt := big.NewInt(int64(publicKey.E))
	exponentBase64 := base64urlUIntEncode(exponentInt)

	// Create the JWK
	jwk := JWK{
		kty: "RSA",
		kid: kid,
		n:   modulusBase64,
		e:   exponentBase64,
	}

	// Validate the JWK
	if err := jwk.validateJWK(); err != nil {
		return nil, err
	}

	// Create the JWKS with the single JWK
	JWKS := &JWKS{
		keys: []JWK{jwk},
	}

	// Validate the JWKS
	if err := JWKS.validateJWKS(); err != nil {
		return nil, err
	}

	return JWKS, nil
}

// GetPublicKey extracts the RSA public key from the JWKS for a given key ID
func (j *JWKS) GetPublicKey(kid uuid.UUID) (*rsa.PublicKey, error) {
	// Validate that we have exactly one key
	if len(j.keys) != 1 {
		return nil, &InvalidJWKError{
			Message: "JWKS must contain exactly one key",
			Code:    "InvalidJWK",
		}
	}

	// Get the single key
	key := j.keys[0]

	// Validate that the key ID matches the requested one
	if key.kid != kid {
		return nil, &KeyNotFoundError{
			Message: "key ID not found in JWKS",
			Code:    "KeyNotFoundError",
		}
	}

	// Decode the modulus and exponent from Base64urlUInt
	modulus, err := base64urlUIntDecode(key.n)
	if err != nil {
		return nil, &InvalidJWKError{
			Message: "failed to decode modulus: " + err.Error(),
			Code:    "InvalidJWK",
		}
	}

	exponent, err := base64urlUIntDecode(key.e)
	if err != nil {
		return nil, &InvalidJWKError{
			Message: "failed to decode exponent: " + err.Error(),
			Code:    "InvalidJWK",
		}
	}

	// Create the RSA public key
	publicKey := &rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}

	return publicKey, nil
}

// GetKeyID retrieves the key ID present in the JWKS
func (j *JWKS) GetKeyID() (uuid.UUID, error) {
	// Validate that we have exactly one key
	if len(j.keys) != 1 {
		return uuid.Nil, &InvalidJWKError{
			Message: "JWKS must contain exactly one key",
			Code:    "InvalidJWK",
		}
	}

	// Get the single key
	key := j.keys[0]

	// Validate that the key ID is a valid UUID
	if key.kid == uuid.Nil {
		return uuid.Nil, &InvalidJWKError{
			Message: "key ID in JWKS is invalid",
			Code:    "InvalidJWK",
		}
	}

	return key.kid, nil
}

// MarshalJSON implements custom JSON marshaling for JWKS
func (j *JWKS) MarshalJSON() ([]byte, error) {
	// Create the external JWKS structure for JSON serialization
	externalJWKS := struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}{
		Keys: make([]struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		}, len(j.keys)),
	}

	// Convert internal JWK structs to external format
	for i, key := range j.keys {
		externalJWKS.Keys[i] = struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		}{
			Kty: key.kty,
			Kid: key.kid.String(),
			N:   key.n,
			E:   key.e,
		}
	}

	return json.Marshal(externalJWKS)
}

// UnmarshalJSON implements custom JSON unmarshaling for JWKS
func (j *JWKS) UnmarshalJSON(data []byte) error {
	// Define the external JWKS structure for JSON deserialization
	var externalJWKS struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	if err := json.Unmarshal(data, &externalJWKS); err != nil {
		return &InvalidJWKError{
			Message: "invalid JWKS JSON format: " + err.Error(),
			Code:    "InvalidJWK",
		}
	}

	// Validate that there is exactly one key
	if len(externalJWKS.Keys) != 1 {
		return &InvalidJWKError{
			Message: "JWKS must contain exactly one key",
			Code:    "InvalidJWK",
		}
	}

	// Convert the external format to internal JWK struct
	key := externalJWKS.Keys[0]

	// Parse the UUID
	parsedUUID, err := uuid.Parse(key.Kid)
	if err != nil {
		return &InvalidJWKError{
			Message: "invalid key ID format: " + err.Error(),
			Code:    "InvalidJWK",
		}
	}

	// Create the internal JWK
	jwk := JWK{
		kty: key.Kty,
		kid: parsedUUID,
		n:   key.N,
		e:   key.E,
	}

	// Validate the JWK
	if err := jwk.validateJWK(); err != nil {
		return err
	}

	// Set the keys in the JWKS
	j.keys = []JWK{jwk}

	return nil
}

// validateJWK validates that the JWK has all required fields and proper values
func (j *JWK) validateJWK() error {
	// Validate that kty is "RSA"
	if j.kty != "RSA" {
		return &InvalidJWKError{
			Message: "kty parameter must be 'RSA'",
			Code:    "InvalidJWK",
		}
	}

	// Validate that kid is a valid UUID (this is always true since it's uuid.UUID type)
	// But we can check if it's the zero value
	if j.kid == uuid.Nil {
		return &InvalidJWKError{
			Message: "kid parameter cannot be empty",
			Code:    "InvalidJWK",
		}
	}

	// Validate that n and e are not empty
	if j.n == "" {
		return &InvalidJWKError{
			Message: "n parameter cannot be empty",
			Code:    "InvalidJWK",
		}
	}

	if j.e == "" {
		return &InvalidJWKError{
			Message: "e parameter cannot be empty",
			Code:    "InvalidJWK",
		}
	}

	return nil
}

// validateJWKS validates that the JWKS has proper structure
func (j *JWKS) validateJWKS() error {
	// Validate that JWKS contains exactly one key
	if len(j.keys) != 1 {
		return &InvalidJWKError{
			Message: "JWKS must contain exactly one key",
			Code:    "InvalidJWK",
		}
	}

	// Validate the single JWK
	if err := j.keys[0].validateJWK(); err != nil {
		return err
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
		return nil, &InvalidJWKError{
			Message: "Base64urlUInt string cannot be empty",
			Code:    "InvalidJWK",
		}
	}

	// Handle the zero case specially as per RFC
	if s == "AA" {
		return big.NewInt(0), nil
	}

	// Decode using unpadded base64url encoding
	bytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, &InvalidJWKError{
			Message: "invalid Base64urlUInt encoding: " + err.Error(),
			Code:    "InvalidJWK",
		}
	}

	// Convert bytes to big integer
	result := new(big.Int).SetBytes(bytes)
	return result, nil
}