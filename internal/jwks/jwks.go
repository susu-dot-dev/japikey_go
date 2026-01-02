package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"

	"github.com/google/uuid"
	"github.com/susu-dot-dev/japikey/errors"
)

type JWK struct {
	kid       uuid.UUID
	n         string
	e         string
	publicKey *rsa.PublicKey
}

type JWKS struct {
	jwk JWK
}

// Separate type for JSON serialization to match RFC 7517 format with "keys" array
type encodedJWK struct {
	Kty string    `json:"kty"`
	Kid uuid.UUID `json:"kid"`
	N   string    `json:"n"`
	E   string    `json:"e"`
}
type encodedJWKS struct {
	Keys []encodedJWK `json:"keys"`
}

func NewJWKS(publicKey *rsa.PublicKey, kid uuid.UUID) (*JWKS, error) {
	if publicKey == nil {
		return nil, errors.NewValidationError("RSA public key cannot be nil")
	}

	if kid == uuid.Nil {
		return nil, errors.NewValidationError("key ID cannot be empty")
	}

	modulusBase64 := base64urlUIntEncode(publicKey.N)
	exponentInt := big.NewInt(int64(publicKey.E))
	exponentBase64 := base64urlUIntEncode(exponentInt)

	jwk := JWK{
		kid:       kid,
		n:         modulusBase64,
		e:         exponentBase64,
		publicKey: publicKey,
	}

	if jwk.kid == uuid.Nil {
		return nil, errors.NewValidationError("kid parameter cannot be empty")
	}

	return &JWKS{jwk}, nil
}

func (j *JWKS) GetPublicKey(kid uuid.UUID) (*rsa.PublicKey, error) {
	if j.jwk.kid != kid {
		return nil, errors.NewKeyNotFoundError("key ID not found in JWKS")
	}

	return j.jwk.publicKey, nil
}

func (j *JWKS) GetKeyID() uuid.UUID {
	return j.jwk.kid
}

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

	publicKey := &rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}

	jwks, err := NewJWKS(publicKey, ejwk.Kid)
	if err != nil {
		return err
	}

	// Round-trip validation ensures encoded values match exactly
	if jwks.jwk.n != ejwk.N || jwks.jwk.e != ejwk.E {
		return errors.NewConversionError("round-trip validation failed: n values do not match")
	}
	j.jwk = jwks.jwk

	return nil
}

func (j *JWKS) validateJSONShape(data []byte) error {
	// Two-phase validation: first untyped to detect extra fields that Go would silently ignore
	var jwksUntyped struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(data, &jwksUntyped); err != nil {
		return errors.NewValidationError("invalid JWKS JSON format: " + err.Error())
	}

	if len(jwksUntyped.Keys) != 1 {
		return errors.NewValidationError("JWKS must contain exactly one key")
	}

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

// RFC 7518 requires zero to be encoded as "AA" (single zero-valued octet)
func base64urlUIntEncode(n *big.Int) string {
	if n == nil {
		return ""
	}

	if n.Sign() == 0 {
		return "AA"
	}

	bytes := n.Bytes()
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func base64urlUIntDecode(s string) (*big.Int, error) {
	if s == "" {
		return nil, errors.NewValidationError("Base64urlUInt string cannot be empty")
	}

	if s == "AA" {
		return big.NewInt(0), nil
	}

	bytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.NewValidationError("invalid Base64urlUInt encoding: " + err.Error())
	}

	return new(big.Int).SetBytes(bytes), nil
}
