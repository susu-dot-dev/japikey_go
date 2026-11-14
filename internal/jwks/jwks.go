package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"uuid"

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

const (
	// MinModulusBits and MaxModulusBits bound the accepted RSA modulus size.
	// The minimum matches what NewJAPIKey generates; the maximum bounds verification CPU cost.
	MinModulusBits = 2048
	MaxModulusBits = 4096

	// MinExponent and MaxExponent bound the accepted RSA public exponent. The maximum
	// matches the limit enforced by Go's crypto/rsa. The exponent must also be odd.
	MinExponent = 3
	MaxExponent = 1<<31 - 1
)

// ValidatePublicKey rejects RSA public keys that are structurally unusable or too weak:
// the modulus must be odd and within [MinModulusBits, MaxModulusBits] bits, and the
// exponent must be odd and within [MinExponent, MaxExponent].
//
// It is applied both when building a JWKS and to every key a verification
// callback returns, so a key cannot bypass it by coming from another source.
func ValidatePublicKey(publicKey *rsa.PublicKey) error {
	if publicKey == nil {
		return errors.NewValidationError("RSA public key cannot be nil")
	}
	if publicKey.N == nil || publicKey.N.Sign() <= 0 {
		return errors.NewValidationError("RSA modulus must be a positive integer")
	}
	if bits := publicKey.N.BitLen(); bits < MinModulusBits || bits > MaxModulusBits {
		return errors.NewValidationError("RSA modulus size is not supported")
	}
	if publicKey.N.Bit(0) == 0 {
		return errors.NewValidationError("RSA modulus must be odd")
	}
	if publicKey.E < MinExponent || publicKey.E > MaxExponent || publicKey.E%2 == 0 {
		return errors.NewValidationError("RSA exponent is not supported")
	}
	return nil
}

func NewJWKS(publicKey *rsa.PublicKey, kid uuid.UUID) (*JWKS, error) {
	if publicKey == nil {
		return nil, errors.NewValidationError("RSA public key cannot be nil")
	}

	if kid == uuid.Nil() {
		return nil, errors.NewValidationError("key ID cannot be empty")
	}

	if err := ValidatePublicKey(publicKey); err != nil {
		return nil, err
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

	if jwk.kid == uuid.Nil() {
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
	// Error messages below are fixed strings. The errors from encoding/json and
	// encoding/base64 can quote parts of the input, which must not be echoed.
	ejwks := encodedJWKS{}
	if err := json.Unmarshal(data, &ejwks); err != nil {
		return errors.NewValidationError("invalid JWKS JSON format")
	}
	ejwk := ejwks.Keys[0]
	if ejwk.Kty != "RSA" {
		return errors.NewValidationError("kty parameter must be 'RSA'")
	}
	modulus, err := base64urlUIntDecode(ejwk.N)
	if err != nil {
		return errors.NewValidationError("failed to decode modulus")
	}

	exponent, err := base64urlUIntDecode(ejwk.E)
	if err != nil {
		return errors.NewValidationError("failed to decode exponent")
	}

	// Check the range before converting, so a huge exponent cannot be truncated into a valid one
	if !exponent.IsInt64() || exponent.Int64() < MinExponent || exponent.Int64() > MaxExponent {
		return errors.NewValidationError("RSA exponent is not supported")
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
		return errors.NewConversionError("round-trip validation failed: n or e values do not match")
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
		return errors.NewValidationError("invalid JWKS JSON format")
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
		return nil, errors.NewValidationError("invalid Base64urlUInt encoding")
	}

	return new(big.Int).SetBytes(bytes), nil
}
