package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"uuid"

	"github.com/susu-dot-dev/japikey/errors"
)

const (
	// KeyTypeRSA and KeyTypeEC are the JWK "kty" values (RFC 7517) of the two
	// key families japikey supports.
	KeyTypeRSA = "RSA"
	KeyTypeEC  = "EC"

	// CurveP256 is the JWK "crv" value for NIST P-256, used by ES256.
	CurveP256 = "P-256"

	// AlgES256 is the JWK "alg" value written on version 2 keys.
	AlgES256 = "ES256"

	// Version2 is the JWK "ver" value written on version 2 keys. Version 1
	// (RSA) keys predate the member and have neither "ver" nor "alg".
	Version2 = 2

	// p256CoordinateBytes is the fixed length of a P-256 coordinate. RFC 7518
	// 6.2.1.2 requires x and y to be encoded at full length, leading zeros included.
	p256CoordinateBytes = 32
)

// JWK is a single validated public key with its key ID. It holds either an RSA
// key (version 1, no "alg" or "ver" member) or a P-256 key (version 2, with
// "alg" and "ver").
type JWK struct {
	kid       uuid.UUID
	kty       string
	n         string // RSA modulus
	e         string // RSA exponent
	crv       string // EC curve
	x         string // EC x coordinate
	y         string // EC y coordinate
	publicKey crypto.PublicKey
}

type JWKS struct {
	jwk JWK
}

// encodedJWK is the JSON form of a JWK (RFC 7517), with "keys" array wrapping
// it in encodedJWKS. Members that do not apply to the key type, and "alg" and
// "ver" for version 1 keys, are omitted so legacy documents are unchanged.
type encodedJWK struct {
	Kty string    `json:"kty"`
	Kid uuid.UUID `json:"kid"`
	N   string    `json:"n,omitempty"`
	E   string    `json:"e,omitempty"`
	Crv string    `json:"crv,omitempty"`
	X   string    `json:"x,omitempty"`
	Y   string    `json:"y,omitempty"`
	Alg string    `json:"alg,omitempty"`
	Ver int       `json:"ver,omitempty"`
}
type encodedJWKS struct {
	Keys []encodedJWK `json:"keys"`
}

const (
	// MinModulusBits and MaxModulusBits bound the accepted RSA modulus size.
	// The minimum matches what version 1 keys were generated with; the maximum
	// bounds verification CPU cost.
	MinModulusBits = 2048
	MaxModulusBits = 4096

	// MinExponent and MaxExponent bound the accepted RSA public exponent. The maximum
	// matches the limit enforced by Go's crypto/rsa. The exponent must also be odd.
	MinExponent = 3
	MaxExponent = 1<<31 - 1
)

// ValidatePublicKey rejects public keys that are structurally unusable or too
// weak. Two key types are accepted:
//   - *rsa.PublicKey (version 1): the modulus must be odd and within
//     [MinModulusBits, MaxModulusBits] bits, and the exponent must be odd and
//     within [MinExponent, MaxExponent].
//   - *ecdsa.PublicKey (version 2): the curve must be P-256 and the point must
//     be a valid point on it (not the point at infinity, in range, on the curve).
//
// It is applied both when building a JWKS and to every key a verification
// callback returns, so a key cannot bypass it by coming from another source.
func ValidatePublicKey(publicKey crypto.PublicKey) error {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return validateRSAPublicKey(key)
	case *ecdsa.PublicKey:
		return validateECPublicKey(key)
	default:
		return errors.NewValidationError("public key type is not supported")
	}
}

func validateRSAPublicKey(publicKey *rsa.PublicKey) error {
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

func validateECPublicKey(publicKey *ecdsa.PublicKey) error {
	if publicKey == nil {
		return errors.NewValidationError("EC public key cannot be nil")
	}
	if publicKey.Curve != elliptic.P256() {
		return errors.NewValidationError("EC curve must be P-256")
	}
	// Bytes panics when a coordinate is nil, and this key may come from an
	// untrusted callback, so check first. Reading the (deprecated) fields is
	// safe: nothing is modified.
	if publicKey.X == nil || publicKey.Y == nil { //nolint:staticcheck // nil check only
		return errors.NewValidationError("EC public key coordinates are required")
	}
	// Bytes validates the point: it rejects the point at infinity, out-of-range
	// coordinates and points that are not on the curve (invalid-curve attacks).
	if _, err := publicKey.Bytes(); err != nil {
		return errors.NewValidationError("EC public key is not a valid P-256 point")
	}
	return nil
}

// NewJWKS builds a JWKS holding one key. publicKey must be an *rsa.PublicKey
// (a version 1 key) or a P-256 *ecdsa.PublicKey (a version 2 key).
func NewJWKS(publicKey crypto.PublicKey, kid uuid.UUID) (*JWKS, error) {
	if publicKey == nil {
		return nil, errors.NewValidationError("public key cannot be nil")
	}

	if kid == uuid.Nil() {
		return nil, errors.NewValidationError("key ID cannot be empty")
	}

	if err := ValidatePublicKey(publicKey); err != nil {
		return nil, err
	}

	jwk := JWK{kid: kid, publicKey: publicKey}
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		jwk.kty = KeyTypeRSA
		jwk.n = base64urlUIntEncode(key.N)
		jwk.e = base64urlUIntEncode(big.NewInt(int64(key.E)))
	case *ecdsa.PublicKey:
		// Already validated, so Bytes cannot fail: 0x04 || X || Y, with each
		// coordinate at its full fixed length (RFC 7518 6.2.1.2)
		point, err := key.Bytes()
		if err != nil {
			return nil, errors.NewValidationError("EC public key is not a valid P-256 point")
		}
		jwk.kty = KeyTypeEC
		jwk.crv = CurveP256
		jwk.x = base64.RawURLEncoding.EncodeToString(point[1 : 1+p256CoordinateBytes])
		jwk.y = base64.RawURLEncoding.EncodeToString(point[1+p256CoordinateBytes:])
	}

	return &JWKS{jwk}, nil
}

// GetPublicKey returns the key with the given ID: an *rsa.PublicKey for a
// version 1 key or an *ecdsa.PublicKey for a version 2 key.
func (j *JWKS) GetPublicKey(kid uuid.UUID) (crypto.PublicKey, error) {
	if j.jwk.kid != kid {
		return nil, errors.NewKeyNotFoundError("key ID not found in JWKS")
	}

	return j.jwk.publicKey, nil
}

func (j *JWKS) GetKeyID() uuid.UUID {
	return j.jwk.kid
}

func (j *JWKS) MarshalJSON() ([]byte, error) {
	ejwk := encodedJWK{
		Kty: j.jwk.kty,
		Kid: j.jwk.kid,
		N:   j.jwk.n,
		E:   j.jwk.e,
		Crv: j.jwk.crv,
		X:   j.jwk.x,
		Y:   j.jwk.y,
	}
	if j.jwk.kty == KeyTypeEC {
		// Version 2 keys record their algorithm and version in the JWK, so that
		// no database column is needed to know how to verify them. Version 1
		// keys have neither member.
		ejwk.Alg = AlgES256
		ejwk.Ver = Version2
	}
	return json.Marshal(encodedJWKS{Keys: []encodedJWK{ejwk}})
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

	var (
		publicKey crypto.PublicKey
		err       error
	)
	switch ejwk.Kty {
	case KeyTypeRSA:
		publicKey, err = decodeRSA(ejwk)
	case KeyTypeEC:
		publicKey, err = decodeEC(ejwk)
	default:
		return errors.NewValidationError("kty parameter must be 'RSA' or 'EC'")
	}
	if err != nil {
		return err
	}

	jwks, err := NewJWKS(publicKey, ejwk.Kid)
	if err != nil {
		return err
	}

	// Round-trip validation ensures encoded values match exactly
	if jwks.jwk.n != ejwk.N || jwks.jwk.e != ejwk.E || jwks.jwk.x != ejwk.X || jwks.jwk.y != ejwk.Y {
		return errors.NewConversionError("round-trip validation failed: key values do not match")
	}
	j.jwk = jwks.jwk

	return nil
}

func decodeRSA(ejwk encodedJWK) (*rsa.PublicKey, error) {
	modulus, err := base64urlUIntDecode(ejwk.N)
	if err != nil {
		return nil, errors.NewValidationError("failed to decode modulus")
	}

	exponent, err := base64urlUIntDecode(ejwk.E)
	if err != nil {
		return nil, errors.NewValidationError("failed to decode exponent")
	}

	// Check the range before converting, so a huge exponent cannot be truncated into a valid one
	if !exponent.IsInt64() || exponent.Int64() < MinExponent || exponent.Int64() > MaxExponent {
		return nil, errors.NewValidationError("RSA exponent is not supported")
	}

	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

func decodeEC(ejwk encodedJWK) (*ecdsa.PublicKey, error) {
	if ejwk.Crv != CurveP256 {
		return nil, errors.NewValidationError("crv parameter must be 'P-256'")
	}
	x, err := decodeFixed(ejwk.X, p256CoordinateBytes)
	if err != nil {
		return nil, errors.NewValidationError("failed to decode x coordinate")
	}
	y, err := decodeFixed(ejwk.Y, p256CoordinateBytes)
	if err != nil {
		return nil, errors.NewValidationError("failed to decode y coordinate")
	}
	// Also rejects the point at infinity and points that are not on the curve
	point := append(append([]byte{0x04}, x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, errors.NewValidationError("EC public key is not a valid P-256 point")
	}
	return pub, nil
}

// validateJSONShape checks the JWKS has exactly one key with exactly the
// members its key type requires, and nothing else. It is two-phase: first
// untyped, to detect extra fields that Go would silently ignore.
//
// The accepted shapes are:
//   - RSA, version 1 (also what legacy keys are stored as): kty, kid, n, e
//   - EC, version 2: kty, kid, crv, x, y, alg ("ES256"), ver (2)
//
// An RSA key must not carry "alg" or "ver", and an EC key must carry both with
// the exact values above, so a key can only ever be read one way.
func (j *JWKS) validateJSONShape(data []byte) error {
	var jwksUntyped struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(data, &jwksUntyped); err != nil {
		return errors.NewValidationError("invalid JWKS JSON format")
	}

	if len(jwksUntyped.Keys) != 1 {
		return errors.NewValidationError("JWKS must contain exactly one key")
	}

	jwk := jwksUntyped.Keys[0]
	var expectedFields []string
	switch jwk["kty"] {
	case KeyTypeRSA:
		expectedFields = []string{"kty", "kid", "n", "e"}
	case KeyTypeEC:
		expectedFields = []string{"kty", "kid", "crv", "x", "y", "alg", "ver"}
	default:
		return errors.NewValidationError("kty parameter must be 'RSA' or 'EC'")
	}
	if len(jwk) != len(expectedFields) {
		return errors.NewValidationError("JWK has missing or unexpected fields for its key type")
	}
	for _, field := range expectedFields {
		if _, exists := jwk[field]; !exists {
			return errors.NewValidationError("JWK must contain '" + field + "' field")
		}
	}
	if jwk["kty"] == KeyTypeEC {
		if alg, ok := jwk["alg"].(string); !ok || alg != AlgES256 {
			return errors.NewValidationError("alg parameter must be 'ES256'")
		}
		// JSON numbers decode to float64
		if ver, ok := jwk["ver"].(float64); !ok || ver != Version2 {
			return errors.NewValidationError("ver parameter must be 2")
		}
	}
	return nil
}

// decodeFixed decodes a base64url value that must be exactly size bytes once
// decoded, in canonical form, so each coordinate has a single encoding.
func decodeFixed(s string, size int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != size {
		return nil, errors.NewValidationError("invalid fixed-length base64url value")
	}
	return b, nil
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
