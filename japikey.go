// Package japikey provides a Go library for generating secure API keys using JWT technology.
// It follows the japikey specification and generates API keys with proper cryptographic signatures
// without storing secrets in a database.
package japikey

import (
	"crypto/rsa"
	"net/http"

	"github.com/google/uuid"
	"github.com/susu-dot-dev/japikey/errors"
	"github.com/susu-dot-dev/japikey/internal/jwks"
	"github.com/susu-dot-dev/japikey/internal/middleware"
	"github.com/susu-dot-dev/japikey/japikey"
)

type Config = japikey.Config

type JAPIKey = japikey.JAPIKey

func NewJAPIKey(config Config) (*JAPIKey, error) {
	return japikey.NewJAPIKey(config)
}

type ValidationError = errors.ValidationError

type ConversionError = errors.ConversionError

// KeyNotFoundError is kept separate from ValidationError because clients may need different behavior
// (e.g., retry with different key, fetch from different source)
type KeyNotFoundError = errors.KeyNotFoundError

type InternalError = errors.InternalError

type JWKS = jwks.JWKS

func NewJWKS(publicKey *rsa.PublicKey, kid uuid.UUID) (*JWKS, error) {
	return jwks.NewJWKS(publicKey, kid)
}

// VerifyConfig holds the configuration for verifying a JAPIKey.
// It contains the required and optional parameters for API key verification.
type VerifyConfig = japikey.VerifyConfig

// JWKCallback is a function that retrieves the JWK (JSON Web Key) given the key ID.
// This function is used during token verification to get the appropriate public key
// for signature verification.
type JWKCallback = japikey.JWKCallback

// VerificationResult holds the result of a successful token verification.
type VerificationResult = japikey.VerificationResult

// Verify takes in the JWT string, the config, as well as a callback function which retrieves the JWK if given the key id.
// It either returns the validated claims, or an appropriate error.
func Verify(tokenString string, config VerifyConfig, keyFunc JWKCallback) (*VerificationResult, error) {
	return japikey.Verify(tokenString, config, keyFunc)
}

// ShouldVerify is a pre-validation function that checks if a token has the correct format before full verification.
func ShouldVerify(tokenString string, baseIssuer string) bool {
	return japikey.ShouldVerify(tokenString, baseIssuer)
}

type DatabaseDriver = middleware.DatabaseDriver

type KeyLookupResult = middleware.KeyLookupResult

type JWKSRouterConfig = middleware.JWKSRouterConfig

func CreateJWKSRouter(config JWKSRouterConfig) (http.Handler, error) {
	return middleware.CreateJWKSRouter(config)
}
