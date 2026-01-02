// Package japikey provides a Go library for generating secure API keys using JWT technology.
// It follows the japikey specification and generates API keys with proper cryptographic signatures
// without storing secrets in a database.
package japikey

import (
	"github.com/susu-dot-dev/japikey/japikey"
)

// Config holds the configuration for creating a JAPIKey.
// It contains the required and optional parameters for API key generation.
type Config = japikey.Config

// JAPIKey represents the primary data type for an API key.
// It contains the JWT string, public key, and key identifier.
type JAPIKey = japikey.JAPIKey

// NewJAPIKey creates a new JAPIKey with the provided configuration using the standard Go constructor pattern.
// It returns a pointer to the JAPIKey struct containing the generated JWT, public key, and other metadata.
// The function follows Go naming conventions (NewX pattern) for constructor functions.
func NewJAPIKey(config Config) (*JAPIKey, error) {
	return japikey.NewJAPIKey(config)
}

// JAPIKeyValidationError is returned when input parameters fail validation.
// Examples include expired time or empty subject.
type JAPIKeyValidationError = japikey.JAPIKeyValidationError

// JAPIKeyGenerationError is returned when cryptographic operations fail during key generation.
// Examples include failure to generate RSA key pair or insufficient entropy.
type JAPIKeyGenerationError = japikey.JAPIKeyGenerationError

// JAPIKeySigningError is returned when JWT signing operations fail.
// Examples include failure to sign the JWT with the private key.
type JAPIKeySigningError = japikey.JAPIKeySigningError

// VerifyConfig holds the configuration for verifying a JAPIKey.
// It contains the required and optional parameters for API key verification.
type VerifyConfig = japikey.VerifyConfig

// JWKCallback is a function that retrieves the JWK (JSON Web Key) given the key ID.
// This function is used during token verification to get the appropriate public key
// for signature verification.
type JWKCallback = japikey.JWKCallback

// VerificationResult holds the result of a successful token verification.
type VerificationResult = japikey.VerificationResult

// JAPIKeyVerificationError represents an error that occurs during token verification.
// It provides specific information about the type of validation that failed.
type JAPIKeyVerificationError = japikey.JAPIKeyVerificationError

// Verify takes in the JWT string, the config, as well as a callback function which retrieves the JWK if given the key id.
// It either returns the validated claims, or an appropriate error.
func Verify(tokenString string, config VerifyConfig, keyFunc JWKCallback) (*VerificationResult, error) {
	return japikey.Verify(tokenString, config, keyFunc)
}

// ShouldVerify is a pre-validation function that checks if a token has the correct format before full verification.
func ShouldVerify(tokenString string, baseIssuer string) bool {
	return japikey.ShouldVerify(tokenString, baseIssuer)
}
