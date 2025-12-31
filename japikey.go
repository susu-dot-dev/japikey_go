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
