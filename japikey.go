// Package japikey provides a Go library for generating secure API keys using JWT technology.
// It follows the japikey specification and generates API keys with proper cryptographic signatures
// without storing secrets in a database.
package japikey

import (
	"github.com/susu-dot-dev/japikey/errors"
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

// ValidationError is returned when input parameters fail validation.
// Examples include expired time, empty subject, invalid JWK format, or invalid RSA parameters.
type ValidationError = errors.ValidationError

// ConversionError is returned when cryptographic operations fail during conversion.
// Examples include failure to convert JAPIKey to JWK or failure to encode RSA parameters.
type ConversionError = errors.ConversionError

// KeyNotFoundError is returned when the requested key ID is not present in the JWKS.
// Examples include attempting to get a public key for a non-existent key ID.
type KeyNotFoundError = errors.KeyNotFoundError

// InternalError is returned when internal operations fail.
// Examples include key generation failures, signing failures, and other internal cryptographic operations.
type InternalError = errors.InternalError
