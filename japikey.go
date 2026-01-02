// Package japikey provides a Go library for generating secure API keys using JWT technology.
// It follows the japikey specification and generates API keys with proper cryptographic signatures
// without storing secrets in a database.
package japikey

import (
	"crypto/rsa"

	"github.com/google/uuid"
	"github.com/susu-dot-dev/japikey/errors"
	"github.com/susu-dot-dev/japikey/internal/jwks"
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
