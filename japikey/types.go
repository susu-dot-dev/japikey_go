package japikey

import (
	"crypto/rsa"

	"github.com/google/uuid"
)

// JWKCallback is a function that retrieves the JWK (JSON Web Key) given the key ID.
// This function is used during token verification to get the appropriate public key
// for signature verification.
type JWKCallback func(keyID uuid.UUID) (*rsa.PublicKey, error)

// VerificationResult holds the result of a successful token verification.
type VerificationResult struct {
	// Claims contains the validated claims from the token
	Claims map[string]interface{}

	// KeyID is the key identifier from the token header
	KeyID uuid.UUID

	// Algorithm is the algorithm used in the token
	Algorithm string
}
