package japikey

import (
	"crypto/rsa"
)

// JWKCallback is a function that retrieves the JWK (JSON Web Key) given the key ID.
// This function is used during token verification to get the appropriate public key
// for signature verification.
type JWKCallback func(keyID string) (*rsa.PublicKey, error)

// VerificationResult holds the result of a successful token verification.
type VerificationResult struct {
	// Claims contains the validated claims from the token
	Claims map[string]interface{}

	// KeyID is the key identifier from the token header
	KeyID string

	// Algorithm is the algorithm used in the token
	Algorithm string
}

// JAPIKeyVerificationError represents an error that occurs during token verification.
// It provides specific information about the type of validation that failed.
type JAPIKeyVerificationError struct {
	// Message is a human-readable description of the error
	Message string
	// Code is a specific error code for the type of error that occurred
	Code string
}

func (e *JAPIKeyVerificationError) Error() string {
	return e.Message
}

// Error codes for different types of verification errors
const (
	TokenFormatError      = "TokenFormatError"
	TokenSizeError        = "TokenSizeError"
	HeaderValidationError = "HeaderValidationError"
	AlgorithmError        = "AlgorithmError"
	PayloadValidationError = "PayloadValidationError"
	VersionValidationError = "VersionValidationError"
	IssuerValidationError  = "IssuerValidationError"
	SignatureValidationError = "SignatureValidationError"
	KeyRetrievalError        = "KeyRetrievalError"
	ExpirationError = "ExpirationError"
	NotBeforeError  = "NotBeforeError"
	IssuedAtError   = "IssuedAtError"
	ConstraintValidationError = "ConstraintValidationError"
	KeyIDMismatchError        = "KeyIDMismatchError"
	SecurityValidationError = "SecurityValidationError"
	InjectionError          = "InjectionError"
	NumericValueError       = "NumericValueError"
)