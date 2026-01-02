package errors

// JapikeyError is the base error type for all japikey errors.
// It provides a standardized structure with a code and message.
type JapikeyError struct {
	Code    string
	Message string
}

func (e *JapikeyError) Error() string {
	return e.Message
}

// ValidationError is returned when input parameters fail validation.
// This includes invalid JWK format, invalid RSA parameters, invalid config values, etc.
type ValidationError struct {
	JapikeyError
}

func NewValidationError(message string) *ValidationError {
	return &ValidationError{
		JapikeyError: JapikeyError{
			Code:    "ValidationError",
			Message: message,
		},
	}
}

// ConversionError is returned when cryptographic operations fail during conversion.
// This includes failures to convert JAPIKey to JWK or failures to encode RSA parameters.
type ConversionError struct {
	JapikeyError
}

func NewConversionError(message string) *ConversionError {
	return &ConversionError{
		JapikeyError: JapikeyError{
			Code:    "ConversionError",
			Message: message,
		},
	}
}

// KeyNotFoundError is returned when the requested key ID is not present in the JWKS.
// Clients may need to handle this differently (e.g., retry with different key, fetch from different source).
type KeyNotFoundError struct {
	JapikeyError
}

func NewKeyNotFoundError(message string) *KeyNotFoundError {
	return &KeyNotFoundError{
		JapikeyError: JapikeyError{
			Code:    "KeyNotFoundError",
			Message: message,
		},
	}
}

// InternalError is returned when internal operations fail.
// This includes key generation failures, signing failures, and other internal cryptographic operations.
type InternalError struct {
	JapikeyError
}

func NewInternalError(message string) *InternalError {
	return &InternalError{
		JapikeyError: JapikeyError{
			Code:    "InternalError",
			Message: message,
		},
	}
}

