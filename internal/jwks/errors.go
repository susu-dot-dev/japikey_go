package jwks

// InvalidJWKError is returned when input parameters fail validation during JSON unmarshaling.
// Examples include invalid JWK JSON format or invalid RSA parameters.
type InvalidJWKError struct {
	Message string
	Code    string
}

func (e *InvalidJWKError) Error() string {
	return e.Message
}

// UnexpectedConversionError is returned when cryptographic operations fail during JWK conversion.
// Examples include failure to convert JAPIKey to JWK or failure to encode RSA parameters.
type UnexpectedConversionError struct {
	Message string
	Code    string
}

func (e *UnexpectedConversionError) Error() string {
	return e.Message
}

// KeyNotFoundError is returned when the requested key ID is not present in the JWKS.
// Examples include attempting to get a public key for a non-existent key ID.
type KeyNotFoundError struct {
	Message string
	Code    string
}

func (e *KeyNotFoundError) Error() string {
	return e.Message
}