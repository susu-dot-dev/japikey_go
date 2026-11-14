package errors

type JapikeyError struct {
	Code    string
	Message string
}

func (e *JapikeyError) Error() string {
	return e.Message
}

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

// UnauthorizedError is returned by japikey.Verify for every token it rejects:
// malformed, oversized, wrong version or issuer, unknown or revoked key, weak
// key, bad signature, expired, wrong audience, and so on. Its message is
// always the same fixed string, so the error can be sent to an unauthenticated
// caller (for example as an HTTP 401) without revealing why the token failed,
// and in particular without revealing whether a key ID exists or was revoked.
//
// The specific reason is kept in Cause and is reachable through errors.Is and
// errors.As (for example *KeyNotFoundError or *TokenExpiredError). Use it for
// logging and metrics only. Do not let it change the response sent to the
// caller, or the key-existence oracle that this type closes is reopened.
type UnauthorizedError struct {
	JapikeyError
	Cause error
}

// UnauthorizedMessage is the fixed message carried by every UnauthorizedError.
const UnauthorizedMessage = "unauthorized"

// NewUnauthorizedError wraps cause in an UnauthorizedError with a fixed message.
func NewUnauthorizedError(cause error) *UnauthorizedError {
	return &UnauthorizedError{
		JapikeyError: JapikeyError{
			Code:    "UnauthorizedError",
			Message: UnauthorizedMessage,
		},
		Cause: cause,
	}
}

// Unwrap returns the specific reason the token was rejected.
func (e *UnauthorizedError) Unwrap() error {
	return e.Cause
}

// KeyNotFoundError reports that a key ID does not exist or has been revoked.
// JWKCallback implementations return it, and the JWKS endpoint maps it to 404.
// Verify never returns it directly: it is wrapped in an UnauthorizedError so
// that callers cannot tell an unknown key apart from any other bad token.
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

type DatabaseTimeoutError struct {
	JapikeyError
}

func NewDatabaseTimeoutError(message string) *DatabaseTimeoutError {
	return &DatabaseTimeoutError{
		JapikeyError: JapikeyError{
			Code:    "DatabaseTimeout",
			Message: message,
		},
	}
}

type DatabaseUnavailableError struct {
	JapikeyError
}

func NewDatabaseUnavailableError(message string) *DatabaseUnavailableError {
	return &DatabaseUnavailableError{
		JapikeyError: JapikeyError{
			Code:    "DatabaseUnavailable",
			Message: message,
		},
	}
}

// TokenExpiredError reports a correctly signed token whose exp has passed.
// Verify returns it wrapped in an UnauthorizedError; use errors.As to detect it.
type TokenExpiredError struct {
	JapikeyError
}

func NewTokenExpiredError(message string) *TokenExpiredError {
	return &TokenExpiredError{
		JapikeyError: JapikeyError{
			Code:    "TokenExpiredError",
			Message: message,
		},
	}
}
