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

// KeyNotFoundError is kept separate because clients may need different behavior
// (e.g., retry with different key, fetch from different source)
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

