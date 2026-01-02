# Quickstart: JAPIKey Verification Function

## Overview
This guide provides a quick introduction to using the JAPIKey verification function in Go.

## Installation

```bash
go mod init your-project
go get github.com/golang-jwt/jwt/v5
go get golang.org/x/crypto
```

## Basic Usage

### Import the Package
```go
import (
    "github.com/your-org/japikey_go/japikey"
)
```

### Define Configuration
```go
config := japikey.Config{
    BaseIssuer: "https://example.com/",  // Base URL for issuer validation
    GetJWKSCallback: func(keyID string) ([]byte, error) {
        // Implement your logic to retrieve JWK by key ID
        // This is typically an HTTP request to {baseIssuer}/.well-known/jwks.json
        return retrieveJWK(keyID)
    },
    Timeout: 5 * time.Second,  // Configurable timeout for key retrieval (> 0)
}
```

### Verify a JAPIKey Token
```go
tokenString := "your.japikey.token.here"

claims, err := japikey.Verify(tokenString, config)
if err != nil {
    // Handle error - detailed structured error with verbose message
    fmt.Printf("Verification failed: %v\n", err)
    return
}

// Use the validated claims
fmt.Printf("Validated claims: %+v\n", claims)
```

## Advanced Usage

### Custom Error Handling
```go
claims, err := japikey.Verify(tokenString, config)
if err != nil {
    // Type assert to get detailed error information
    if structuredErr, ok := err.(*japikey.StructuredError); ok {
        fmt.Printf("Error Type: %s\n", structuredErr.ErrorType)
        fmt.Printf("Message: %s\n", structuredErr.Message)
        fmt.Printf("Details: %+v\n", structuredErr.Details)
    }
    return
}
```

### Pre-validation
```go
// Check if a token should be validated before full verification
isValidFormat := japikey.ShouldVerify(tokenString, config.BaseIssuer)
if !isValidFormat {
    // Token has structural issues, skip full verification
    fmt.Println("Token format is invalid")
    return
}

// Proceed with full verification
claims, err := japikey.Verify(tokenString, config)
```

## Configuration Options

### Required Configuration
- `BaseIssuer`: Base URL for validating the issuer field in tokens
- `GetJWKSCallback`: Function to retrieve cryptographic keys by key ID
- `Timeout`: Timeout for key retrieval (must be greater than 0)

### Optional Configuration
- Additional JWT verification options can be passed if needed

## Error Handling

The verification function returns detailed structured errors with verbose messages for debugging:

- `VERSION_VALIDATION_ERROR`: Token version is invalid or exceeds maximum allowed
- `ISSUER_VALIDATION_ERROR`: Token issuer doesn't match expected format
- `KEY_ID_MISMATCH_ERROR`: Key ID in header doesn't match UUID from issuer
- `SIGNATURE_VERIFICATION_ERROR`: Token signature verification failed
- `EXPIRATION_ERROR`: Token has expired
- `NOT_BEFORE_ERROR`: Token is not yet valid
- `TOKEN_SIZE_ERROR`: Token exceeds maximum allowed size (4KB)
- `ALGORITHM_ERROR`: Token uses unsupported algorithm
- `MALFORMED_TOKEN_ERROR`: Token structure is invalid

Outer HTTP handlers can sanitize these detailed errors for end users while preserving debug information for developers.

## Security Considerations

1. **Timeout Configuration**: Always set a reasonable timeout for key retrieval to prevent hanging requests
2. **Token Size**: The function enforces a 4KB maximum to prevent resource exhaustion
3. **Time Validation**: Strict time matching is used with no clock skew tolerance; 'exp' claim is required, but 'nbf' and 'iat' are optional
4. **Algorithm Validation**: Only RS256 algorithm is accepted
5. **Constant-time Operations**: Signature verification uses constant-time comparisons to prevent timing attacks