# JAPIKey Verification

This package provides functionality to verify JAPIKey tokens, which are JWT-based API keys with specific format requirements.

## Features

- Verify JAPIKey tokens with proper format validation
- Validate version, issuer, and key ID constraints
- Support for custom key retrieval functions
- Comprehensive error handling with detailed error types
- Pre-validation function for efficiency

## Usage

### Basic Verification

```go
package main

import (
    "fmt"
    "time"
    
    "github.com/susu-dot-dev/japikey"
)

func main() {
    // Example token string (this would come from your API request)
    tokenString := "your.jwt.token.here"
    
    // Create verification config
    config := japikey.VerifyConfig{
        BaseIssuerURL: "https://example.com/",  // Base URL for issuer validation
        Timeout:       5 * time.Second,         // Timeout for key retrieval
    }
    
    // Define a function to retrieve the public key by key ID
    keyFunc := func(keyID string) (*rsa.PublicKey, error) {
        // Implement your logic to retrieve the public key
        // This might involve fetching from a JWKS endpoint
        return retrievePublicKey(keyID)
    }
    
    // Verify the token
    result, err := japikey.Verify(tokenString, config, keyFunc)
    if err != nil {
        // Handle verification error
        if verificationErr, ok := err.(*japikey.JAPIKeyVerificationError); ok {
            fmt.Printf("Verification failed: %s (%s)\n", verificationErr.Message, verificationErr.Code)
        } else {
            fmt.Printf("Verification failed: %v\n", err)
        }
        return
    }
    
    // Use the validated claims
    fmt.Printf("Validated claims: %+v\n", result.Claims)
    fmt.Printf("Key ID: %s\n", result.KeyID)
}
```

### Pre-validation

For efficiency, you can use the pre-validation function to quickly check if a token has the correct format before performing full verification:

```go
// Check if token has correct format before full verification
isValid := japikey.ShouldVerify(tokenString, "https://example.com/")
if !isValid {
    // Token has structural issues, skip full verification
    fmt.Println("Token format is invalid")
    return
}

// Proceed with full verification
result, err := japikey.Verify(tokenString, config, keyFunc)
```

## Error Handling

The verification function returns structured errors with specific error codes:

- `TokenFormatError`: Token format is invalid
- `TokenSizeError`: Token exceeds maximum allowed size (4KB)
- `HeaderValidationError`: Header validation failed
- `AlgorithmError`: Invalid algorithm (only RS256 is supported)
- `VersionValidationError`: Version validation failed
- `IssuerValidationError`: Issuer validation failed
- `KeyIDMismatchError`: Key ID doesn't match issuer UUID
- `SignatureValidationError`: Signature verification failed
- `ExpirationError`: Token has expired
- `NotBeforeError`: Token is not yet valid
- `IssuedAtError`: Token was issued in the future
- `InjectionError`: Potential injection attack detected
- `NumericValueError`: Token contains excessively large numeric values

## Security Features

- Maximum token size limit (4KB) to prevent resource exhaustion
- Strict algorithm validation (RS256 only)
- Input sanitization to prevent injection attacks
- Proper error handling to prevent information leakage
- Constant-time operations where applicable
- Time-based claim validation with no clock skew tolerance
