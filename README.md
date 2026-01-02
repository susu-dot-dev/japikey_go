# JAPIKey

JAPIKey is a Go library for generating and verifying secure API keys using JWT technology. It follows the japikey specification and provides both generation and verification of API keys with proper cryptographic signatures without storing secrets in a database.

## Installation

```bash
go get github.com/susu-dot-dev/japikey
```

## Usage

### Generation

```go
package main

import (
    "fmt"
    "time"
    "github.com/susu-dot-dev/japikey"
)

func main() {
    // Create a config with required fields
    config := japikey.Config{
        Subject:   "user-123",
        Issuer:    "https://myapp.com",
        Audience:  "myapp-users",
        ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hours from now
    }

    // Generate the JAPIKey
    result, err := japikey.NewJAPIKey(config)
    if err != nil {
        // Handle error appropriately
        if validationErr, ok := err.(*japikey.JAPIKeyValidationError); ok {
            fmt.Printf("Validation error: %s\n", validationErr.Message)
        } else if genErr, ok := err.(*japikey.JAPIKeyGenerationError); ok {
            fmt.Printf("Generation error: %s\n", genErr.Message)
        } else if signingErr, ok := err.(*japikey.JAPIKeySigningError); ok {
            fmt.Printf("Signing error: %s\n", signingErr.Message)
        }
        return
    }

    // Use the generated JWT and public key
    fmt.Printf("Generated JWT: %s\n", result.JWT)
    fmt.Printf("Key ID: %s\n", result.KeyID)
    fmt.Printf("Public Key: %+v\n", result.PublicKey)
}
```

### Verification

```go
package main

import (
    "crypto/rsa"
    "fmt"
    "time"
    "github.com/susu-dot-dev/japikey"
)

func main() {
    // Example token string (this would come from your API request)
    tokenString := "your.jwt.token.here"

    // Create verification config
    config := japikey.VerifyConfig{
        BaseIssuerURL: "https://myapp.com/",  // Base URL for issuer validation
        Timeout:       5 * time.Second,       // Timeout for key retrieval
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

// Example function to retrieve public key by key ID
func retrievePublicKey(keyID string) (*rsa.PublicKey, error) {
    // This is a placeholder implementation
    // In a real application, you would fetch the key from a JWKS endpoint
    // or from a local cache of known public keys
    return nil, fmt.Errorf("not implemented")
}
```

### Adding Custom Claims

```go
config := japikey.Config{
    Subject:   "user-123",
    Issuer:    "https://myapp.com",
    Audience:  "myapp-users",
    ExpiresAt: time.Now().Add(24 * time.Hour),
    Claims: map[string]interface{}{
        "role": "admin",
        "permissions": []string{"read", "write"},
        "custom_field": "custom_value",
    },
}

result, err := japikey.NewJAPIKey(config)
if err != nil {
    // Handle error...
    return
}

fmt.Printf("JWT with custom claims: %s\n", result.JWT)
```

## Error Handling

The library provides structured error types for different failure scenarios:

- `JAPIKeyValidationError`: Input validation failures
- `JAPIKeyGenerationError`: Cryptographic key generation failures
- `JAPIKeySigningError`: JWT signing failures

Use type assertions to handle specific error cases:

```go
_, err := japikey.NewJAPIKey(config)
if err != nil {
    switch err := err.(type) {
    case *japikey.JAPIKeyValidationError:
        // Handle validation error
        fmt.Printf("Validation failed: %s\n", err.Message)
    case *japikey.JAPIKeyGenerationError:
        // Handle generation error
        fmt.Printf("Key generation failed: %s\n", err.Message)
    case *japikey.JAPIKeySigningError:
        // Handle signing error
        fmt.Printf("Signing failed: %s\n", err.Message)
    default:
        // Handle other errors
        fmt.Printf("Unexpected error: %v\n", err)
    }
}
```

## Security

- Each API key is generated with a unique RSA key pair (2048-bit)
- Private keys are discarded immediately after signing to ensure they're never stored
- The library follows JWT standards (RFC 7519) for token structure and claims
- Thread-safe operation is supported for concurrent API key generation requests

## License

This project is licensed under the terms specified in the LICENSE file.
