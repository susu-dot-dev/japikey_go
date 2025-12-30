# Quickstart Guide: JAPIKey Signing Library

## Installation

```bash
go get github.com/your-org/japikey
```

## Basic Usage

### Creating a JAPIKey

```go
package main

import (
    "fmt"
    "time"
    "github.com/your-org/japikey"
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
    result, err := japikey.CreateJAPIKey(config)
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

## Adding Custom Claims

```go
config := japikey.Config{
    Subject:   "user-123",
    Issuer:    "https://myapp.com",
    Audience:  "myapp-users",
    ExpiresAt: time.Now().Add(24 * time.Hour),
    Claims: jwt.MapClaims{
        "role": "admin",
        "permissions": []string{"read", "write"},
        "custom_field": "custom_value",
    },
}

result, err := japikey.CreateJAPIKey(config)
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
_, err := japikey.CreateJAPIKey(config)
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