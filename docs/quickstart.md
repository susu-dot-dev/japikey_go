# Quickstart Guide

## Installation

To use japikey-go in your project, simply add it as a Go module:

```bash
go mod init your-project
go get github.com/susu-dot-dev/japikey-go
```

## Local Development

For local development, we provide a Makefile with common commands:

```bash
# Run tests
make test

# Format code
make fmt

# Run linting
make lint

# Run all checks (format, vet, lint, test)
make check

# Build the project
make build

# Run all checks and build (for CI)
make ci
```

## Basic Usage

Here's a minimal example to get started with japikey-go:

```go
package main

import (
    "fmt"
    "time"
    "github.com/susu-dot-dev/japikey-go"
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
        if validationErr, ok := err.(*japikey.ValidationError); ok {
            fmt.Printf("Validation error: %s\n", validationErr.Error())
        } else if internalErr, ok := err.(*japikey.InternalError); ok {
            fmt.Printf("Internal error: %s\n", internalErr.Error())
        }
        return
    }

    // Use the generated JWT and public key
    fmt.Printf("Generated JWT: %s\n", result.JWT)
    fmt.Printf("Key ID: %s\n", result.KeyID)
    fmt.Printf("Public Key: %+v\n", result.PublicKey)
}
```

## Requirements

- Go 1.21 or later
- Linux or Mac operating system

## JWKS (JSON Web Key Set) Support

The library also provides support for converting JAPIKeys to JWKS format and working with JWKS:

### Converting JAPIKey to JWKS

```go
// Create a JAPIKey
japikeyResult, err := japikey.NewJAPIKey(config)
if err != nil {
    log.Fatal(err)
}

// Convert to JWKS
jwks, err := japikeyResult.ToJWKS()
if err != nil {
    log.Fatal(err)
}

// Serialize to JSON
jwksJSON, err := json.Marshal(jwks)
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(jwksJSON))
```

### Creating JWKS from RSA Public Key

```go
import (
    "crypto/rsa"
    "github.com/google/uuid"
)

// Create JWKS directly from RSA public key and UUID
publicKey := /* your RSA public key */
keyID := uuid.Must(uuid.Parse("123e4567-e89b-12d3-a456-426614174000"))

jwks, err := japikey.NewJWKS(publicKey, keyID)
if err != nil {
    log.Fatal(err)
}
```

### Extracting Information from JWKS

```go
// Get the key ID from JWKS
keyID := jwks.GetKeyID()

// Get the public key for a specific key ID
publicKey, err := jwks.GetPublicKey(keyID)
if err != nil {
    log.Fatal(err)
}
```

### Deserializing JWKS from JSON

```go
jsonStr := `{"keys":[{"kty":"RSA","kid":"...","n":"...","e":"..."}]}`
var jwks japikey.JWKS
err := json.Unmarshal([]byte(jsonStr), &jwks)
if err != nil {
    log.Fatal(err)
}
```

## Next Steps

Check out the examples in the `example/` directory:
- `example/main.go` - Basic JAPIKey usage
- `example/jwks_example.go` - Complete JWKS examples
- `example/jwks.json` - Sample JWKS file for testing
