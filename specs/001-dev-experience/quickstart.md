# Quickstart Guide

## Installation

To use japikey_go in your project, simply add it as a Go module:

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

Here's a minimal example to get started with japikey_go:

```go
package main

import (
    "fmt"
    "time"
    "github.com/susu-dot-dev/japikey-go/japikey"
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

## Requirements

- Go 1.21 or later
- Linux or Mac operating system

## Next Steps

Check out the example in the `example/` directory for a complete example of basic functionality.