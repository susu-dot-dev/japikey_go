# Quickstart Guide

## Installation

```bash
go mod init your-project
go get github.com/susu-dot-dev/japikey
```

## Local Development

This repo is a Go workspace of four modules; use the Makefile rather than bare `go` commands.

```bash
make test    # all tests
make check   # fmt, vet, lint, test
make ci      # deps, tidy, check, build
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full list.

## Basic Usage

Mint a key:

```go
package main

import (
    "fmt"
    "time"
    "github.com/susu-dot-dev/japikey"
)

func main() {
    result, err := japikey.NewJAPIKey(japikey.Config{
        Subject: "user-123",
        // Base issuer URL; iss becomes "<Issuer>/<key id>". https, canonical,
        // no query, fragment or user info (see AllowInsecureHTTP).
        Issuer:    "https://myapp.com",
        Audience:  "myapp-users",
        ExpiresAt: time.Now().Add(24 * time.Hour),
    })
    if err != nil {
        fmt.Println(err) // *japikey.ValidationError or *japikey.InternalError
        return
    }

    // result.JWT is the secret: hand it to the user, don't log or store it.
    // Store result.PublicKey and result.KeyID.
    fmt.Printf("Key ID: %s\n", result.KeyID)
}
```

To verify keys, see [japikey/README.md](../japikey/README.md); to serve the JWKS over HTTP, see [internal/middleware/README.md](../internal/middleware/README.md).

## Requirements

- Go 1.27 or later

## JWKS (JSON Web Key Set) Support

A JWKS holds exactly one RSA key (2048 to 4096 bits).

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

### Creating JWKS from a Public Key

```go
// publicKey is an *ecdsa.PublicKey (or an *rsa.PublicKey for a version 1 key), keyID a uuid.UUID
jwks, err := japikey.NewJWKS(publicKey, keyID)
if err != nil {
    log.Fatal(err)
}
```

### Extracting Information from JWKS

```go
keyID := jwks.GetKeyID()

// *KeyNotFoundError if keyID doesn't match
publicKey, err := jwks.GetPublicKey(keyID)
```

### Deserializing JWKS from JSON

```go
// Exactly one key with exactly the fields kty, kid, n, e
var jwks japikey.JWKS
err := json.Unmarshal([]byte(jsonStr), &jwks) // *ValidationError on bad input
```

## Next Steps

Examples (run with `make examples`):
- `example/basic/main.go`: minting keys
- `example/jwks/main.go`: JWKS conversion
