# JAPIKey API Contract

## Overview
This document describes the interface for the JAPIKey signing library.

The library provides a top-level package that re-exports the API surface from the internal japikey package, making it available at the module root level for easier imports.

## Functions

### NewJAPIKey(config Config) (*JAPIKey, error)

Creates a new JAPIKey with the provided configuration using the standard Go constructor pattern.

#### Parameters
- `config` (Config): Configuration object containing the required and optional parameters

#### Returns
- `*JAPIKey`: A pointer to the JAPIKey struct containing the generated JWT, public key, and other metadata
- `error`: An error if the operation failed, nil otherwise

## Re-exports

The top-level package re-exports the following types and functions from the internal japikey package:

- `Config` type for configuration
- `JAPIKey` type as the primary data type
- `NewJAPIKey` function as the constructor
- Error types: `JAPIKeyValidationError`, `JAPIKeyGenerationError`, `JAPIKeySigningError`

#### Errors
- `JAPIKeyValidationError`: When input parameters fail validation
- `JAPIKeyGenerationError`: When cryptographic operations fail during key generation
- `JAPIKeySigningError`: When JWT signing operations fail

## Types

### Config
```go
type Config struct {
    Subject   string          // Required: Subject identifier
    Issuer    string          // Required: Issuer identifier (URL format)
    Audience  string          // Required: Audience identifier
    ExpiresAt time.Time       // Required: Expiration time (must be in the future)
    Claims    jwt.MapClaims   // Optional: Additional claims to include in the JWT
}
```

### JAPIKey
```go
type JAPIKey struct {
    JWT       string                    // The signed JWT token
    PublicKey *rsa.PublicKey            // The RSA public key for verification
    KeyID     string                    // The unique identifier for the key pair
}
```

### JAPIKeyValidationError
```go
type JAPIKeyValidationError struct {
    Message string // Human-readable error message
    Code    string // Error code identifier ("ValidationError")
}
```

### JAPIKeyGenerationError
```go
type JAPIKeyGenerationError struct {
    Message string // Human-readable error message
    Code    string // Error code identifier ("KeyGenerationError")
}
```

### JAPIKeySigningError
```go
type JAPIKeySigningError struct {
    Message string // Human-readable error message
    Code    string // Error code identifier ("SigningError")
}
```