# JAPIKey API Contract

## Overview
This document describes the interface for the JAPIKey signing library.

## Functions

### CreateJAPIKey(config Config) (Result, error)

Creates a new JAPIKey with the provided configuration.

#### Parameters
- `config` (Config): Configuration object containing the required and optional parameters

#### Returns
- `Result`: A result object containing the generated JWT, public key, and other metadata
- `error`: An error if the operation failed, nil otherwise

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