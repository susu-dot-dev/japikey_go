# JWK Conversion API Contract

## Overview
This document describes the interface for the JWK (JSON Web Key) conversion functionality in the JAPIKey library.

The library provides functions to convert between JAPIKey structures and JWKS (JSON Web Key Sets) format, following RFC 7517 and RFC 7518 standards. The implementation uses Go's built-in crypto libraries to ensure security and compliance.

## Functions

### NewJWKS(publicKey *rsa.PublicKey, kid uuid.UUID) (*JWKS, error)

Creates a new JWKS containing exactly one RSA key from a public key and key ID, following RFC 7517/7518 standards.

#### Parameters
- `publicKey` (*rsa.PublicKey): The RSA public key to include in the JWK
- `kid` (uuid.UUID): The key identifier (must be a valid UUID)

#### Returns
- `*JWKS`: A pointer to the JWKS struct containing the single JWK
- `error`: An error if the operation failed, nil otherwise

#### Errors
- `InvalidJWKError`: When input parameters fail validation (e.g., invalid key ID format)
- `UnexpectedConversionError`: When the conversion from public key to JWK fails

### (j *JAPIKey) ToJWKS() (*JWKS, error)

Helper method to convert a JAPIKey to JWKS format.

#### Parameters
- None (method on JAPIKey struct)

#### Returns
- `*JWKS`: A pointer to the JWKS struct containing the single JWK
- `error`: An error if the operation failed, nil otherwise

#### Errors
- `InvalidJWKError`: When JAPIKey fields fail validation (e.g., invalid key ID format)
- `UnexpectedConversionError`: When the conversion from JAPIKey to JWK fails

## Methods

### (j *JWKS) GetPublicKey(kid uuid.UUID) (*rsa.PublicKey, error)

Extracts the RSA public key from the JWKS for a given key ID.

#### Parameters
- `kid` (uuid.UUID): The key identifier to look for

#### Returns
- `*rsa.PublicKey`: The RSA public key associated with the given key ID
- `error`: An error if the operation failed, nil otherwise

#### Errors
- `KeyNotFoundError`: When the requested key ID is not present in the JWKS
- `InvalidJWKError`: When the JWKS contains invalid RSA parameters

### (j *JWKS) GetKeyID() (uuid.UUID, error)

Retrieves the key ID present in the JWKS.

#### Parameters
- None

#### Returns
- `uuid.UUID`: The key ID present in the JWKS
- `error`: An error if the operation failed, nil otherwise

#### Errors
- `InvalidJWKError`: When the JWKS contains invalid key ID format

## Re-exports

The top-level package re-exports the following types and functions from the internal jwks package:

- `JWKS` type as the primary data type for JSON Web Key Sets
- `NewJWKS` function as the constructor for creating JWKS
- Error types: `InvalidJWKError`, `UnexpectedConversionError`, `KeyNotFoundError`

## Types

### JWKS
```go
type JWKS struct {
    keys []JWK // Array containing exactly one JWK
}
```

### JWK
```go
type JWK struct {
    kty string    // Always "RSA" to identify the key type
    kid uuid.UUID // The key identifier (UUID format)
    n   string    // The RSA modulus encoded as Base64urlUInt
    e   string    // The RSA exponent encoded as Base64urlUInt
}
```

### InvalidJWKError
```go
type InvalidJWKError struct {
    Message string // Human-readable error message
    Code    string // Error code identifier ("InvalidJWK")
}
```

### UnexpectedConversionError
```go
type UnexpectedConversionError struct {
    Message string // Human-readable error message
    Code    string // Error code identifier ("UnexpectedConversionError")
}
```

### KeyNotFoundError
```go
type KeyNotFoundError struct {
    Message string // Human-readable error message
    Code    string // Error code identifier ("KeyNotFoundError")
}
```

## JSON Serialization

The JWKS type implements custom MarshalJSON and UnmarshalJSON methods to control the exact serialization format:

### JSON Output Format
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "123e4567-e89b-12d3-a456-426614174000",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdM...",
      "e": "AQAB"
    }
  ]
}
```

### Base64urlUInt Encoding
- RSA modulus (n) and exponent (e) are encoded as Base64urlUInt values according to RFC 7518
- Uses unpadded base64url encoding (no '=' characters)
- Positive integer values represented as the base64url encoding of the value's unsigned big-endian representation