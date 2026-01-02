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
- `ValidationError`: When input parameters fail validation (e.g., invalid key ID format, nil public key)
- `ConversionError`: When the conversion from public key to JWK fails during cryptographic operations

### (j *JAPIKey) ToJWKS() (*JWKS, error)

Helper method to convert a JAPIKey to JWKS format.

#### Parameters
- None (method on JAPIKey struct)

#### Returns
- `*JWKS`: A pointer to the JWKS struct containing the single JWK
- `error`: An error if the operation failed, nil otherwise

#### Errors
- `ValidationError`: When JAPIKey fields fail validation (e.g., invalid key ID format, nil public key)
- `ConversionError`: When the conversion from JAPIKey to JWK fails during cryptographic operations

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
- `ValidationError`: When the JWKS contains invalid RSA parameters or fails validation

### (j *JWKS) GetKeyID() (uuid.UUID, error)

Retrieves the key ID present in the JWKS.

#### Parameters
- None

#### Returns
- `uuid.UUID`: The key ID present in the JWKS
- `error`: An error if the operation failed, nil otherwise

#### Errors
- `ValidationError`: When the JWKS contains invalid key ID format or fails validation

## Re-exports

The top-level package re-exports the following types and functions from the internal jwks package:

- `JWKS` type as the primary data type for JSON Web Key Sets
- `NewJWKS` function as the constructor for creating JWKS
- Error types: `ValidationError`, `ConversionError`, `KeyNotFoundError`, `InternalError`

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

## Error Types and Inheritance Model

All error types in the japikey library follow a standardized inheritance model with a base `JapikeyError` type that provides a consistent structure across all error types.

### Base Error Type: JapikeyError

```go
type JapikeyError struct {
    Code    string // Error code identifier (e.g., "ValidationError", "ConversionError")
    Message string // Human-readable error message with contextual details
}

func (e *JapikeyError) Error() string {
    return e.Message
}
```

All specific error types embed `JapikeyError` and set the appropriate code during construction. This ensures consistent error handling and allows clients to access both the error code and message.

### Error Construction

Errors are constructed using factory functions that automatically set the correct error code:

```go
// ValidationError is returned when input parameters fail validation
validationErr := errors.NewValidationError("key ID cannot be empty")

// ConversionError is returned when cryptographic operations fail during conversion
conversionErr := errors.NewConversionError("round-trip validation failed: n values do not match")

// KeyNotFoundError is returned when the requested key ID is not present in the JWKS
keyNotFoundErr := errors.NewKeyNotFoundError("key ID not found in JWKS")

// InternalError is returned when internal operations fail
internalErr := errors.NewInternalError("failed to generate RSA key pair")
```

### Specific Error Types

#### ValidationError

Returned when input parameters fail validation. This includes:
- Invalid JWK format during JSON unmarshaling
- Invalid RSA parameters (e.g., invalid Base64urlUInt encoding)
- Invalid key ID format (e.g., empty or non-UUID)
- Missing required fields
- Invalid field values

```go
type ValidationError struct {
    JapikeyError // Embeds base error with Code="ValidationError" and Message
}

func NewValidationError(message string) *ValidationError
```

**Usage Example:**
```go
if kid == uuid.Nil {
    return errors.NewValidationError("key ID cannot be empty")
}
```

#### ConversionError

Returned when cryptographic operations fail during conversion. This includes:
- Failures to convert JAPIKey to JWK
- Failures to encode RSA parameters
- Round-trip validation failures

```go
type ConversionError struct {
    JapikeyError // Embeds base error with Code="ConversionError" and Message
}

func NewConversionError(message string) *ConversionError
```

**Usage Example:**
```go
if jwks.jwk.n != ejwk.N || jwks.jwk.e != ejwk.E {
    return errors.NewConversionError("round-trip validation failed: n values do not match")
}
```

#### KeyNotFoundError

Returned when the requested key ID is not present in the JWKS. This error type is kept separate from validation errors because clients may need to handle missing keys differently (e.g., retry with a different key, fetch from a different source).

```go
type KeyNotFoundError struct {
    JapikeyError // Embeds base error with Code="KeyNotFoundError" and Message
}

func NewKeyNotFoundError(message string) *KeyNotFoundError
```

**Usage Example:**
```go
if j.jwk.kid != kid {
    return errors.NewKeyNotFoundError("key ID not found in JWKS")
}
```

#### InternalError

Returned when internal operations fail. This includes:
- Key generation failures
- Signing failures
- Other internal cryptographic operation failures

```go
type InternalError struct {
    JapikeyError // Embeds base error with Code="InternalError" and Message
}

func NewInternalError(message string) *InternalError
```

**Usage Example:**
```go
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
    return nil, errors.NewInternalError("failed to generate RSA key pair")
}
```

### Error Handling Best Practices

1. **Use Type Assertions**: Check for specific error types when different handling is required:
   ```go
   if validationErr, ok := err.(*japikey.ValidationError); ok {
       // Handle validation errors
   } else if keyNotFoundErr, ok := err.(*japikey.KeyNotFoundError); ok {
       // Handle missing key (may need to fetch from different source)
   }
   ```

2. **Access Error Code**: All errors provide a `Code` field for programmatic error handling:
   ```go
   if err != nil {
       japikeyErr, ok := err.(*errors.JapikeyError)
       if ok {
           switch japikeyErr.Code {
           case "ValidationError":
               // Handle validation
           case "KeyNotFoundError":
               // Handle missing key
           }
       }
   }
   ```

3. **Error Messages**: Error messages provide contextual information about what went wrong. Use the `Message` field or call `Error()` method for human-readable error details.

### Error Categories

Errors are categorized to minimize the number of unique error types while maintaining sufficient granularity for client handling:

- **ValidationError**: Generic validation failures with contextual messages
- **ConversionError**: Conversion-specific failures with contextual messages
- **KeyNotFoundError**: Unique error type for missing keys (clients need different behavior)
- **InternalError**: Internal operation failures (typically not recoverable by clients)

This design balances simplicity (fewer error types) with utility (specific types where clients need different behavior).

## JSON Serialization

The JWKS type implements custom `MarshalJSON` and `UnmarshalJSON` methods to control the exact serialization format and ensure strict validation.

### Internal Data Structures

The implementation uses separate structs for the in-memory representation and JSON representation:

```go
// In-memory representation (lowercase fields for encapsulation)
type JWK struct {
    kid       uuid.UUID      // The key identifier (UUID format)
    n         string         // The RSA modulus encoded as Base64urlUInt
    e         string         // The RSA exponent encoded as Base64urlUInt
    publicKey *rsa.PublicKey // The RSA public key
}

type JWKS struct {
    jwk JWK // Single JWK (simplified in-memory representation)
}

// JSON representation (exported fields for marshaling)
type encodedJWK struct {
    Kty string    `json:"kty"`
    Kid uuid.UUID `json:"kid"`
    N   string    `json:"n"`
    E   string    `json:"e"`
}

type encodedJWKS struct {
    Keys []encodedJWK `json:"keys"`
}
```

### MarshalJSON Implementation

The `MarshalJSON` method converts the in-memory JWKS structure to the standard JWKS JSON format:

1. Creates an `encodedJWKS` struct with a `Keys` array containing exactly one `encodedJWK`
2. Sets `Kty` to "RSA"
3. Copies `kid`, `n`, and `e` from the in-memory JWK to the encoded JWK
4. Uses standard `json.Marshal` to serialize the `encodedJWKS` struct

**Implementation Pattern:**
```go
func (j *JWKS) MarshalJSON() ([]byte, error) {
    ejwks := encodedJWKS{
        Keys: []encodedJWK{
            {
                Kty: "RSA",
                Kid: j.jwk.kid,
                N:   j.jwk.n,
                E:   j.jwk.e,
            },
        },
    }
    return json.Marshal(ejwks)
}
```

### UnmarshalJSON Implementation

The `UnmarshalJSON` method performs a **two-phase validation and deserialization process** to ensure strict compliance with the JWKS format:

#### Phase 1: JSON Shape Validation (`validateJSONShape`)

Before attempting typed unmarshaling, the method validates the JSON structure using untyped unmarshaling:

1. **Unmarshal into untyped structure**: Uses `map[string]interface{}` to detect extra fields that Go would otherwise ignore
2. **Validate keys array**: Ensures the `keys` array exists and contains exactly one element
3. **Validate JWK fields**: Ensures the single JWK object contains exactly 4 fields: `kty`, `kid`, `n`, `e`
4. **Validate field presence**: Checks that each required field exists in the JWK object

**Error Handling**: All validation failures in this phase return `ValidationError` with contextual messages:
- "invalid JWKS JSON format: ..." for JSON parsing errors
- "JWKS must contain exactly one key" for incorrect array length
- "JWK must contain exactly 4 fields: kty, kid, n, e" for incorrect field count
- "JWK must contain '<field>' field" for missing required fields

#### Phase 2: Typed Unmarshaling and Validation

After shape validation passes, the method performs typed unmarshaling:

1. **Unmarshal into encodedJWKS**: Uses the typed `encodedJWKS` struct to unmarshal the JSON
2. **Validate kty parameter**: Ensures `kty` equals "RSA" (returns `ValidationError` if not)
3. **Decode Base64urlUInt values**: 
   - Decodes `n` (modulus) using `base64urlUIntDecode()` (returns `ValidationError` on failure)
   - Decodes `e` (exponent) using `base64urlUIntDecode()` (returns `ValidationError` on failure)
4. **Construct RSA public key**: Creates `*rsa.PublicKey` from decoded modulus and exponent
5. **Use NewJWKS constructor**: Calls `NewJWKS()` to create a validated JWKS instance (re-validates key ID and public key)
6. **Round-trip validation**: Compares the encoded `n` and `e` values from JSON with the re-encoded values from the constructed JWKS to ensure encoding consistency (returns `ConversionError` if mismatch)

**Implementation Pattern:**
```go
func (j *JWKS) UnmarshalJSON(data []byte) error {
    // Phase 1: Validate JSON shape
    if err := j.validateJSONShape(data); err != nil {
        return err
    }
    
    // Phase 2: Typed unmarshaling
    ejwks := encodedJWKS{}
    if err := json.Unmarshal(data, &ejwks); err != nil {
        return errors.NewValidationError("invalid JWKS JSON format: " + err.Error())
    }
    
    ejwk := ejwks.Keys[0]
    
    // Validate kty
    if ejwk.Kty != "RSA" {
        return errors.NewValidationError("kty parameter must be 'RSA'")
    }
    
    // Decode Base64urlUInt values
    modulus, err := base64urlUIntDecode(ejwk.N)
    if err != nil {
        return errors.NewValidationError("failed to decode modulus: " + err.Error())
    }
    
    exponent, err := base64urlUIntDecode(ejwk.E)
    if err != nil {
        return errors.NewValidationError("failed to decode exponent: " + err.Error())
    }
    
    // Construct RSA public key
    publicKey := &rsa.PublicKey{
        N: modulus,
        E: int(exponent.Int64()),
    }
    
    // Use constructor for validation
    jwks, err := NewJWKS(publicKey, ejwk.Kid)
    if err != nil {
        return err
    }
    
    // Round-trip validation
    if jwks.jwk.n != ejwk.N || jwks.jwk.e != ejwk.E {
        return errors.NewConversionError("round-trip validation failed: n values do not match")
    }
    
    j.jwk = jwks.jwk
    return nil
}
```

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
- Zero values are represented as "AA" (BASE64URL(single zero-valued octet))

### Validation Guarantees

The two-phase unmarshaling process ensures:

1. **No extra fields**: The untyped validation phase detects any extra fields that would be silently ignored
2. **Exact field count**: Only exactly 4 fields (`kty`, `kid`, `n`, `e`) are allowed in the JWK
3. **Exact key count**: Only exactly one key is allowed in the JWKS
4. **Type safety**: All values are validated for correct types and formats
5. **Encoding consistency**: Round-trip validation ensures Base64urlUInt encoding is correct
6. **Constructor reuse**: Uses `NewJWKS()` constructor to ensure all validation rules are applied consistently
