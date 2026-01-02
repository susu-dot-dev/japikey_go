# Quickstart: JWK Conversion Support

## Overview
This library provides functionality to convert JAPIKeys to JWKS (JSON Web Key Sets) format and vice versa, following RFC 7517 and RFC 7518 standards. The implementation uses Go's built-in crypto libraries to ensure security and compliance. The JWK-related types and functions are re-exported from the top-level japikey package for easy access.

## Installation
```bash
# The JWKS functionality is part of the main japikey library
# No additional installation required
```

## Basic Usage

### Creating a JWKS from an RSA Public Key
```go
import (
    "path/to/japikey"
    "github.com/google/uuid"
)

// Create a JWKS from an RSA public key and key ID
publicKey := /* your RSA public key */
keyID := uuid.Must(uuid.Parse("123e4567-e89b-12d3-a456-426614174000")) // UUID type

jwks, err := japikey.NewJWKS(publicKey, keyID)
if err != nil {
    // Handle error (e.g., invalid key ID, nil public key)
    log.Fatal(err)
}

// Serialize to JSON
jsonBytes, err := json.Marshal(jwks)
if err != nil {
    log.Fatal(err)
}

fmt.Println(string(jsonBytes))
// Output: {"keys":[{"kty":"RSA","kid":"123e4567-e89b-12d3-a456-426614174000","n":"...","e":"..."}]}
```

### Converting a JAPIKey to JWKS
```go
import (
    "path/to/japikey"
    "github.com/google/uuid"
)

// Assuming you have a JAPIKey instance with UUID type KeyID
japiKey := /* your JAPIKey instance with UUID type KeyID */

jwks, err := japiKey.ToJWKS()
if err != nil {
    // Handle error
    log.Fatal(err)
}
```

### Extracting Public Key from JWKS
```go
import (
    "path/to/japikey"
    "github.com/google/uuid"
)

// Extract public key for a specific key ID
keyID := uuid.Must(uuid.Parse("123e4567-e89b-12d3-a456-426614174000")) // UUID type
jwks := /* your JWKS instance */

publicKey, err := jwks.GetPublicKey(keyID)
if err != nil {
    // Handle error (e.g., key not found, invalid JWKS)
    log.Fatal(err)
}
```

### Getting Key ID from JWKS
```go
import (
    "path/to/japikey"
    "github.com/google/uuid"
)

// Get the key ID present in the JWKS
jwks := /* your JWKS instance */
keyID, err := jwks.GetKeyID()
if err != nil {
    // Handle error
    log.Fatal(err)
}
// keyID is of type uuid.UUID
```

### Deserializing JWKS from JSON
```go
import (
    "encoding/json"
    "path/to/japikey"
    "github.com/google/uuid"
)

jsonStr := `{"keys":[{"kty":"RSA","kid":"123e4567-e89b-12d3-a456-426614174000","n":"...","e":"..."}]}`
var jwks japikey.JWKS
err := json.Unmarshal([]byte(jsonStr), &jwks)
if err != nil {
    log.Fatal(err)
}
// The internal UUID type ensures the kid field is always a valid UUID
```

## Verification Tool

To verify that our JWKS output matches the format of established libraries:

1. Run the jwx CLI tool in the jwx/ folder to generate test data:
```bash
make generate-jwks-test-data
```

2. The tool will create `example/jwks.json` with JWKS generated using lestrrat-go/jwx/jwk for comparison.

## Error Handling

The library uses structured error handling with an inheritance model. All errors inherit from a base `JapikeyError` type and are constructed using factory functions.

### Error Types

- **ValidationError**: Input validation failures (invalid JWK format, invalid RSA parameters, invalid key ID format)
- **ConversionError**: Cryptographic conversion failures (JAPIKey to JWK conversion, encoding failures)
- **KeyNotFoundError**: Requested key ID not found in JWKS (kept separate for client-specific handling)
- **InternalError**: Internal operation failures (key generation, signing failures)

### Error Handling Example

```go
import (
    "path/to/japikey"
    "errors"
)

jwks, err := japikey.NewJWKS(publicKey, keyID)
if err != nil {
    var validationErr *japikey.ValidationError
    var conversionErr *japikey.ConversionError
    var keyNotFoundErr *japikey.KeyNotFoundError
    var internalErr *japikey.InternalError

    if errors.As(err, &validationErr) {
        // Handle validation error (e.g., invalid key ID, invalid JWK format)
        log.Printf("Validation error: %v", err)
        // Access error code: validationErr.Code (will be "ValidationError")
        // Access message: validationErr.Message or err.Error()
    } else if errors.As(err, &conversionErr) {
        // Handle conversion error (e.g., JAPIKey to JWK failure, encoding failures)
        log.Printf("Conversion error: %v", err)
    } else if errors.As(err, &keyNotFoundErr) {
        // Handle key not found error (e.g., kid not present in JWK)
        // This may require different handling like fetching from another source
        log.Printf("Key not found: %v", err)
    } else if errors.As(err, &internalErr) {
        // Handle internal error (e.g., key generation failure)
        log.Printf("Internal error: %v", err)
    } else {
        // Handle other errors
        log.Printf("Error creating JWKS: %v", err)
    }
}
```

### Error Construction

Errors are constructed using factory functions that automatically set the appropriate error code:

```go
// In library code:
if kid == uuid.Nil {
    return errors.NewValidationError("key ID cannot be empty")
}

if j.jwk.kid != kid {
    return errors.NewKeyNotFoundError("key ID not found in JWKS")
}

if jwks.jwk.n != ejwk.N {
    return errors.NewConversionError("round-trip validation failed: n values do not match")
}
```

### Accessing Error Information

All errors provide both a `Code` and `Message` field:

```go
if err != nil {
    // Access the error message
    message := err.Error() // or err.Message if type-asserted
    
    // Type assert to access Code field
    if japikeyErr, ok := err.(interface{ Code() string }); ok {
        code := japikeyErr.Code()
        switch code {
        case "ValidationError":
            // Handle validation
        case "KeyNotFoundError":
            // Handle missing key (may need different behavior)
        }
    }
}
```

## Supported Formats

- **Key Type**: RSA only (kty="RSA")
- **Key ID**: UUID format
- **RSA Parameters**: 
  - Modulus (n): Base64urlUInt encoding
  - Exponent (e): Base64urlUInt encoding
- **JSON Format**: Standard JWKS format with "keys" array containing exactly one key
