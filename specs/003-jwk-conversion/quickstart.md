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

The library uses structured error handling with specific error types:

```go
import (
    "path/to/japikey"
    "errors"
)

jwks, err := japikey.NewJWKS(publicKey, keyID)
if err != nil {
    var invalidJWKErr *japikey.InvalidJWKError
    var unexpectedConvErr *japikey.UnexpectedConversionError
    var keyNotFoundErr *japikey.KeyNotFoundError

    if errors.As(err, &invalidJWKErr) {
        // Handle invalid JWK error (e.g., during JSON unmarshaling)
        log.Printf("Invalid JWK: %v", err)
    } else if errors.As(err, &unexpectedConvErr) {
        // Handle unexpected conversion error (e.g., JAPIKey to JWK failure)
        log.Printf("Unexpected conversion error: %v", err)
    } else if errors.As(err, &keyNotFoundErr) {
        // Handle key not found error (e.g., kid not present in JWK)
        log.Printf("Key not found: %v", err)
    } else {
        // Handle other errors
        log.Printf("Error creating JWKS: %v", err)
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
