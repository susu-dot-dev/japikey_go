# Example Interface Contract

## Package: example

### Function: main()

**Signature**: `func main()`

**Purpose**: Demonstrates how to use the japikey functionality to generate secure API keys.

**Input**: None

**Output**:
- Generated JWT: A signed JSON Web Token
- Key ID: A unique identifier for the key
- Public Key: The RSA public key component

**Error Handling**: Handles validation, generation, and signing errors with appropriate error types.

**Usage Example**:
```go
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
```

## Package: example (Alternative function with custom claims)

### Function: main() with custom claims

**Signature**: `func main()`

**Purpose**: Demonstrates how to use the japikey functionality with custom claims to add additional information to the API key.

**Input**:
- config: japikey.Config with custom claims

**Output**:
- JWT string with custom claims
- error: nil in success cases

**Error Handling**: Handles validation, generation, and signing errors with appropriate error types.

**Usage Example**:
```go
config := japikey.Config{
    Subject:   "user-123",
    Issuer:    "https://myapp.com",
    Audience:  "myapp-users",
    ExpiresAt: time.Now().Add(24 * time.Hour),
    Claims: map[string]interface{}{
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