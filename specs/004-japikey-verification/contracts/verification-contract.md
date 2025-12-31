# API Contract: JAPIKey Verification

## Overview
This document specifies the interface contract for the JAPIKey verification function.

## Function Signature

```go
func Verify(tokenString string, config Config) (jwt.MapClaims, error)
```

## Input Parameters

### tokenString (string, required)
- **Description**: The JAPIKey token to verify in JWT format
- **Format**: Base64UrlEncoded.Header.Base64UrlEncoded.Payload.Base64UrlEncoded.Signature
- **Size Limit**: Must not exceed 4KB
- **Validation**: Must follow JWT format with header, payload, and signature

### config (Config, required)
- **Description**: Configuration parameters for token verification

#### Config Fields:
- **BaseIssuer** (string, required)
  - Base URL for validating the issuer field in tokens
  - Format: Valid URL string ending with "/"
  - Example: "https://example.com/"

- **GetJWKSCallback** (func(string) ([]byte, error), required)
  - Function to retrieve cryptographic keys by key ID
  - Takes key ID as string parameter
  - Returns JWK as byte array or error

- **Timeout** (time.Duration, required)
  - Timeout for key retrieval operations
  - Must be greater than 0
  - Default: 5 seconds

## Return Values

### Success Case
- **Type**: jwt.MapClaims (map[string]interface{})
- **Description**: Validated claims from the token
- **Content**: All validated claims from the token payload

### Error Case
- **Type**: error
- **Description**: Detailed structured error with verbose message
- **Content**: Contains specific error type and details about the validation failure

## Error Types

The function returns structured errors with the following types:

### Version Validation Error
- **Type**: VERSION_VALIDATION_ERROR
- **Trigger**: Token version is invalid or exceeds maximum allowed
- **Details**: Contains the invalid version value and maximum allowed version

### Issuer Validation Error
- **Type**: ISSUER_VALIDATION_ERROR
- **Trigger**: Token issuer doesn't match expected format
- **Details**: Contains the invalid issuer and expected base issuer

### Key ID Mismatch Error
- **Type**: KEY_ID_MISMATCH_ERROR
- **Trigger**: Key ID in header doesn't match UUID from issuer
- **Details**: Contains the key ID from header and UUID from issuer

### Signature Verification Error
- **Type**: SIGNATURE_VERIFICATION_ERROR
- **Trigger**: Token signature verification failed
- **Details**: Contains signature verification details

### Expiration Error
- **Type**: EXPIRATION_ERROR
- **Trigger**: Token has expired
- **Details**: Contains expiration time and current time

### Not Before Error
- **Type**: NOT_BEFORE_ERROR
- **Trigger**: Token is not yet valid
- **Details**: Contains not-before time and current time

### Token Size Error
- **Type**: TOKEN_SIZE_ERROR
- **Trigger**: Token exceeds maximum allowed size (4KB)
- **Details**: Contains the token size and maximum allowed size

### Algorithm Error
- **Type**: ALGORITHM_ERROR
- **Trigger**: Token uses unsupported algorithm
- **Details**: Contains the algorithm used and supported algorithm

### Malformed Token Error
- **Type**: MALFORMED_TOKEN_ERROR
- **Trigger**: Token structure is invalid
- **Details**: Contains information about the structural issue

## Pre-validation Function

```go
func ShouldVerify(tokenString string, baseIssuer string) bool
```

### Description
Pre-validation function that checks if a token has the correct format before full verification.

### Parameters
- **tokenString** (string, required): The token to check
- **baseIssuer** (string, required): Base issuer URL for validation

### Return
- **Type**: bool
- **Description**: True if token has correct format, false otherwise

## Security Requirements

1. **Constant-time Operations**: Signature verification must use constant-time comparisons
2. **No Clock Skew**: Time-based validations must use strict time matching; 'exp' claim is required, but 'nbf' and 'iat' are optional
3. **Algorithm Validation**: Only RS256 algorithm is accepted
4. **Input Sanitization**: All token components must be validated to prevent injection attacks
5. **Resource Limits**: Token size must not exceed 4KB to prevent resource exhaustion