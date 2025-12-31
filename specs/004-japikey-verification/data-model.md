# Data Model: JAPIKey Verification Function

## Overview
This document describes the data structures and entities for the JAPIKey verification function implementation.

## Key Entities

### JAPIKey Token
- **Description**: A security token with specific format requirements including version, issuer, and key ID constraints
- **Structure**: 
  - Header: Contains algorithm (alg) and key ID (kid)
  - Payload: Contains claims including version (ver), issuer (iss), expiration (exp), not before (nbf), issued at (iat)
  - Signature: Cryptographic signature for verification

### Verification Configuration
- **Description**: Parameters needed for token verification including base issuer URL and key retrieval callback
- **Fields**:
  - BaseIssuer (URL): Base URL for issuer validation
  - GetJWKSCallback (function): Function to retrieve cryptographic keys by key ID
  - Timeout (time.Duration): Timeout for key retrieval (must be > 0)
  - VerifyOptions (optional): Additional JWT verification options

### Validated Claims
- **Description**: The decoded payload from a successfully verified token
- **Structure**: Map of claim names to values
- **Validation**: Must pass all JAPIKey-specific validations

### Structured Error
- **Description**: A well-defined error object that indicates the specific reason for verification failure
- **Fields**:
  - ErrorType (string): Type of validation failure (e.g., "VERSION_VALIDATION_ERROR", "ISSUER_VALIDATION_ERROR", "SIGNATURE_VERIFICATION_ERROR")
  - Message (string): Detailed error message for debugging
  - Details (map[string]interface{}): Additional context about the failure

## Validation Rules

### Token Structure Validation
- Token must follow JWT format (header.payload.signature)
- Header must contain 'alg' and 'kid' fields
- Payload must contain 'ver', 'iss' claims
- Token size must not exceed 4KB

### Version Validation
- 'ver' claim must be a string
- Format must match: ^v(\d{1,3})$ (with appropriate prefix)
- Version number must not exceed maximum allowed version

### Issuer Validation
- 'iss' claim must be a non-empty string
- Must start with BaseIssuer URL
- Must contain a UUID after the base issuer
- Extracted UUID must be a valid UUID format

### Key ID Validation
- 'kid' in header must match the UUID part extracted from the issuer
- Must be properly formatted and safe to use

### Time-Based Validation
- 'exp' claim must not be in the past (with no clock skew tolerance) and is required
- 'nbf' claim must not be in the future (with no clock skew tolerance) if present; tokens without 'nbf' are valid
- 'iat' claim must be a valid timestamp (with no clock skew tolerance) if present; tokens without 'iat' are valid

### Algorithm Validation
- 'alg' header parameter must be exactly 'RS256'
- All other algorithms must be rejected

### Signature Validation
- Token signature must be successfully verified using the retrieved cryptographic key
- Verification must use RS256 algorithm
- Constant-time comparison operations must be used to prevent timing attacks

## State Transitions

### Token Verification Process
1. **Input**: Token string and configuration
2. **Decode**: Token is decoded without verification to extract header and payload
3. **Validate Structure**: Token format and basic fields are validated
4. **Validate Claims**: Version, issuer, and key ID are validated
5. **Retrieve Key**: Cryptographic key is retrieved using the callback function
6. **Verify Signature**: Token signature is verified using the retrieved key
7. **Output**: Validated claims on success, or structured error on failure

## Relationships
- Verification Configuration contains a callback function that retrieves cryptographic keys
- JAPIKey Token is validated against Verification Configuration parameters
- Validated Claims are extracted from a successfully verified JAPIKey Token
- Structured Error is returned when verification fails at any step