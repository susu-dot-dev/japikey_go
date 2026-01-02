# Research: JAPIKey Verification Function

## Overview
This research document captures findings about the JavaScript implementation referenced in the feature specification and best practices for implementing the JAPIKey verification function in Go.

## JavaScript Implementation Analysis

### Key Components
Based on the JavaScript implementation at https://raw.githubusercontent.com/susu-dot-dev/japikey_js/refs/heads/main/packages/authenticate/src/index.ts:

1. **authenticate function**:
   - Takes a token string and options (baseIssuer, getJWKS, verifyOptions)
   - Decodes JWT without verification first
   - Validates version format and number
   - Validates issuer format and UUID
   - Matches kid with UUID from issuer
   - Verifies token signature using JWKS

2. **shouldAuthenticate function**:
   - Pre-validation function that returns boolean
   - Checks if token should be authenticated without full verification

3. **createGetJWKS function**:
   - Creates a function to retrieve JWKS from baseIssuer/.well-known/jwks.json

### Validation Sequence
1. Decode JWT token and header without verification
2. Validate version format and number
3. Validate issuer format (must start with baseIssuer + UUID)
4. Validate kid matches UUID from issuer
5. Verify token signature using JWKS

### Error Handling
- Uses custom error types: MalformedTokenError and UnauthorizedError
- Early validation before attempting signature verification
- Specific error messages for different validation failures

## Go Implementation Considerations

### Libraries
- github.com/golang-jwt/jwt/v5 for JWT handling
- golang.org/x/crypto for cryptographic operations
- Standard Go libraries for HTTP requests and JSON handling

### Security Requirements
- Constant-time comparison operations to prevent timing attacks
- Maximum token size limit (4KB) to prevent resource exhaustion
- Strict time matching for time-based claims (no clock skew tolerance)
- Algorithm validation (RS256 only)
- Input sanitization to prevent injection attacks

### Configuration
- Configurable timeout for key retrieval (with minimum > 0)
- Base issuer URL for validation
- Callback function for retrieving cryptographic keys

## Decision: Use Go JWT library with custom validation
**Rationale**: The Go JWT library (github.com/golang-jwt/jwt/v5) provides a solid foundation for JWT handling, but we need to implement custom validation logic to meet the specific JAPIKey requirements.

## Decision: Implement validation in specific order
**Rationale**: Following the same validation sequence as the JavaScript implementation ensures compatibility and proper security. Validate version, issuer, and kid before attempting signature verification.

## Decision: Create structured error types
**Rationale**: Detailed error types with verbose messages are required per the specification to aid in debugging while allowing outer handlers to sanitize responses.

## Alternatives Considered

### Alternative 1: Pure standard library implementation
- Rejected because the JWT library provides necessary cryptographic functions and proper handling of JWT standards

### Alternative 2: Different algorithm support
- Rejected because the specification requires RS256 only for security consistency

### Alternative 3: Different validation order
- Rejected because the specified order (structural validation before signature verification) is more secure and efficient