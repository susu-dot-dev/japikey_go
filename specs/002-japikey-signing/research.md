# Research Summary: JAPIKey Signing Library

## JavaScript API Key Implementation Analysis

### JavaScript API Input Parameters
The JavaScript `createApiKey` function takes:
- `claims`: Additional JWT claims to include
- `options`: An object with:
  - `sub`: Subject identifier (string)
  - `iss`: Issuer URL (URL object)
  - `aud`: Audience identifier (string)
  - `expiresAt`: Expiration time (Date object)

### JavaScript API Return Values
The JavaScript `createApiKey` function returns a `CreateApiKeyResult` object with:
- `jwk`: The JSON Web Key (public key for verification)
- `jwt`: The signed JWT token
- `kid`: The key identifier

### Why These Fields Are Needed
Based on the README and implementation:
1. **jwt**: The actual API key that clients will use for authentication
2. **jwk**: The public key needed for verification by clients and servers
3. **kid**: The key identifier needed to:
   - Store the public key in the database with the correct identifier
   - Allow clients to fetch the correct key from the JWKS endpoint
   - Enable proper key lookup during verification

### Constants Used in JavaScript Implementation
- `ALG`: Signing algorithm (RS256)
- `VER`: Version identifier ('japikey-v1')
- `VER_PREFIX`: Version prefix ('japikey-v')
- `VER_NUM`: Version number (1)

### Key Generation Process
1. Generate a unique key ID using UUID v7
2. Generate a new public/private key pair
3. Create a JWT with the provided claims plus standard claims
4. Create a JWK from the public key
5. Sign the JWT with the private key
6. Return the JWK, JWT, and key ID

## Decision: Use golang-jwt library for JWT handling
**Rationale**: The specification requires integration with golang-jwt library (github.com/golang-jwt/jwt/v5) which is the standard JWT library for Go and provides all necessary functionality for creating and signing JWTs with RSA keys.

## Decision: Use crypto/rsa.GenerateKey for key generation
**Rationale**: Go's standard crypto/rsa package provides secure key generation functionality that meets the requirements for generating 2048-bit RSA key pairs needed for RS256 JWT signing.

## Decision: Implement custom Error structs that implement the error interface
**Rationale**: The specification requires structured error types (JAPIKeyValidationError, JAPIKeyGenerationError, JAPIKeySigningError) that allow for type assertions. Implementing the error interface ensures compatibility with Go error handling patterns.

## Decision: Thread-safe implementation using sync primitives
**Rationale**: The specification requires thread-safe operation to support concurrent API key generation requests. This can be achieved using Go's sync package where needed, though the core signing operation is stateless and naturally thread-safe.

## Decision: Input validation for security
**Rationale**: All user inputs (subject, issuer, audience, expiration) must be properly validated to prevent security vulnerabilities. This includes checking for empty values, valid URL formats, and reasonable expiration times.

## Decision: Consolidate types and errors in sign.go
**Rationale**: For simplicity and better cohesion, types (Config, Result) and error definitions will be in the same file (sign.go) as the main functionality rather than separate files.

## Decision: Simplified Result type
**Rationale**: Based on analysis of the JavaScript implementation, the Result type should include only the essential fields that callers need: the JWT string, the JWK (public key), and the key ID. The Claims and SigningMethod fields are not needed since the JWT already contains the claims and the signing method is fixed (RS256).