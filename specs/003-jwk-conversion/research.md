# Research for JWK Conversion Support

## Decision: Consolidated JWKS Implementation in Single File
**Rationale**: To simplify the codebase and improve maintainability, all JWKS functionality will be consolidated in a single jwks.go file without a separate validation.go file. This approach reduces complexity by keeping all related functionality in one place, making it easier to understand and maintain the JWKS implementation.

## Decision: Immutable Structs with Lowercase Fields
**Rationale**: To enforce immutability after construction and proper encapsulation, the JWKS and JWK structs will use lowercase field names. This ensures that only the internal jwks package can update the variables, enforcing immutability from external packages. Validation will occur only at construction or unmarshalling time, not on every function call, improving performance and ensuring data integrity.

## Decision: Internal Package Structure
**Rationale**: Moving all JWKS-related code (except the external wrapper in japikey.go) into an internal/ subdirectory with a separate jwks package provides better encapsulation and separation of concerns. This structure keeps the implementation details hidden from external users while providing a clean public interface.

## Decision: Validation at Construction Time
**Rationale**: Rather than validating inputs on every function call, validation will occur only at construction or unmarshalling time. This approach improves performance by avoiding redundant validation checks while maintaining data integrity. Once constructed, the structs are immutable, ensuring their validity throughout their lifetime.

## Decision: Base64urlUInt Encoding Implementation
**Rationale**: To properly encode RSA parameters "n" (modulus) and "e" (exponent) as Base64urlUInt values according to RFC 7518, we'll use Go's encoding/base64 package with RawURLEncoding (unpadded base64url) and math/big's Bytes() method to get the big-endian representation. This ensures compliance with the RFC specification that requires positive integer values to be represented as the base64url encoding of the value's unsigned big-endian representation as an octet sequence, utilizing the minimum number of octets needed.

## Decision: JWKS Structure with Custom Marshal/Unmarshal
**Rationale**: The internal Go struct will contain lowercase fields for proper encapsulation, but custom MarshalJSON and UnmarshalJSON methods will handle the full JWKS format with the "keys" array containing exactly one key. This satisfies the requirement to keep the internal struct simple while ensuring the JSON output follows the standard JWKS format as defined in RFC 7517.

## Decision: Structured Error Handling Pattern
**Rationale**: Following the same structured error pattern as the 002 spec, we'll implement error types with standard codes like InvalidInput for general validation failures, while keeping specific error types for cases that callers would want to handle. This ensures consistency across the codebase and provides clear error messages for debugging.

## Decision: Validation Strategy for JWKS Parameters
**Rationale**: Implement comprehensive validation for all JWKS parameters to ensure RFC compliance, but only at construction or unmarshalling time:
- Validate that "kty" parameter has value "RSA"
- Validate that "n" and "e" parameters are present and properly formatted as Base64urlUInt
- Validate that the "n" (modulus) parameter is a valid Base64urlUInt-encoded value representing the RSA modulus with proper big-endian representation
- Validate that the "e" (exponent) parameter is a valid Base64urlUInt-encoded value representing the RSA exponent with proper big-endian representation
- Ensure member names within a JWKS are unique and reject JWKS with duplicate member names
- Only accept JWKS with the exact supported parameters ("kty", "kid", "n", "e")
- Reject JWKS containing any additional parameters beyond the supported ones