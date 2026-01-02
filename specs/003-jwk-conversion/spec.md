# Feature Specification: JWK Conversion Support

**Feature Branch**: `003-jwk-conversion`
**Created**: 2025-12-30
**Status**: Draft
**Input**: User description: "A user of JAPIKeys will need to store the public key and key id in some form for later verification of the system. One method to do so is with the JWK (json web key) RFC. Support converting a JAPIKey to a JWK via a helper on the JAPIKey struct. Similarly, support taking the JWK struct and getting back the key id, and a different method to return the rsa.publicKey. As a user, I can take the JWK struct and easily JSON stringify it. The JWK will only ever have one key in it, matching the key id in the JAPIKey. The JWK must adhere to the spec. Do not yet worry about the full round-trip of validating a JAPIKey token using the JWK, as that will be in a future spec. The primary acceptance criteria must be around the formal RFC for the JWK standard, as well as input validation (e.g. make sure the key id is a uuid, make sure the public key is not null etc). Acceptance criteria includes proper error handling, and structured errors similar to the 002 spec"

## Clarifications

### Session 2025-12-30

- Q: Should JWK conversion methods be implemented as methods on the JAPIKey struct itself, as separate utility functions, or as a separate service? → A: JWK conversion methods should be implemented as methods on the JAPIKey struct itself, and JWK to public key conversion should be part of the JWK struct
- Q: What error handling pattern should be used for JWK operations? → A: Use the same structured error pattern as the 002 spec
- Q: How should the JWK be serialized to JSON to ensure only allowed parameters are included? → A: The JWK struct should implement a MarshalJSON method to control the exact serialization format, ensuring the struct only needs the minimum required fields
- Q: When should validation of JAPIKey fields occur during the conversion process? → A: Perform validation during the conversion process to ensure data integrity at the point of transformation, checking it as part of the transformation process every time since it's just a struct and theoretically some other code could modify the values
- Q: What fields should the JWK struct contain? → A: The JWK struct should contain only the required fields ("kty", "kid", "n", "e") to maintain simplicity

### Session 2025-12-31

- Q: Should the core JWKS implementation use only Go's built-in crypto packages or external libraries? → A: Core implementation uses only Go's built-in crypto packages, with external library only for jwx CLI tool
- Q: Should the JWKS JSON structure follow the standard format with a "keys" array? → A: Standard JWKS format with "keys" array containing exactly one key object, but the golang struct should be simple and only contain the required fields, with marshal/unmarshal code handling the JSON representation
- Q: When should the jwx cli generate test data? → A: Generate test data at build time using makefile command, output to static JSON file imported by tests
- Q: How should error handling be structured? → A: Use structured errors with standard codes like InvalidInput, with messages containing further details; consolidate error types around standard classes while keeping specific types for cases that callers would want to handle
- Q: How should JSON serialization be implemented? → A: Implement custom MarshalJSON/UnmarshalJSON methods to have full control over the format

### Session 2025-12-31 (Architecture Updates)

- Q: Should validation logic be kept in a separate validation.go file or consolidated? → A: Consolidate all validation and JWKS functionality within a single jwks.go file without a separate validation.go file
- Q: How should struct immutability be handled after construction? → A: Ensure struct variables are treated as immutable after construction, with validation occurring only at construction or unmarshalling time, not on every function call
- Q: Where should JWKS-related code be located? → A: Move all JWKS-related code (except the external wrapper in japikey.go) into an internal/ subdirectory
- Q: What package should be used for JWKS code? → A: Use a separate package jwks for the JWKS code
- Q: How should struct field visibility be handled? → A: Use lowercase variable names in structs to ensure only the jwks package can update the variables
- Q: When should validation occur? → A: Validate struct data only during construction or unmarshalling, not on every function call

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Generate JWKS from Public Key (Priority: P1)

As a user, I can generate a JWKS containing exactly one RS256 key from a public key NewJWKS(rsa.publicKey, kid), and I can serialize and deserialize that value to and from JSON. Given an invalid kid, this fails.

**Why this priority**: This is the core functionality that enables users to create a JWK from an RSA public key and key ID, which is the fundamental building block for JWK operations.

**Independent Test**: Can be fully tested by providing a valid RSA public key and key ID to the NewJWKS function, verifying the resulting JWKS contains exactly one RS256 key, and confirming that serialization/deserialization to and from JSON works properly. Also verify that invalid key IDs result in appropriate error responses. The implementation should be in the internal/jwks package with immutable structs using lowercase field names.

**Acceptance Scenarios**:

1. **Given** a valid RSA public key and a valid key ID (UUID), **When** I call NewJWKS(rsa.publicKey, kid), **Then** I receive a properly formatted JWKS containing exactly one RS256 key with the correct parameters
2. **Given** a valid RSA public key and an invalid key ID (not a UUID), **When** I call NewJWKS(rsa.publicKey, kid), **Then** I receive a structured error indicating the key ID validation failure
3. **Given** a null RSA public key and a valid key ID, **When** I call NewJWKS(rsa.publicKey, kid), **Then** I receive a structured error indicating the public key validation failure
4. **Given** a valid JWKS, **When** I serialize it to JSON and then deserialize back to JWKS, **Then** the resulting JWKS is identical to the original
5. **Given** a valid JWKS, **When** I serialize it to JSON, **Then** I receive a properly formatted JSON string representing the JWKS
6. **Given** invalid JSON input (malformed, missing fields, wrong types), **When** I attempt to deserialize to JWKS, **Then** I receive a structured error indicating the deserialization failure
7. **Given** JSON with invalid RSA parameters (e.g. incorrectly formatted n or e values), **When** I attempt to deserialize to JWKS, **Then** I receive a structured error indicating the parameter validation failure

---

### User Story 2 - Extract Public Key and Key ID from JWKS (Priority: P2)

As a user, I can take an existing JWKS, and return the public key for a given kid. Given a JWKS, I can see which kid is present for it. Otherwise, I get the appropriate error message if the kid is missing or the JWKS is malformed for whichever reason.

**Why this priority**: This enables users to retrieve the RSA public key from a JWKS when they know the key ID, and to discover which key IDs are available in a JWKS.

**Independent Test**: Can be fully tested by creating a valid JWKS, extracting the public key for a known key ID, and verifying it matches the original. Also test extracting the key ID from the JWKS and verifying error handling for malformed JWKS or missing key IDs. The implementation should be in the internal/jwks package with immutable structs using lowercase field names.

**Acceptance Scenarios**:

1. **Given** a valid JWKS with a known key ID, **When** I request the public key for that key ID, **Then** I receive the correct RSA public key
2. **Given** a valid JWKS, **When** I request to see which key ID is present, **Then** I receive the correct key ID string
3. **Given** a JWKS without the requested key ID, **When** I request the public key for that key ID, **Then** I receive a structured error indicating the missing key ID
4. **Given** a valid JWKS containing a different key ID than requested (both valid UUIDs), **When** I request the public key for the non-matching key ID, **Then** I receive a structured error indicating the key ID not found in JWKS
5. **Given** a malformed JWKS (e.g., missing required parameters, invalid format), **When** I attempt to extract information, **Then** I receive a structured error indicating the JWKS validation failure

---

### User Story 3 - Get JWKS from JAPIKey (Priority: P3)

As a user with a valid JAPIKey, there is a helper method to get the JWKS from it.

**Why this priority**: This provides a convenient way for users to convert their existing JAPIKey to JWKS format without having to manually extract the components.

**Independent Test**: Can be fully tested by creating a valid JAPIKey, calling the helper method to get the JWKS, and verifying the resulting JWKS contains the correct key ID and public key information. The implementation should use the internal/jwks package with immutable structs using lowercase field names.

**Acceptance Scenarios**:

1. **Given** a valid JAPIKey with a UUID key ID and RSA public key, **When** I call the helper method to get JWKS, **Then** I receive a properly formatted JWKS containing exactly one RS256 key
2. **Given** a JAPIKey with an invalid key ID (not a UUID), **When** I call the helper method to get JWKS, **Then** I receive a structured error indicating the key ID validation failure
3. **Given** a JAPIKey with a null RSA public key, **When** I call the helper method to get JWKS, **Then** I receive a structured error indicating the public key validation failure

---

### User Story 4 - JWX Verification Tool (Priority: P4)

As a user, I can use the jwx tool which has two commands: parse - which takes a JSON string via stdin and prints via stdout the single public key as a base64 encoded string (or an error message), and generate, which takes a public key in stdin (as a base64 string) along with the key uuid as an argument and prints via stdout the jwks json.

**Why this priority**: This provides a verification oracle for unit tests, allowing validation of our JWK implementation against the established jwx library. This ensures correctness of our implementation through independent verification.

**Independent Test**: Can be fully tested by running the tool with various inputs and validating the outputs. The parse command should accept valid JWK JSON and return the public key as base64, while the generate command should accept a base64 public key and UUID to generate a JWKS JSON. The tool should be used by the Makefile to build the jwx CLI tool before running tests, and unit tests should exec out to the tool to validate the correctness of our implementation.

**Acceptance Scenarios**:

1. **Given** a valid JWK JSON string via stdin to the parse command, **When** I run the tool, **Then** I receive the public key as a base64 encoded string via stdout
2. **Given** an invalid JWK JSON string via stdin to the parse command, **When** I run the tool, **Then** I receive an appropriate error message
3. **Given** a base64 encoded public key via stdin and a valid UUID argument to the generate command, **When** I run the tool, **Then** I receive a properly formatted JWKS JSON via stdout
4. **Given** the tool is executed from the Makefile during test preparation, **When** tests run, **Then** the jwx CLI tool is available for validation
5. **Given** our JWK implementation produces a JWKS, **When** tests validate using the jwx tool oracle, **Then** both our implementation and the jwx library produce equivalent results for import/export/round-trip operations
6. **Given** a round-trip scenario (export from our code, import via jwx tool, export again via jwx tool, import back to our code), **When** tests validate the final result, **Then** the original and final values match to verify correctness

---

### Edge Cases

- What happens when the JWK contains multiple keys instead of just one?
- How does the system handle malformed JWK JSON?
- What validation occurs for the RSA key parameters in the JWK?
- How does the system handle JWKs with non-RSA algorithms?
- What happens when the key ID in the JWK is not a valid UUID format?
- How does the system handle the immutability of struct variables after construction?
- What validation occurs only at construction or unmarshalling time?
- How does the system ensure that validation is not performed on every function call?
- What happens when the jwx tool receives malformed input?
- How does the jwx tool handle different RSA key formats?
- What error handling does the jwx tool provide for invalid UUIDs?
- How does the test framework handle jwx tool execution failures?

## Requirements *(mandatory)*

### Error Types and Inheritance Model

The system MUST define and use a standardized error inheritance model with a base `JapikeyError` type that provides consistent structure across all error types.

#### Base Error Type: JapikeyError

All error types inherit from `JapikeyError`, which provides:
- `Code` (string): Error code identifier (e.g., "ValidationError", "ConversionError")
- `Message` (string): Human-readable error message with contextual details

Errors are constructed using factory functions that automatically set the correct error code:
- `errors.NewValidationError(message string)`
- `errors.NewConversionError(message string)`
- `errors.NewKeyNotFoundError(message string)`
- `errors.NewInternalError(message string)`

#### Error Categories

The system MUST define and use the following error categories for JWK operations:

- **ValidationError**: Used for all validation failures when unmarshaling JSON files (besides standard JSON format errors), invalid JWK structure, missing required fields, invalid RSA parameters, or invalid key ID format. This is a generic error type with contextual messages rather than many specific error types.

- **ConversionError**: Used when cryptographic operations fail during conversion (e.g., converting JAPIKey to JWK, encoding RSA parameters, round-trip validation failures). This is a generic error type with contextual messages.

- **KeyNotFoundError**: Used when the kid (key ID) is not present in the JWK or JWKS. This error type is kept separate from validation errors because clients may need to handle missing keys differently (e.g., retry with different key, fetch from different source).

- **InternalError**: Used when internal operations fail (e.g., key generation failures, signing failures). This is a generic error type for internal cryptographic operation failures.

#### Error Design Principles

1. **Inheritance Model**: All errors embed `JapikeyError` to ensure consistent structure
2. **Factory Functions**: Errors are constructed using `New*Error()` functions that set the appropriate code
3. **Generic Categories**: Use generic error types (ValidationError, ConversionError, InternalError) with contextual messages rather than many specific error types
4. **Specific Types When Needed**: Only keep unique error types (like KeyNotFoundError) when clients need different behavior based on the error type
5. **Contextual Messages**: Error messages provide detailed context about what went wrong, allowing clients to understand the specific failure

### Functional Requirements

- **FR-001**: System MUST provide a NewJWKS function that accepts an RSA public key and key ID (kid) and returns a JWKS containing exactly one RS256 key
- **FR-002**: System MUST validate that the key ID (kid) parameter is a valid UUID format when creating a JWKS
- **FR-003**: System MUST validate that the RSA public key parameter is not null when creating a JWKS
- **FR-004**: System MUST provide methods to extract the RSA public key from a JWKS for a given key ID
- **FR-005**: System MUST provide methods to retrieve the key ID present in a JWKS
- **FR-006**: System MUST provide structured error handling using the same pattern as the 002 spec for all validation failures, with standard error codes like InvalidInput and specific error types for cases that callers would want to handle
- **FR-007**: System MUST implement custom MarshalJSON and UnmarshalJSON methods to convert JWKS to and from JSON format with full control over the serialization format
- **FR-007a**: System MUST use separate structs for in-memory representation (lowercase fields) and JSON representation (exported fields) to ensure proper encapsulation
- **FR-007b**: System MUST implement UnmarshalJSON using a two-phase validation process: (1) untyped JSON shape validation to detect extra fields, (2) typed unmarshaling with field validation
- **FR-007c**: System MUST validate JSON shape before typed unmarshaling by checking: keys array exists with exactly one element, JWK object contains exactly 4 fields (kty, kid, n, e), all required fields are present
- **FR-007d**: System MUST perform round-trip validation after unmarshaling by comparing encoded n and e values from JSON with re-encoded values from the constructed JWKS, returning ConversionError if mismatch
- **FR-007e**: System MUST use the NewJWKS constructor during UnmarshalJSON to ensure all validation rules are applied consistently
- **FR-008**: System MUST validate that the key ID in a JWKS is a valid UUID when extracting it
- **FR-009**: System MUST validate that the public key in a JWKS is a valid RSA public key when extracting it
- **FR-010**: System MUST include the "kty" parameter with value "RSA" in the generated JWKS to identify the key type
- **FR-011**: System MUST include the "kid" parameter in the generated JWKS with the same value as the provided key ID
- **FR-012**: System MUST include the RSA-specific parameters "n" (modulus) and "e" (exponent) in the generated JWKS, properly encoded as Base64urlUInt values according to RFC 7518
- **FR-013**: System MUST validate that the "kty" parameter in a JWKS has value "RSA" when extracting the RSA public key
- **FR-014**: System MUST validate that the "n" and "e" parameters are present and properly formatted as Base64urlUInt when extracting the RSA public key from a JWKS
- **FR-015**: System MUST reject JWKS that do not contain exactly one key (validated in Phase 1 of UnmarshalJSON)
- **FR-016**: System MUST ensure member names within a JWKS are unique and reject JWKS with duplicate member names
- **FR-017**: System MUST only accept and generate JWKS with the following exact parameters: "kty", "kid", "n", and "e"
- **FR-018**: System MUST reject JWKS containing any additional parameters beyond the supported ones ("kty", "kid", "n", "e") - validated using untyped JSON unmarshaling in Phase 1 to detect fields that would otherwise be silently ignored
- **FR-019**: System MUST handle case-sensitive string comparisons for all JWKS parameters
- **FR-020**: System MUST ensure the generated JWKS follows the JSON object structure as defined in RFC 7517
- **FR-021**: System MUST validate that the "n" (modulus) parameter in a JWKS is a valid Base64urlUInt-encoded value representing the RSA modulus according to RFC 7518, with proper big-endian representation
- **FR-022**: System MUST validate that the "e" (exponent) parameter in a JWKS is a valid Base64urlUInt-encoded value representing the RSA exponent according to RFC 7518, with proper big-endian representation
- **FR-023**: System MUST properly decode Base64urlUInt values for "n" and "e" parameters when extracting the RSA public key from a JWKS, using big-endian representation as specified in RFC 7518
- **FR-024**: System MUST validate that the RSA public key extracted from JWKS parameters produces a valid, usable RSA public key object
- **FR-025**: System MUST encode the RSA modulus (N) as a Base64urlUInt by converting the big.Int value to its big-endian byte representation without leading zero-valued octets (except when needed to represent positive values correctly) before base64url encoding
- **FR-026**: System MUST encode the RSA exponent (E) as a Base64urlUInt by converting the integer value to its big-endian byte representation before base64url encoding
- **FR-027**: System MUST use unpadded base64url encoding (RFC 7515 Section 2 terminology) for all Base64urlUInt values, omitting trailing '=' characters
- **FR-028**: System MUST represent positive integer values as the base64url encoding of the value's unsigned big-endian representation as an octet sequence, utilizing the minimum number of octets needed to represent the value (RFC 7518 definition of Base64urlUInt)
- **FR-029**: System MUST properly handle zero values in Base64urlUInt encoding, representing zero as BASE64URL(single zero-valued octet), which is "AA"
- **FR-030**: System MUST validate that the octet sequence for Base64urlUInt values utilizes the minimum number of octets needed to represent the value as specified in RFC 7518
- **FR-031**: System MUST ensure that the base64url encoding follows the URL- and filename-safe character set defined in RFC 4648 Section 5, with all trailing '=' characters omitted as permitted by RFC 4648 Section 3.2
- **FR-032**: System MUST validate that the key ID in the JWKS matches the requested key ID when extracting a specific public key
- **FR-033**: System MUST reject invalid JSON during deserialization with appropriate error messages
- **FR-034**: System MUST reject JSON with invalid RSA parameters (incorrectly formatted n or e values) during deserialization
- **FR-035**: System MUST provide a helper method on JAPIKey to convert it to JWKS format
- **FR-036**: System MUST validate that the JAPIKey contains a valid UUID key ID before converting to JWKS
- **FR-037**: System MUST validate that the JAPIKey contains a valid RSA public key before converting to JWKS
- **FR-038**: System MUST provide a jwx CLI tool in the jwx/ folder with its own go.mod file that uses lestrrat-go/jwx/jwk to generate example keys and JWKS for comparison in unit tests
- **FR-039**: System MUST provide a makefile command to execute the jwx CLI tool that outputs a JSON test file for use in unit tests
- **FR-040**: System MUST ensure the jwx CLI tool does not become a direct dependency of the primary go.mod program
- **FR-041**: System MUST implement all validation and JWKS functionality within a single jwks.go file without a separate validation.go file
- **FR-042**: System MUST ensure struct variables are treated as immutable after construction, with validation occurring only at construction or unmarshalling time
- **FR-043**: System MUST move all JWKS-related code (except the external wrapper in japikey.go) into an internal/ subdirectory
- **FR-044**: System MUST use a separate package jwks for the JWKS code
- **FR-045**: System MUST use lowercase variable names in structs to ensure only the jwks package can update the variables
- **FR-046**: System MUST validate struct data only during construction or unmarshalling, not on every function call
- **FR-047**: System MUST define and use a base `JapikeyError` type with `Code` and `Message` fields that all error types inherit from
- **FR-048**: System MUST define and use `ValidationError` for all validation failures when unmarshaling JSON files (besides standard JSON format errors), invalid JWK structure, missing required fields, invalid RSA parameters, or invalid key ID format
- **FR-049**: System MUST define and use `ConversionError` when cryptographic operations fail during conversion (e.g., converting JAPIKey to JWK, encoding RSA parameters, round-trip validation failures)
- **FR-050**: System MUST define and use `KeyNotFoundError` for when the kid is not present in the JWK (kept separate because clients may need different behavior)
- **FR-051**: System MUST define and use `InternalError` for internal operation failures (e.g., key generation failures, signing failures)
- **FR-052**: System MUST construct errors using factory functions (e.g., `NewValidationError()`, `NewConversionError()`) that automatically set the appropriate error code
- **FR-053**: System MUST use generic error categories (ValidationError, ConversionError, InternalError) with contextual messages rather than many specific error types
- **FR-054**: System MUST only keep unique error types (like KeyNotFoundError) when clients need different behavior based on the error type
- **FR-055**: System MUST use UUID data type internally instead of string to enforce that the string, if present, is a UUID
- **FR-056**: System MUST provide a jwx CLI tool with parse and generate commands for JWK operations
- **FR-057**: The jwx tool parse command MUST accept a JSON string via stdin and output the single public key as a base64 encoded string via stdout
- **FR-058**: The jwx tool parse command MUST return an appropriate error message when the input is not a valid JWK
- **FR-059**: The jwx tool generate command MUST accept a base64 encoded public key via stdin and a UUID argument, and output a JWKS JSON via stdout
- **FR-060**: The Makefile MUST ensure the jwx CLI tool is built before running tests
- **FR-061**: Unit tests MUST be able to exec out to the jwx tool to validate the correctness of our JWK implementation
- **FR-062**: The jwx CLI tool MUST use the lestrrat-go/jwx/jwk library to provide an independent verification oracle
- **FR-063**: The jwx CLI tool MUST support import, export, and round-trip validation for JWK operations
- **FR-064**: All compiled files MUST be ignored by the version control system to prevent binaries from being committed to the repository

### Key Entities

- **JAPIKey**: The primary key structure containing a key ID (UUID) and RSA public key
- **JWKS (JSON Web Key Set)**: A standard format for representing a set of JSON Web Keys as a JSON object with a "keys" member containing an array of JWKs; the Go struct should be simple containing only required fields with lowercase names, with serialization handling the full JWKS format; located in internal/jwks package
- **JWK (JSON Web Key)**: A standard format for representing cryptographic keys as JSON, containing only the required fields with lowercase names: "kty", "kid", "n", and "e"; located in internal/jwks package
- **Key ID**: A UUID that uniquely identifies the JAPIKey/JWK pair
- **RSA Public Key**: The public cryptographic key component that can be extracted from or embedded in the JWK
- **Base64urlUInt**: The representation of a positive or zero integer value as the base64url encoding of the value's unsigned big-endian representation as an octet sequence, with the minimum number of octets needed to represent the value
- **internal/jwks package**: The internal package containing all JWKS-related functionality with lowercase field names to enforce immutability after construction

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can successfully generate a JWKS from a valid RSA public key and key ID with 100% accuracy in test cases
- **SC-002**: Users can successfully serialize a JWKS to JSON format with 100% accuracy in test cases
- **SC-003**: Users can successfully deserialize a JWKS from JSON format with 100% accuracy in test cases
- **SC-004**: Users can extract the correct RSA public key from a JWKS for a given key ID with 100% accuracy in test cases
- **SC-005**: Users can retrieve the correct key ID from a JWKS with 100% accuracy in test cases
- **SC-006**: All validation failures return structured errors that clearly indicate the specific validation issue in 100% of test cases
- **SC-007**: Generated JWKS contain all required RFC 7517 parameters ("kty" set to "RSA", "kid" matching the provided ID, and RSA-specific parameters "n" and "e") in 100% of test cases
- **SC-008**: The "n" and "e" parameters in generated JWKS are properly encoded as Base64urlUInt values according to RFC 7518 in 100% of test cases
- **SC-009**: JWKS validation correctly identifies and rejects JWKS with missing or incorrectly formatted RSA parameters ("n" and "e") in 100% of test cases
- **SC-010**: JWKS validation correctly identifies and rejects JWKS that do not contain exactly one key in 100% of test cases
- **SC-011**: JWKS validation correctly identifies and rejects JWKS with duplicate member names in 100% of test cases
- **SC-012**: JWKS validation correctly accepts only JWKS with the exact supported parameters ("kty", "kid", "n", "e") in 100% of test cases
- **SC-013**: JWKS validation correctly rejects JWKS containing any additional parameters beyond the supported ones in 100% of test cases
- **SC-014**: JWKS validation correctly rejects invalid JSON during deserialization in 100% of test cases
- **SC-015**: JWKS validation correctly rejects JSON with invalid RSA parameters during deserialization in 100% of test cases
- **SC-016**: The JWKS conversion and extraction operations complete in under 100ms in 95% of test cases
- **SC-017**: Users can successfully convert a valid JAPIKey to JWKS format using the helper method with 100% accuracy in test cases
- **SC-018**: Users can successfully round-trip a JAPIKey to JWKS JSON and back to the original public key with 100% accuracy in test cases, ensuring the original and final public keys are identical
- **SC-019**: JWKS generated by our implementation match the format and content of JWKS generated by lestrrat-go/jwx/jwk library with 100% accuracy in verification tests
- **SC-020**: The jwx CLI tool successfully parses valid JWK JSON and outputs the public key as a base64 encoded string with 100% accuracy in test cases
- **SC-021**: The jwx CLI tool correctly returns error messages for invalid JWK JSON with 100% accuracy in test cases
- **SC-022**: The jwx CLI tool successfully generates JWKS JSON from a base64 public key and UUID with 100% accuracy in test cases
- **SC-023**: The Makefile successfully builds the jwx CLI tool before running tests in 100% of test runs
- **SC-024**: Unit tests successfully execute the jwx CLI to validate JWK implementation correctness in 100% of test runs
- **SC-025**: Import/export/round-trip operations validate correctly between our implementation and the jwx CLI oracle with 100% accuracy in verification tests

