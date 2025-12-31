# Feature Specification: JAPIKey Signing Library

**Feature Branch**: `002-japikey-signing`
**Created**: December 29, 2025
**Status**: Draft
**Input**: User description: "Implement the core signing library for japikey. First, webfetch https://raw.githubusercontent.com/susu-dot-dev/japikey_js/refs/heads/main/README.md to understand how the api keys work in general. Next, fetch the main code here: https://raw.githubusercontent.com/susu-dot-dev/japikey_js/refs/heads/main/packages/japikey/src/sign.ts as well as these constants to understand how the javascript implementation works: export const ALG = 'RS256'; export const VER_PREFIX = 'japikey-v'; export const VER_NUM = 1; export const VER = \`${VER_PREFIX}${VER_NUM}\`;. Then, research the golang-jwt package, and additionally fetch the docs here: https://golang-jwt.github.io/jwt/usage/create/ to understand its usage. Put all of this research together to design a developer friendly, low-level interface that re-implements the createApiKey function in the javascript package. Since the data types are all just normal JWT's, directly use the golang-jwt data structures when speccing out the requirements. Putting this all together, your user story should be: As a user, I can create a JAPIKey by passing in the mandatory fields, as well as any optional claims, and get a JWT back, containing those claims. As a user, if I pass in invalid options, I cannot create a JWT and I get an appropriate error. The spec number should start with 002"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Create JAPIKey with Mandatory Fields (Priority: P1)

As a developer, I want to create a JAPIKey by providing the required fields (subject, issuer, audience, and expiration time) so that I can generate a secure API key that embeds all necessary information without storing secrets in a database.

**Why this priority**: This is the core functionality of the library - without this basic capability, the library has no value. It enables the primary use case of generating secure API keys using JWT technology.

**Independent Test**: Can be fully tested by calling the create function with valid mandatory parameters and verifying that a properly formatted JWT is returned with the correct claims.

**Acceptance Scenarios**:

1. **Given** a valid subject, issuer URL, audience, and future expiration time, **When** I call the create JAPIKey function, **Then** I receive a valid JWT string containing the provided claims and additional metadata, as well as the corresponding key id, and matching JWK

---

### User Story 2 - Create JAPIKey with Optional Claims (Priority: P2)

As a developer, I want to include additional custom claims when creating a JAPIKey so that I can embed application-specific information in the API key.

**Why this priority**: This provides flexibility for different use cases where applications need to include additional metadata in the API key beyond the standard claims.

**Independent Test**: Can be tested by calling the create function with optional claims and verifying that the JWT contains both mandatory and optional claims.

**Acceptance Scenarios**:

1. **Given** valid mandatory fields and additional custom claims, **When** I call the create JAPIKey function, **Then** I receive a JWT containing both mandatory and custom claims.

---

### User Story 3 - Handle Invalid Input Parameters with Structured Errors (Priority: P1)

As a developer, I want the JAPIKey creation to fail with structured error types when I provide invalid parameters so that I can implement specific fallback patterns in my code based on the error type.

**Why this priority**: Security and reliability are critical for an authentication library. Structured error handling allows developers to implement specific fallback patterns and provides good developer experience.

**Independent Test**: Can be tested by providing various invalid inputs (expired date, empty subject, etc.) and verifying appropriate structured error responses with specific error codes.

**Acceptance Scenarios**:

1. **Given** an expiration time in the past, **When** I call the create JAPIKey function, **Then** I receive a structured error of type JAPIKeyValidationError with a specific error code indicating the expiration time is invalid.
2. **Given** an empty or invalid subject, **When** I call the create JAPIKey function, **Then** I receive a structured error of type JAPIKeyValidationError with a specific error code indicating the subject is invalid.
3. **Given** a cryptographic failure during key generation, **When** I call the create JAPIKey function, **Then** I receive a structured error of type JAPIKeyGenerationError.
4. **Given** a failure during JWT signing, **When** I call the create JAPIKey function, **Then** I receive a structured error of type JAPIKeySigningError.

---

### Edge Cases

- What happens when the system cannot generate a key pair due to cryptographic errors?
- How does the system handle extremely long expiration times that exceed reasonable limits?
- What if the subject, audience, or issuer values contain special characters that might affect JWT parsing?
- How does the system handle concurrent requests to generate multiple API keys simultaneously?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST implement all features as standalone libraries with clear interfaces
- **FR-002**: System MUST provide comprehensive documentation including quickstart guides and API examples for every behavior
- **FR-003**: System MUST include security-focused tests for all core features covering both security posture and functional correctness
- **FR-004**: System MUST validate the specification with tests before implementing features
- **FR-006**: System MUST generate a new public/private key pair for each API key using RSA-256 algorithm with 2048-bit keys
- **FR-007**: System MUST create a JWT containing the subject, issuer, audience, expiration time, and additional metadata
- **FR-008**: System MUST use Go 1.21 or later with standard Go modules and github.com/golang-jwt/jwt/v5 for JWT handling
- **FR-009**: System MUST include a version identifier (ver) in the JWT claims following the format 'japikey-v1'
- **FR-010**: System MUST generate a unique key identifier (kid) for each API key using uuidv7 format
- **FR-011**: System MUST embed the key identifier in the JWT header
- **FR-012**: System MUST return the public key as a JWK (JSON Web Key) along with the signed JWT
- **FR-013**: System MUST discard the private key immediately after signing the JWT to ensure it's never stored
- **FR-014**: System MUST validate that the expiration time is in the future
- **FR-031**: System MUST NOT enforce a maximum limit on the expiration time for API keys
- **FR-015**: System MUST validate that the subject is a non-empty string
- **FR-016**: System MUST allow optional additional claims to be included in the JWT
- **FR-017**: System MUST return structured error types with specific error codes when invalid parameters are provided
- **FR-018**: System MUST ensure the JWT signature is valid using the generated public key
- **FR-019**: System MUST follow JWT standards (RFC 7519) for token structure and claims
- **FR-020**: System MUST provide a developer-friendly API that follows Go conventions and integrates with golang-jwt types
- **FR-021**: System MUST return JWT as a string that is compatible with golang-jwt parsing functions
- **FR-022**: System MUST return the signing method as a golang-jwt SigningMethod type
- **FR-023**: System MUST return claims as a jwt.MapClaims type from golang-jwt
- **FR-024**: System MUST provide exhaustive error types that cover all possible failure scenarios
- **FR-025**: System MUST implement error types that allow developers to use type assertions for specific error handling
- **FR-026**: System MUST provide a configuration struct that follows Go naming conventions for API parameters
- **FR-027**: System MUST implement the main function as a method on a service struct following Go idioms
- **FR-032**: System MUST be thread-safe to support concurrent API key generation requests
- **FR-028**: System MUST return success data types that are compatible with golang-jwt library types
- **FR-029**: System MUST provide a NewJAPIKey function that accepts a configuration struct with mandatory and optional parameters
- **FR-030**: System MUST return a result struct containing the JWT string, golang-jwt compatible claims, and JWK
- **FR-033**: System MUST ensure that user-passed in claims cannot override the mandatory config claims (subject, issuer, audience, expiration) or the version identifier

### Error Types

The system MUST implement the following structured error types to allow for specific error handling:

- **JAPIKeyValidationError**: Returned when input parameters fail validation (e.g., expired time, empty subject)
  - **ErrorCode**: ValidationError
  - **Possible Reasons**:
    - Expiration time is in the past
    - Subject is empty
    - Invalid issuer URL format
    - Invalid audience format

- **JAPIKeyGenerationError**: Returned when cryptographic operations fail during key generation
  - **ErrorCode**: KeyGenerationError
  - **Possible Reasons**:
    - Failure to generate RSA key pair
    - Insufficient entropy for key generation
    - System resource limitations during key generation

- **JAPIKeySigningError**: Returned when JWT signing operations fail
  - **ErrorCode**: SigningError
  - **Possible Reasons**:
    - Failure to sign the JWT with the private key
    - Invalid signing algorithm specified
    - Private key unavailable or corrupted

### Success Response Structure

The function MUST return a struct with the following golang-jwt compatible fields:

- **JWT**: A string containing the signed JWT token
- **PublicKey**: An RSA public key for verification
- **KeyID**: A string identifier for the key

### API Structure

The system MUST implement a Go-idiomatic API with:

- A `Config` struct containing all required and optional parameters
- A `JAPIKey` struct as the primary data type representing the API key
- A `NewJAPIKey` constructor function following Go naming conventions (NewX pattern) that returns a pointer to JAPIKey
- Error types that implement the standard `error` interface for compatibility

### Package Re-exports

The system MUST provide a top-level package at the module root that re-exports the API surface from the internal japikey package, allowing users to import directly from the module root:

- Re-export the `Config` type
- Re-export the `JAPIKey` struct as the primary data type
- Re-export the `NewJAPIKey` constructor function
- Re-export error types: `JAPIKeyValidationError`, `JAPIKeyGenerationError`, `JAPIKeySigningError`

### Key Entities

- **JAPIKey**: The primary data type representing a JWT token containing claims about the user and additional metadata, signed with a unique private key. This struct contains the JWT string, public key, and key identifier.
- **JWK (JSON Web Key)**: A JSON structure representing a cryptographic key, containing the public key that can verify the JAPIKey signature
- **Key Identifier (kid)**: A unique identifier for each key pair, embedded in the JWT header to enable key lookup during verification
- **Claims**: Information embedded in the JWT including standard claims (subject, issuer, audience, expiration) and optional custom claims, using golang-jwt MapClaims type

## Clarifications

### Session 2025-12-29

- Q: What RSA key size should be used for generating the key pairs? → A: 2048-bit
- Q: Should there be a maximum limit on the expiration time for API keys? → A: No limit
- Q: What format should be used for the key identifier (kid)? → A: uuidv7
- Q: Should the JAPIKey generation be thread-safe for concurrent use? → A: Thread-safe

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Developers can generate a valid JAPIKey pointer by calling the NewJAPIKey function with mandatory parameters
- **SC-002**: 100% of generated JAPIKeys can be successfully validated using the corresponding public key
- **SC-003**: The library provides structured error codes for 100% of failure scenarios
- **SC-004**: Generated JAPIKeys follow JWT standards and can be parsed by standard JWT libraries
- **SC-005**: The private key is never accessible after JAPIKey creation, ensuring security best practices
- **SC-006**: All success return types are compatible with golang-jwt library types
- **SC-007**: Developers can use type assertions to handle specific error cases programmatically
- **SC-008**: The API follows Go naming conventions and idioms
