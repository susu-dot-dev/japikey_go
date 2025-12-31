# Feature Specification: JAPIKey Verification Function

**Feature Branch**: `004-japikey-verification`
**Created**: 2025-12-30
**Status**: Draft
**Input**: User description: "Create the low level function to verify that a JAPIKey is correct. First, research the javascript implementation for requirements: https://raw.githubusercontent.com/susu-dot-dev/japikey_js/refs/heads/main/packages/authenticate/src/index.ts. The verify function should take in the JWT string, the config, as well as a callback function which retrieves the JWK if given the key id. It should either return the validated claims, or an appropriate structured error. Functional requirements should be to ensure all of the ways that tokens can be invalid are handled, since this is user-controlled input. All of the special JAPIKey constraints should be checked, as derived from the functional requirements from reading the javascript implementation. Since this is a security feature it is essential that this code is simple, extremely well tested, using standard libraries and exhaustively covering all cases"

## Clarifications

### Session 2025-12-30

- Q: What is the expected throughput requirement for the JAPIKey verification function? → A: No specific throughput requirement
- Q: How detailed should the structured error responses be when verification fails? → A: Detailed error types for each validation failure
- Q: What should be the maximum allowed token size to prevent resource exhaustion attacks? → A: 4KB
- Q: What should be the acceptable clock skew tolerance for validating time-based claims (exp, nbf, iat)? → A: No tolerance (strict time matching)
- Q: What should be the timeout for retrieving cryptographic keys from the callback function? → A: 5 seconds, configurable in the Config with value > 0

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Verify JAPIKey Token (Priority: P1)

As a service developer, I want to verify incoming JAPIKey tokens so that I can authenticate API requests and ensure they come from authorized sources.

**Why this priority**: This is the core functionality that enables secure API access using JAPIKeys. Without this, the entire authentication system fails.

**Independent Test**: Can be fully tested by providing a valid JAPIKey token and verifying it returns the expected claims, or providing an invalid token and confirming it returns an appropriate error.

**Acceptance Scenarios**:

1. **Given** a valid JAPIKey token with correct format, version, issuer, and signature, **When** the verify function is called with the token and appropriate configuration, **Then** it returns the validated claims from the token.
2. **Given** an invalid JAPIKey token with incorrect signature, **When** the verify function is called, **Then** it returns an appropriate structured error indicating signature verification failure.

---

### User Story 2 - Handle Malformed JAPIKey Tokens (Priority: P1)

As a service developer, I want the verification function to handle malformed JAPIKey tokens gracefully so that my service can respond appropriately to invalid authentication attempts.

**Why this priority**: Security-critical functionality to prevent malformed tokens from causing system errors or security vulnerabilities.

**Independent Test**: Can be tested by providing various malformed tokens (invalid format, missing fields, wrong version format) and confirming appropriate structured errors are returned.

**Acceptance Scenarios**:

1. **Given** a JAPIKey token with invalid version format, **When** the verify function is called, **Then** it returns a structured error indicating version validation failure.
2. **Given** a JAPIKey token with mismatched key ID and issuer, **When** the verify function is called, **Then** it returns a structured error indicating issuer/key ID mismatch.

---

### User Story 3 - Validate JAPIKey Constraints (Priority: P2)

As a service developer, I want the verification function to validate all special JAPIKey constraints so that only properly formatted tokens are accepted.

**Why this priority**: Ensures compliance with JAPIKey specification and prevents tokens that don't meet the required format from being accepted.

**Independent Test**: Can be tested by providing tokens that violate specific JAPIKey constraints (e.g., version number too high, issuer format incorrect) and confirming appropriate errors are returned.

**Acceptance Scenarios**:

1. **Given** a JAPIKey token with version number exceeding the maximum allowed, **When** the verify function is called, **Then** it returns a structured error indicating version constraint violation.
2. **Given** a JAPIKey token with issuer that doesn't match the expected base issuer format, **When** the verify function is called, **Then** it returns a structured error indicating issuer validation failure.

---

### User Story 4 - Security Validation (Priority: P1)

As a security officer, I want the verification function to implement comprehensive security validations so that the system is protected against all known token-based attacks.

**Why this priority**: Security is critical for the system's integrity and preventing unauthorized access through malicious tokens.

**Independent Test**: Can be tested by providing tokens designed to exploit various attack vectors (timing attacks, injection, resource exhaustion) and confirming they are properly rejected.

**Acceptance Scenarios**:

1. **Given** a JAPIKey token with an expired 'exp' claim, **When** the verify function is called, **Then** it returns a structured error indicating token expiration.
2. **Given** a JAPIKey token with an invalid algorithm in the header, **When** the verify function is called, **Then** it returns a structured error indicating algorithm mismatch.
3. **Given** an extremely large token designed to cause resource exhaustion, **When** the verify function is called, **Then** it returns a structured error indicating size violation.

---

### Edge Cases

- What happens when the token contains non-UTF8 characters?
- How does the system handle extremely large tokens that might cause memory issues?
- What if the callback function to retrieve cryptographic keys fails or times out?
- How does the system handle tokens with future expiration dates?
- What happens when the token version is in an unexpected format?
- How does the system handle tokens with invalid time claims (exp, nbf, iat)?
- What happens when the token contains unexpected nested structures?
- How does the system handle tokens with excessively large numeric values?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST provide a verify function that accepts a token string, configuration (including configurable timeout > 0), and a callback function to retrieve cryptographic keys by key ID
- **FR-002**: System MUST validate the token version format against the JAPIKey specification
- **FR-003**: System MUST validate that the issuer follows the required format with base issuer URL and UUID
- **FR-004**: System MUST verify that the key ID in the token header matches the UUID part of the issuer
- **FR-005**: System MUST verify the token signature using the retrieved cryptographic key from the callback function
- **FR-006**: System MUST return the validated claims when verification succeeds
- **FR-007**: System MUST return detailed structured errors with verbose messages for each specific validation failure, allowing for debugging purposes
- **FR-008**: System MUST validate that the version number doesn't exceed the maximum allowed version
- **FR-009**: System MUST decode the token without verification first to extract header and payload for validation
- **FR-010**: System MUST support only the RS256 cryptographic algorithm for signature verification
- **FR-011**: System MUST provide a function to pre-validate tokens before full verification
- **FR-012**: System MUST handle all error cases gracefully without exposing internal details
- **FR-013**: System MUST implement comprehensive tests covering all validation paths and error scenarios
- **FR-014**: System MUST use the golang-jwt/jwt/v5 library for JWT handling and validation as much as possible
- **FR-015**: System MUST log security-related events with appropriate detail for audit trails
- **FR-016**: System MUST validate that the token has not expired based on the 'exp' claim with no clock skew tolerance (strict time matching)
- **FR-017**: System MUST validate that the token is not before the 'nbf' (not before) time if present with no clock skew tolerance (strict time matching); tokens without 'nbf' are valid
- **FR-018**: System MUST validate that the token has a valid 'iat' (issued at) time if present with no clock skew tolerance (strict time matching); tokens without 'iat' are valid
- **FR-019**: System MUST implement constant-time comparison operations to prevent timing attacks during signature verification
- **FR-020**: System MUST enforce a maximum token size limit of 4KB to prevent resource exhaustion attacks
- **FR-021**: System MUST validate that the token contains only expected and properly formatted claims
- **FR-022**: System MUST validate that the 'alg' header parameter is exactly 'RS256' and reject all other algorithms
- **FR-023**: System MUST validate that the 'typ' header parameter is 'JWT' or absent
- **FR-024**: System MUST implement rate limiting or other protections against brute force attacks
- **FR-025**: System MUST validate that the token structure follows the expected format (header.payload.signature)
- **FR-026**: System MUST sanitize and validate all token components to prevent injection attacks
- **FR-027**: System MUST validate that cryptographic key IDs are properly formatted and safe to use
- **FR-028**: System MUST implement proper error handling to prevent information leakage through error messages
- **FR-029**: System MUST validate that the token does not contain unexpected nested structures that could lead to parsing vulnerabilities
- **FR-030**: System MUST validate that the token does not contain excessively large numeric values that could cause overflow issues

### Key Entities

- **JAPIKey Token**: A security token with specific format requirements including version, issuer, and key ID constraints
- **Verification Configuration**: Parameters needed for token verification including base issuer URL and key retrieval callback
- **Validated Claims**: The decoded payload from a successfully verified token
- **Structured Error**: A well-defined error object that indicates the specific reason for verification failure

## Dependencies and Assumptions

- The system has access to a function to retrieve cryptographic keys by key ID
- The system MUST use the golang-jwt/jwt/v5 library for JWT handling and validation as much as possible
- The system has access to standard cryptographic libraries (golang.org/x/crypto) for cryptographic operations when needed beyond what golang-jwt provides
- Network connectivity is available when retrieving cryptographic keys from remote sources
- The JAPIKey specification format is stable and will not change during implementation
- The base issuer URL format is known and consistent
- The system has appropriate protections against brute force and denial-of-service attacks
- The system has access to secure random number generation for cryptographic operations
- The system has appropriate time synchronization for validating time-based claims

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of valid JAPIKey tokens are successfully verified and return the correct claims
- **SC-002**: 100% of invalid JAPIKey tokens are rejected with appropriate structured errors
- **SC-004**: All possible token validation failure scenarios are covered by tests with at least 90% code coverage
- **SC-005**: Security audit confirms no vulnerabilities in the token verification implementation
- **SC-006**: Verification function successfully prevents all known token-based attacks including timing attacks, injection attacks, and resource exhaustion
- **SC-008**: All security-related events are logged with appropriate detail for audit trails without exposing sensitive information