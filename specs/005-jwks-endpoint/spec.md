# Feature Specification: JAPIKey JWKS Endpoint Middleware

**Feature Branch**: `005-jwks-endpoint`
**Created**: January 2, 2026
**Status**: Draft

## Clarifications

### Session 2026-01-02

- Q: What is the default cache duration when the maxAgeSeconds parameter is not provided? → A: Default to 0 (no caching)
- Q: What status code should be returned for database errors? → B: Return 503 when database is temporarily down, 500 for other errors
- Q: What logging and observability requirements should be implemented? → A: No logging needed, except for 500-class errors
- Q: Is rate limiting in scope for this middleware? → A: Out of scope - applications handle rate limiting at router/gateway level
- Q: How should the middleware handle corrupted/malformed public keys from the database? → A: Not applicable - the database abstraction returns `*rsa.PublicKey` type, so the implementer of the abstraction handles any corruption/validation issues
**Input**: User description: "Implement a middleware function that serves the OIDC .well-known/jwks.json endpoint for japikey verification. This differs from standard JWKS implementations by using a unique URL structure where each API key has its own JWKS endpoint at /jwks/{kid}/.well-known/jwks.json."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Retrieve JWKS for Valid API Key (Priority: P1)

As a client application needing to verify a JAPIKey, I want to fetch the public key for a specific API key ID so that I can validate the authenticity of the API key without storing any secrets.

**Why this priority**: This is the core functionality of the endpoint. Without this capability, clients cannot verify JAPIKeys, making the entire japikey system unusable for authentication. This is the primary use case that enables the security model.

**Independent Test**: Can be fully tested by making an HTTP GET request to the JWKS endpoint with a valid key ID and verifying that the response contains a properly formatted JWKS with the correct public key. Delivers value by enabling API key verification.

**Acceptance Scenarios**:

1. **Given** an existing, non-revoked API key with ID "abc-123", **When** I send a GET request to "/{base-path}/abc-123/.well-known/jwks.json" (where {base-path} is where the middleware is mounted), **Then** I receive a JSON response with status code 200 containing a JWKS object with exactly one key that matches the public key for "abc-123", and the response includes a Cache-Control header

2. **Given** an existing, non-revoked API key with any valid ID format, **When** I request the JWKS endpoint for that ID, **Then** the response is returned within 100 milliseconds and contains only the public key for that specific ID (no other keys)

---

### User Story 2 - Handle Non-Existent API Key Requests (Priority: P1)

As a client application verifying JAPIKeys, I want to receive a clear error when I request a JWKS for a non-existent API key ID so that I can fail fast and not attempt verification with invalid keys.

**Why this priority**: Security and reliability are critical. Clients must be able to distinguish between valid and invalid API keys. This prevents attacks where invalid keys might be accepted if the endpoint returns unexpected responses.

**Independent Test**: Can be fully tested by making an HTTP GET request to the JWKS endpoint with a non-existent key ID and verifying that the response is a 404 error with appropriate error details. Delivers value by ensuring security and proper error handling.

**Acceptance Scenarios**:

1. **Given** an API key ID that does not exist in the database, **When** I send a GET request to "/{base-path}/{non-existent-id}/.well-known/jwks.json" (where {base-path} is where the middleware is mounted), **Then** I receive a JSON response with status code 404 containing an error message indicating the API key was not found

2. **Given** any request to the JWKS endpoint with a key ID that has never been created, **When** I make the request, **Then** no database insertion or modification occurs as a result

---

### User Story 3 - Handle Revoked API Key Requests (Priority: P1)

As a client application verifying JAPIKeys, I want to receive a 404 error when I request a JWKS for a revoked API key ID so that I can detect and reject compromised or invalid keys.

**Why this priority**: Key revocation is a critical security feature. If a revoked key returns a valid JWKS, the client would accept invalid API keys, creating a serious security vulnerability. This ensures that revoked keys cannot be used even if the JWT signature is still valid.

**Independent Test**: Can be fully tested by creating an API key, revoking it in the database, then requesting the JWKS endpoint and verifying a 404 response. Delivers value by enabling secure key revocation.

**Acceptance Scenarios**:

1. **Given** a revoked API key with ID "revoked-123", **When** I send a GET request to "/{base-path}/revoked-123/.well-known/jwks.json" (where {base-path} is where the middleware is mounted), **Then** I receive a JSON response with status code 404 containing an error message indicating the API key was not found

2. **Given** an API key that was valid but has been revoked for any reason (user action, security incident, etc.), **When** a client requests its JWKS, **Then** the endpoint treats it identically to a non-existent key, preventing its use

---

### User Story 4 - Configurable Cache Control Header (Priority: P2)

As an operator of a JAPIKey system, I want to configure the cache duration for JWKS responses so that I can control how long clients cache the public key information.

**Why this priority**: Caching affects both performance and security. Longer caching reduces load on the server but delays revocation detection. Shorter caching enables faster revocation but increases server load. This allows operators to balance these concerns for their use case.

**Independent Test**: Can be fully tested by configuring different cache durations and verifying that the Cache-Control header reflects the configured value. Delivers value by providing operational flexibility.

**Acceptance Scenarios**:

1. **Given** the middleware is configured with a cache duration of 300 seconds, **When** I request a JWKS endpoint, **Then** the response includes a Cache-Control header with "max-age=300"

2. **Given** the middleware is configured with a cache duration of 0, **When** I request a JWKS endpoint, **Then** the response includes a Cache-Control header with "max-age=0", indicating no caching should occur

3. **Given** a negative cache duration is provided, **When** the middleware processes the request, **Then** the Cache-Control header uses "max-age=0" (clamped to zero)

---

### Edge Cases

- What happens when the key ID format is invalid or contains special characters?
- How does the system handle concurrent requests for the same key ID?
- What happens if the database is temporarily unavailable?
- How does the system handle requests that don't match the expected URL pattern?
- What happens if the database query succeeds but returns a key without a valid public key?
- How does the system handle malformed key IDs that might be injection attacks?
- **What happens when the public key in the database is corrupted or malformed?** → Handled by the database abstraction implementation, which returns `*rsa.PublicKey` type. The middleware does not handle this case directly.
- How does the system handle extremely high request rates (rate limiting)? **Out of scope - rate limiting is handled by the application at the router/gateway level**

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST provide a middleware or router function that accepts a database driver and optional cache configuration as parameters
- **FR-002**: System MUST define a database abstraction interface that accepts a key ID and returns the RSA public key and a revoked boolean flag
- **FR-003**: System MUST match HTTP GET requests to the route pattern "/{kid}/.well-known/jwks.json" (the base path where the middleware is mounted is determined by the consumer)
- **FR-004**: System MUST extract the key ID (kid) parameter from the URL path
- **FR-005**: System MUST query the database via the abstraction interface to retrieve the API key data for the provided key ID
- **FR-006**: System MUST return a 404 Not Found response when the API key does not exist in the database
- **FR-007**: System MUST return a 404 Not Found response when the API key exists but has been revoked
- **FR-008**: System MUST construct a JSON response in JWKS format containing exactly one key
- **FR-009**: System MUST include the public key in JWKS format (RFC 7517) with fields for key type (kty), key ID (kid), modulus (n), and exponent (e)
- **FR-010**: System MUST set the Cache-Control header with a configurable max-age value in seconds
- **FR-011**: System MUST set the Content-Type header to "application/json"
- **FR-012**: System MUST return a 200 OK status code when a valid, non-revoked key is found
- **FR-013**: System MUST return error responses in JSON format with appropriate error details
- **FR-014**: System MUST default to 0 (no caching) when the cache duration parameter is not provided
- **FR-015**: System MUST clamp negative cache duration values to 0 to prevent invalid headers
- **FR-016**: System MUST ensure that the JWKS response contains only the public key for the requested key ID, never multiple keys
- **FR-017**: System MUST not expose any private key information in the response
- **FR-018**: System MUST handle database connection errors and return appropriate error responses
- **FR-019**: System MUST not modify the database state when serving JWKS requests (read-only operation)
- **FR-020**: System MUST handle invalid key ID formats gracefully (reject malformed IDs)
- **FR-021**: System MUST provide clear error messages for all failure scenarios
- **FR-022**: System MUST follow the japikey error conventions for consistent error responses across the library
- **FR-023**: System MUST log errors for all 500-class status responses (500, 503) for debugging and monitoring purposes

### Error Handling Requirements

The system MUST implement the following error handling behaviors:

- **NotFoundError**: Returned when the API key ID does not exist in the database
  - **Status Code**: 404
  - **Response**: JSON error object with error type and message

- **NotFoundError**: Returned when the API key exists but has been revoked
  - **Status Code**: 404
  - **Response**: JSON error object with error type and message (same as non-existent)

- **DatabaseError**: Returned when the database query fails or is unavailable
  - **Status Code**: 503 (Service Unavailable) when database is temporarily down, 500 (Internal Server Error) for other database errors
  - **Response**: JSON error object with error type and message

### API Interface

The system MUST provide a function with the following signature:

```go
func CreateJWKSRouter(db DatabaseDriver, maxAgeSeconds int) http.Handler
```

Where:
- `db`: A database driver interface that provides key lookup functionality
- `maxAgeSeconds`: Optional cache duration in seconds (0 means no caching, negative values are clamped to 0)
- Returns: An HTTP handler that can be mounted to handle JWKS requests

### Database Interface Requirement

The system MUST define a database abstraction interface that provides the ability to query for API key data given a key ID. This interface MUST:

- Accept a key ID (kid) as input
- Return the public key as an RSA public key structure (implementation independent of storage format)
- Return a boolean flag indicating whether the key has been revoked
- Handle error cases appropriately (e.g., key not found, database errors)

The interface abstraction allows the middleware to work with any database implementation while abstracting away storage details. Applications implementing this interface are responsible for converting their stored key format (e.g., JWK, PEM, or other formats) into the required RSA public key structure.

### URL Structure Note

The middleware handles the route pattern "/{kid}/.well-known/jwks.json" relative to where it is mounted. The base path (e.g., "/jwks", "/api-keys", "/keys") is determined by the application that mounts the middleware. For example:
- If mounted at "/jwks", the full URL would be "/jwks/{kid}/.well-known/jwks.json"
- If mounted at "/api-keys", the full URL would be "/api-keys/{kid}/.well-known/jwks.json"
- If mounted at the root "/", the full URL would be "/{kid}/.well-known/jwks.json"

This flexibility allows applications to choose a base path that fits their URL structure conventions.

### Key Entities

- **API Key**: A record stored in the database containing the public key, metadata, and revocation status. Key attributes include a unique key ID (kid), public key in JWK format, revoked flag, and associated user metadata.
- **JWKS (JSON Web Key Set)**: A JSON response format defined by RFC 7517 containing a set of public keys. In this implementation, it contains exactly zero or one key.
- **Key ID (kid)**: A unique identifier for each API key, used to lookup the corresponding public key. This ID is embedded in the JWT header and used as part of the URL path.
- **Cache-Control Header**: An HTTP header that specifies caching directives for clients, controlling how long the JWKS response can be cached.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of requests for valid, non-revoked API key IDs return a 200 status with a properly formatted JWKS response containing the correct public key
- **SC-002**: 100% of requests for non-existent or revoked API key IDs return a 404 status with an appropriate error message
- **SC-003**: JWKS responses contain exactly one key for valid requests and zero keys for 404 responses (never multiple keys)
- **SC-004**: All JWKS responses include a Cache-Control header that matches the configured cache duration
- **SC-005**: The endpoint returns responses within 100 milliseconds for valid requests under normal load
- **SC-006**: Error responses follow the japikey error conventions with consistent JSON structure
- **SC-007**: No private key information is ever exposed in any response or log
- **SC-008**: The endpoint handles concurrent requests for the same key ID without race conditions or database corruption
- **SC-009**: 100% of JWKS responses are valid according to RFC 7517 standards and can be parsed by standard JWT libraries
- **SC-010**: The endpoint treats revoked keys identically to non-existent keys, ensuring revocation is immediately effective

### Assumptions

- The database driver interface provides a method to look up API keys by key ID, returning an RSA public key structure and a revoked boolean flag
- The database storage format for public keys is implementation-specific (e.g., JWK, PEM, or other formats) and is converted to RSA public key by the interface implementation
- The API key ID (kid) is a string that can be extracted from the URL path
- The middleware will be used with standard HTTP routing mechanisms in Go
- Error response format follows the existing japikey error conventions
- Cache duration of 0 means clients should not cache the response at all
