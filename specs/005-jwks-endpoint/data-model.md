# Data Model: JAPIKey JWKS Endpoint Middleware

**Feature Branch**: `005-jwks-endpoint`
**Date**: January 2, 2026
**Phase**: Phase 1 - Design & Contracts

## Overview

This document defines the data structures and entities used by the JAPIKey JWKS endpoint middleware.

---

## Core Entities

### DatabaseDriver Interface

The database abstraction interface that applications must implement to provide key lookup functionality.

**Location**: `jwks/jwks.go`

**Definition**:

```go
type DatabaseDriver interface {
    GetKey(ctx context.Context, kid string) (*rsa.PublicKey, bool, error)
}
```

**Methods**:

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| GetKey | ctx (context), kid (string) | publicKey (*rsa.PublicKey), revoked (bool), error (error) | Retrieves an API key by its key ID |

**Error Behavior**:
- Returns `(*rsa.PublicKey, false, nil)` when key exists and is not revoked
- Returns `(nil, false, ErrKeyNotFound)` when key does not exist
- Returns `(nil, true, nil)` when key exists but is revoked
- Returns `(nil, false, ErrDatabaseUnavailable)` for temporary database failures
- Returns `(nil, false, ErrDatabaseTimeout)` for query timeouts
- Returns other wrapped errors for unexpected database failures

---

### JWKS Endpoint Handler

The HTTP handler that serves JWKS requests.

**Location**: `jwks/jwks.go`

**Definition**:

```go
type JWKSHandler struct {
    db            DatabaseDriver
    maxAgeSeconds  int
}

func CreateJWKSRouter(db DatabaseDriver, maxAgeSeconds int) http.Handler
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| db | DatabaseDriver | Database driver for key lookups |
| maxAgeSeconds | int | Cache duration in seconds (0 = no caching) |

**Behavior**:
- Matches route pattern: `/{kid}/.well-known/jwks.json`
- Extracts `kid` from URL path
- Queries database for key data
- Returns appropriate HTTP response based on result

---

### Response Types

#### JWKS Response

The JWKS (JSON Web Key Set) response format, defined by RFC 7517.

**Location**: Uses existing `internal/jwks.JWKS` type

**JSON Structure**:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "uuid-string",
      "n": "base64url-encoded-modulus",
      "e": "base64url-encoded-exponent"
    }
  ]
}
```

**Validation Rules**:
- Contains exactly one key array element
- `kty` must be "RSA"
- `kid` must be a valid UUID
- `n` and `e` are base64url-encoded big integers
- Follows RFC 7517 format exactly

---

#### Error Response

The error response format for all failure scenarios.

**Location**: Uses existing error types from `errors/errors.go`

**JSON Structure**:

```json
{
  "code": "ErrorType",
  "message": "Human-readable error message"
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| code | string | Error type identifier (e.g., "KeyNotFoundError", "InternalError") |
| message | string | Human-readable error message |

**Validation Rules**:
- Both `code` and `message` are required
- `code` must match japikey error conventions
- `message` should be descriptive but not expose sensitive information

---

## Data Flow

### Request Processing Flow

```
HTTP GET Request
    ↓
Extract kid from URL path
    ↓
Validate kid format (UUID)
    ↓
Call db.GetKey(ctx, kid)
    ↓
┌─────────────────────────────┐
│  Database Response Types    │
├─────────────────────────────┤
│ Valid key (not revoked)     │ → 200 OK + JWKS
│ Key not found               │ → 404 Not Found
│ Key revoked                 │ → 404 Not Found
│ Database timeout            │ → 503 Service Unavailable
│ Database unavailable        │ → 503 Service Unavailable
│ Other error                 │ → 500 Internal Server Error
└─────────────────────────────┘
    ↓
Set headers (Cache-Control, Content-Type)
    ↓
Return JSON response
```

---

## State Transitions

### API Key States

```
[Key Created] ──(revoke)──> [Key Revoked]
                               ↓
                          [404 Not Found]

[Key Created] ──(request JWKS)──> [Return 200 + JWKS]
```

**State Descriptions**:
- **Key Created**: Key exists in database, not revoked, returns JWKS
- **Key Revoked**: Key exists but revoked flag is true, treated as not found
- **Not Found**: Key does not exist in database

**Invariants**:
- Once revoked, a key can never return a valid JWKS
- Revoked keys are indistinguishable from non-existent keys to clients
- Only non-revoked keys return JWKS responses

---

## Relationships

```
JWKSHandler
    ├── uses → DatabaseDriver
    │           └── GetKey()
    └── uses → internal/jwks.JWKS
                └── NewJWKS()
                    └── returns RFC 7517 compliant JWKS
```

---

## Constraints and Validation

### Input Validation

| Input | Validation Rule | Error Response |
|-------|----------------|----------------|
| kid (URL parameter) | Must be valid UUID string | 404 Not Found |
| kid (URL parameter) | Must not be empty | 404 Not Found |
| maxAgeSeconds | Negative values clamped to 0 | N/A (clamped, not error) |
| maxAgeSeconds | Optional (defaults to 0) | N/A |

### Output Validation

| Output | Validation Rule |
|--------|----------------|
| JWKS keys array | Must contain exactly one key |
| JWKS kty field | Must be "RSA" |
| JWKS kid field | Must match requested kid |
| JWKS n field | Base64url-encoded modulus |
| JWKS e field | Base64url-encoded exponent |
| Error code | Must be valid japikey error type |
| Cache-Control header | Must be "max-age={seconds}" |

### Security Constraints

- Private key information MUST never be exposed in responses or logs
- JWKS response contains ONLY public key information
- Error messages MUST NOT expose database details
- All database operations MUST be read-only
- Database queries MUST use context for cancellation and timeout

---

## Performance Considerations

### Cache Behavior

- Client-side caching controlled by `Cache-Control: max-age={seconds}` header
- Server-side caching: Not implemented (left to database layer if needed)
- Default: `max-age=0` (no caching) if not specified

### Concurrency

- Handler must be safe for concurrent use
- Database driver must handle concurrent requests
- No shared state between requests

### Database Query Performance

- Query should be indexed by kid for fast lookups
- Timeout should be enforced via context
- Connection pooling is database driver's responsibility

---

## Error Handling Matrix

| Scenario | Database Returns | HTTP Status | Response Type |
|----------|------------------|-------------|---------------|
| Valid key found, not revoked | (key, false, nil) | 200 OK | JWKS |
| Key not found | (nil, false, ErrKeyNotFound) | 404 Not Found | Error |
| Key revoked | (nil, true, nil) | 404 Not Found | Error |
| Database timeout | (nil, false, ErrDatabaseTimeout) | 503 Service Unavailable | Error |
| Database unavailable | (nil, false, ErrDatabaseUnavailable) | 503 Service Unavailable | Error |
| Other database error | (nil, false, wrapped error) | 500 Internal Server Error | Error |
| Invalid kid format | (nil, false, ErrKeyNotFound) | 404 Not Found | Error |

---

## Implementation Notes

### UUID Handling

- kid is passed as string from URL path
- Must be converted to `uuid.UUID` type for JWKS generation
- Invalid UUID format should be treated as key not found (404)

### Base64url Encoding

- JWKS uses base64url encoding (RFC 4648 without padding)
- Existing `internal/jwks` package handles encoding/decoding
- Modulus and exponent are encoded as big integers

### Context Usage

- Context from HTTP request should be passed to database driver
- Enables request cancellation and timeout propagation
- Logging should use request context for tracing

---

## Success Criteria Alignment

| Success Criteria | Data Model Element |
|------------------|---------------------|
| SC-001: 100% valid requests return 200 | JWKSHandler response logic |
| SC-002: 100% non-existent/revoked return 404 | DatabaseDriver error handling |
| SC-003: JWKS contains exactly one key | JWKS validation rules |
| SC-004: Cache-Control header matches config | JWKSHandler maxAgeSeconds field |
| SC-005: <100ms response time | Performance considerations |
| SC-006: Error responses follow conventions | Error response type |
| SC-007: No private key exposure | Security constraints |
| SC-008: Concurrent requests handled safely | Concurrency requirements |
| SC-009: JWKS valid per RFC 7517 | Uses existing validated JWKS code |
| SC-010: Revoked keys identical to non-existent | State transitions |
