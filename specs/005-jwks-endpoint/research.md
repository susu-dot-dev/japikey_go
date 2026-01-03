# Research: JAPIKey JWKS Endpoint Middleware

**Feature Branch**: `005-jwks-endpoint`
**Date**: January 2, 2026
**Phase**: Phase 0 - Research & Design Decisions

## Overview

This document consolidates research findings for implementing the JAPIKey JWKS endpoint middleware. Research focused on Go HTTP middleware patterns, database abstraction design, error handling conventions, and testing best practices.

---

## Research Areas

### 1. Go HTTP Middleware Pattern

**Decision**: Use standard Go middleware pattern with `func(next http.Handler) http.Handler` signature

**Rationale**: This is the idiomatic Go approach for middleware, consistent with the standard library `net/http` package and widely adopted in the Go ecosystem. The pattern is flexible, composable, and allows middleware to be chained easily.

**Implementation Pattern**:

```go
func middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Logic before handler
        // ...

        // Call next handler
        next.ServeHTTP(w, r)

        // Logic after handler (if needed)
        // ...
    })
}
```

**Key Considerations**:
- Return `http.HandlerFunc` which implements `http.Handler`
- Call `next.ServeHTTP(w, r)` to pass control to the next handler
- Can write response and short-circuit by not calling `next.ServeHTTP`
- Headers should be set before calling `next.ServeHTTP` to avoid issues

**Alternatives Considered**:
- Framework-specific patterns (gin, chi, echo): Rejected because this is a library that should work with any Go HTTP framework
- Context-based passing patterns: Rejected as unnecessary complexity for this use case

**Reference**: [Go HTTP Middleware Best Practices](https://gowebexamples.com/advanced-middleware/)

---

### 2. Database Abstraction Layer Design

**Decision**: Define a `DatabaseDriver` interface that returns concrete types and uses Go error wrapping for error classification

**Rationale**: Interface-based abstraction allows applications to implement their own storage logic (SQL, NoSQL, in-memory, etc.) while the middleware remains storage-agnostic. Using typed errors with wrapping enables proper error classification without requiring custom error types in the interface.

**Interface Design**:

```go
type DatabaseDriver interface {
    // GetKey retrieves an API key by its key ID (kid)
    // Returns the RSA public key, a boolean indicating if the key is revoked,
    // and an error if the operation fails
    GetKey(ctx context.Context, kid string) (*rsa.PublicKey, bool, error)
}
```

**Error Classification**:

1. **Key Not Found**: Wrap error with `errors.Is(err, ErrKeyNotFound)` check
2. **Database Timeout**: Wrap error with `errors.Is(err, context.DeadlineExceeded)`
3. **Database Unavailable**: Wrap error with `errors.Is(err, ErrDatabaseUnavailable)`
4. **Other Database Errors**: Generic database errors

**Rationale for Error Handling Approach**:
- Using `errors.Is()` and `errors.As()` allows the middleware to classify errors without exposing implementation details
- Applications can wrap their database errors appropriately
- Consistent with Go 1.13+ error handling best practices
- Allows the middleware to map database errors to appropriate HTTP status codes

**Alternatives Considered**:
- Custom error types in interface: Rejected because it forces applications to convert their errors to our types
- Returning error codes as strings or ints: Rejected as error-prone and un-Go-like
- Returning status codes from database layer: Rejected as mixing concerns (database layer shouldn't know about HTTP)

**Reference**: [Repository Pattern in Go](https://threedots.tech/post/repository-pattern-in-go/)

---

### 3. Error Response Format

**Decision**: Follow existing japikey error conventions defined in `errors/errors.go`

**Rationale**: The spec explicitly requires following japikey error conventions (FR-022, FR-023). Existing error types provide a consistent structure with `Code` and `Message` fields.

**Existing Error Types**:
- `ValidationError`: For invalid input
- `ConversionError`: For data conversion failures
- `KeyNotFoundError`: For missing keys
- `InternalError`: For unexpected failures
- `TokenExpiredError`: For expired tokens (not applicable here)

**Error Response Format**:

```go
type ErrorResponse struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}
```

**HTTP Status Code Mapping**:
- 404 Not Found: Key not found or revoked (KeyNotFoundError)
- 503 Service Unavailable: Database temporarily down (database timeout/unavailable)
- 500 Internal Server Error: Other unexpected errors (InternalError)

---

### 4. JWKS Generation Integration

**Decision**: Use existing `internal/jwks` package for JWKS generation

**Rationale**: The existing code already implements RFC 7517-compliant JWKS format with proper base64url encoding. Reusing this code avoids duplication and ensures consistency across the library.

**Existing Function**:

```go
func NewJWKS(publicKey *rsa.PublicKey, kid uuid.UUID) (*JWKS, error)
```

**Usage Pattern**:
1. Convert string kid from URL to `uuid.UUID`
2. Call `NewJWKS(publicKey, kid)` to create JWKS structure
3. JWKS implements `json.Marshaler`, so can be directly serialized to JSON

**Validation**: The existing code already validates:
- Public key is not nil
- kid is not empty (uuid.Nil)
- Proper RFC 7517 format with exactly one key
- Round-trip validation ensures encoded values match

---

### 5. Testing Strategy with httptest

**Decision**: Use Go's `net/http/httptest` package for comprehensive middleware testing

**Rationale**: The `httptest` package is the standard Go library for testing HTTP handlers and middleware. It provides `ResponseRecorder` for capturing responses and test servers for integration testing. This approach is idiomatic and widely used in the Go ecosystem.

**Testing Pattern**:

```go
func TestJWKSEndpoint(t *testing.T) {
    // Setup mock database
    mockDB := &MockDatabaseDriver{
        // Configure mock responses
    }

    // Create handler
    handler := CreateJWKSRouter(mockDB, 300)

    // Test cases
    tests := []struct {
        name           string
        kid            string
        expectedStatus int
        checkResponse  func(*testing.T, *httptest.ResponseRecorder)
    }{
        {
            name:           "valid key",
            kid:            "valid-kid",
            expectedStatus: http.StatusOK,
            checkResponse: func(t *testing.T, rr *httptest.ResponseRecorder) {
                // Validate JWKS response
                var jwks struct {
                    Keys []map[string]interface{} `json:"keys"`
                }
                err := json.Unmarshal(rr.Body.Bytes(), &jwks)
                assert.NoError(t, err)
                assert.Len(t, jwks.Keys, 1)
                assert.Equal(t, "RSA", jwks.Keys[0]["kty"])
            },
        },
        {
            name:           "key not found",
            kid:            "non-existent",
            expectedStatus: http.StatusNotFound,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Create request
            req, err := http.NewRequest("GET", "/"+tt.kid+"/.well-known/jwks.json", nil)
            assert.NoError(t, err)

            // Record response
            rr := httptest.NewRecorder()

            // Call handler
            handler.ServeHTTP(rr, req)

            // Validate
            assert.Equal(t, tt.expectedStatus, rr.Code)
            assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
            assert.Contains(t, rr.Header().Get("Cache-Control"), "max-age=300")

            if tt.checkResponse != nil {
                tt.checkResponse(t, rr)
            }
        })
    }
}
```

**Mock Database Implementation**:

```go
type MockDatabaseDriver struct {
    GetKeyFunc func(ctx context.Context, kid string) (*rsa.PublicKey, bool, error)
}

func (m *MockDatabaseDriver) GetKey(ctx context.Context, kid string) (*rsa.PublicKey, bool, error) {
    return m.GetKeyFunc(ctx, kid)
}
```

**Test Coverage Requirements**:
1. Valid key returns 200 with proper JWKS
2. Non-existent key returns 404
3. Revoked key returns 404
4. Database timeout returns 503
5. Database unavailable returns 503
6. Other database errors return 500
7. Cache-Control header is set correctly
8. Content-Type header is application/json
9. JWKS format is valid (RFC 7517)
10. Only requested key is returned (no other keys)
11. Invalid kid format returns 404
12. Concurrent requests are handled safely

**Reference**: [Testing HTTP Handlers with httptest](https://blog.questionable.services/article/testing-http-handlers-go/)

---

### 6. Path Parameter Extraction

**Decision**: Use Go's standard `net/http.ServeMux` with path parameter extraction

**Rationale**: Since Go 1.22, `net/http.ServeMux` supports wildcards for path parameter extraction, making external routing libraries unnecessary for this simple use case. This keeps dependencies minimal and follows standard library practices.

**Route Pattern**:

```go
mux := http.NewServeMux()
mux.HandleFunc("/{kid}/.well-known/jwks.json", jwksHandler)
```

**Parameter Extraction**:

```go
kid := r.PathValue("kid")
```

**Alternatives Considered**:
- External routers (chi, gin, echo): Rejected as unnecessary complexity and dependency for a simple single-route handler
- Manual path parsing: Rejected as error-prone and less maintainable

---

## Unresolved Questions

None. All technical decisions have been researched and resolved.

---

## Next Steps

Proceed to Phase 1 (Design & Contracts) to create:
1. `data-model.md` - Define data structures and entities
2. `contracts/api-contract.md` - Specify API contract for JWKS endpoint
3. `quickstart.md` - Document quick start guide for developers
