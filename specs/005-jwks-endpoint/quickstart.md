# Quick Start Guide: JWKS Endpoint Middleware

**Feature Branch**: `005-jwks-endpoint`
**Date**: January 2, 2026

## Overview

The JAPIKey JWKS endpoint middleware serves the OIDC `.well-known/jwks.json` endpoint for API key verification. This guide shows you how to integrate the middleware into your Go application.

---

## Installation

```bash
go get github.com/susu-dot-dev/japikey
```

---

## Basic Usage

### Step 1: Implement the Database Driver

Implement the `japikey.DatabaseDriver` interface to provide key lookup functionality:

```go
package main

import (
    "context"
    "crypto/rsa"
    "github.com/google/uuid"
    "errors"
    "github.com/susu-dot-dev/japikey"
    "github.com/susu-dot-dev/japikey/errors"
)

type MyDatabase struct {
    // Your database connection
}

func (db *MyDatabase) GetKey(ctx context.Context, kid string) (*rsa.PublicKey, bool, error) {
    // 1. Convert kid string to UUID
    kidUUID, err := uuid.Parse(kid)
    if err != nil {
        return nil, false, errors.NewKeyNotFoundError("invalid kid format")
    }

    // 2. Query your database for the key
    // This is pseudo-code - replace with your actual database query
    keyData, err := db.queryKey(ctx, kidUUID)
    if err != nil {
        if errors.Is(err, ErrKeyNotFound) {
            return nil, false, errors.NewKeyNotFoundError("key not found")
        }
        if errors.Is(err, context.DeadlineExceeded) {
            return nil, false, errors.NewDatabaseTimeoutError("database timeout")
        }
        return nil, false, err
    }

    // 3. Parse your stored public key to *rsa.PublicKey
    // Your storage format determines how you do this
    publicKey, err := parsePublicKey(keyData.PublicKeyPEM)
    if err != nil {
        return nil, false, err
    }

    // 4. Return the public key, revoked flag, and nil error
    return publicKey, keyData.Revoked, nil
}
```

### Step 2: Create the JWKS Handler

Create the JWKS handler with your database driver:

```go
package main

import (
    "github.com/susu-dot-dev/japikey"
)

func main() {
    // Initialize your database
    db := &MyDatabase{
        // Your database configuration
    }

    // Create JWKS handler with cache duration of 300 seconds (5 minutes)
    maxAgeSeconds := 300
    jwksHandler := japikey.CreateJWKSRouter(db, maxAgeSeconds)

    // Mount the handler at your desired base path
    // The full URL will be: /jwks/{kid}/.well-known/jwks.json
    http.Handle("/jwks/", jwksHandler)

    // Start the server
    http.ListenAndServe(":8080", nil)
}
```

### Step 3: Test the Endpoint

```bash
curl http://localhost:8080/jwks/550e8400-e29b-41d4-a716-4466554400000/.well-known/jwks.json
```

---

## Basic Usage

### Step 1: Implement the Database Driver

Implement the `DatabaseDriver` interface to provide key lookup functionality:

```go
package main

import (
    "context"
    "crypto/rsa"
    "github.com/google/uuid"
    "errors"
    "github.com/susu-dot-dev/japikey"
)

type MyDatabase struct {
    // Your database connection
}

func (db *MyDatabase) GetKey(ctx context.Context, kid string) (*rsa.PublicKey, bool, error) {
    // 1. Convert kid string to UUID
    kidUUID, err := uuid.Parse(kid)
    if err != nil {
        return nil, false, errors.NewKeyNotFoundError
    }

    // 2. Query your database for the key
    // This is pseudo-code - replace with your actual database query
    keyData, err := db.queryKey(ctx, kidUUID)
    if err != nil {
        if errors.Is(err, ErrKeyNotFound) {
            return nil, false, errors.NewKeyNotFoundError
        }
        if errors.Is(err, context.DeadlineExceeded) {
            return nil, false, errors.NewDatabaseTimeoutError
        }
        return nil, false, err
    }

    // 3. Parse your stored public key to *rsa.PublicKey
    // Your storage format determines how you do this
    publicKey, err := parsePublicKey(keyData.PublicKeyPEM)
    if err != nil {
        return nil, false, err
    }

    // 4. Return the public key, revoked flag, and nil error
    return publicKey, keyData.Revoked, nil
}
```

### Step 2: Create the JWKS Handler

Create the JWKS handler with your database driver:

```go
package main

import (
    "github.com/susu-dot-dev/japikey"
)

func main() {
    // Initialize your database
    db := &MyDatabase{
        // Your database configuration
    }

    // Create JWKS handler with cache duration of 300 seconds (5 minutes)
    maxAgeSeconds := 300
    jwksHandler := japikey.CreateJWKSRouter(db, maxAgeSeconds)

    // Mount the handler at your desired base path
    // The full URL will be: /jwks/{kid}/.well-known/jwks.json
    http.Handle("/jwks/", jwksHandler)

    // Start the server
    http.ListenAndServe(":8080", nil)
}
```

### Step 3: Test the Endpoint

```bash
curl http://localhost:8080/jwks/550e8400-e29b-41d4-a716-446655440000/.well-known/jwks.json
```

Expected response:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "550e8400-e29b-41d4-a716-446655440000",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB"
    }
  ]
}
```

---

## Configuration Options

### Cache Duration

Control how long clients cache the JWKS response:

```go
// No caching (default)
jwksHandler := japikey.CreateJWKSRouter(db, 0)

// Cache for 5 minutes (300 seconds)
jwksHandler := japikey.CreateJWKSRouter(db, 300)

// Cache for 1 hour (3600 seconds)
jwksHandler := japikey.CreateJWKSRouter(db, 3600)
```

**Note**: Negative values are automatically clamped to 0.

### Base Path

Choose the base path that fits your URL structure:

```go
// Mount at /jwks
// URL: /jwks/{kid}/.well-known/jwks.json
http.Handle("/jwks/", jwksHandler)

// Mount at /api-keys
// URL: /api-keys/{kid}/.well-known/jwks.json
http.Handle("/api-keys/", jwksHandler)

// Mount at root
// URL: /{kid}/.well-known/jwks.json
http.Handle("/", jwksHandler)
```

---

## Error Handling

### Database Error Types

Your database driver should return specific error types:

```go
// Key not found (404)
return nil, false, errors.NewKeyNotFoundError

// Database timeout (503)
return nil, false, errors.NewDatabaseTimeoutError

// Database unavailable (503)
return nil, false, errors.NewDatabaseUnavailableError

// Other errors (500)
return nil, false, err
```

### Logging

The middleware logs 500-class errors for debugging. For example:

```go
log.Printf("[JWKS] Database unavailable: %v", err)
```

---

## Storage Formats

### Option 1: Store Public Key as PEM

```go
type KeyData struct {
    Kid         uuid.UUID
    PublicKeyPEM string
    Revoked     bool
}

func parsePublicKey(pem string) (*rsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(pem))
    if block == nil {
        return nil, errors.New("failed to decode PEM block")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    rsaPub, ok := pub.(*rsa.PublicKey)
    if !ok {
        return nil, errors.New("not an RSA public key")
    }

    return rsaPub, nil
}
```

### Option 2: Store Public Key as JWK

```go
type KeyData struct {
    Kid         uuid.UUID
    PublicKeyJWK string
    Revoked     bool
}

func parsePublicKey(jwkJSON string) (*rsa.PublicKey, error) {
    var jwk struct {
        N string `json:"n"`
        E string `json:"e"`
    }

    if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
        return nil, err
    }

    // Decode base64url values
    nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
    if err != nil {
        return nil, err
    }

    eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
    if err != nil {
        return nil, err
    }

    // Reconstruct RSA public key
    n := new(big.Int).SetBytes(nBytes)
    e := new(big.Int).SetBytes(eBytes)

    return &rsa.PublicKey{
        N: n,
        E: int(e.Int64()),
    }, nil
}
```

---

## Integration with Web Frameworks

### Gin Framework

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/susu-dot-dev/japikey"
)

func main() {
    router := gin.Default()

    db := &MyDatabase{}
    jwksHandler := japikey.CreateJWKSRouter(db, 300)

    // Wrap the handler for Gin
    router.Any("/jwks/:kid/.well-known/jwks.json", func(c *gin.Context) {
        jwksHandler.ServeHTTP(c.Writer, c.Request)
    })

    router.Run(":8080")
}
```

### Chi Router

```go
import (
    "github.com/go-chi/chi/v5"
    "github.com/susu-dot-dev/japikey"
)

func main() {
    r := chi.NewRouter()

    db := &MyDatabase{}
    jwksHandler := japikey.CreateJWKSRouter(db, 300)

    r.Mount("/jwks", jwksHandler)

    http.ListenAndServe(":8080", r)
}
```

---

## Testing Your Implementation

### Using httptest

```go
package main

import (
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/susu-dot-dev/japikey"
    "github.com/stretchr/testify/assert"
)

func TestJWKSEndpoint(t *testing.T) {
    // Setup mock database
    mockDB := &MockDatabaseDriver{}

    // Create handler
    handler := japikey.CreateJWKSRouter(mockDB, 300)

    // Test request
    req, _ := http.NewRequest("GET", "/test-kid/.well-known/jwks.json", nil)
    rr := httptest.NewRecorder()

    handler.ServeHTTP(rr, req)

    // Validate response
    assert.Equal(t, http.StatusOK, rr.Code)
    assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
    assert.Contains(t, rr.Header().Get("Cache-Control"), "max-age=300")
}
```

---

## Common Patterns

### Connection Pooling

```go
type MyDatabase struct {
    db *sql.DB
}

func NewMyDatabase(dsn string) (*MyDatabase, error) {
    db, err := sql.Open("postgres", dsn)
    if err != nil {
        return nil, err
    }

    // Configure connection pool
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(5)
    db.SetConnMaxLifetime(5 * time.Minute)

    return &MyDatabase{db: db}, nil
}
```

### Context Timeouts

```go
func (db *MyDatabase) GetKey(ctx context.Context, kid string) (*rsa.PublicKey, bool, error) {
    // Add timeout to context
    ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()

    // Query with timeout
    keyData, err := db.queryKey(ctx, kidUUID)
    if errors.Is(err, context.DeadlineExceeded) {
        return nil, false, errors.NewDatabaseTimeoutError
    }

    return publicKey, keyData.Revoked, nil
}
```

---

## Troubleshooting

### Key Not Found (404)

**Problem**: Requests return 404 for valid keys

**Possible Causes**:
1. UUID format mismatch in database
2. Key is marked as revoked
3. Database query returns nil for valid keys

**Solution**: Verify your `GetKey` implementation returns `(nil, false, errors.NewKeyNotFoundError)` only when the key truly doesn't exist.

### Database Timeout (503)

**Problem**: Requests return 503 intermittently

**Possible Causes**:
1. Database query is slow
2. Connection pool exhausted
3. Network issues

**Solution**: 
1. Add indexes on kid column
2. Increase connection pool size
3. Optimize database queries
4. Return `errors.NewDatabaseTimeoutError` for timeouts

### Invalid JWKS Format

**Problem**: Clients cannot parse JWKS response

**Possible Causes**:
1. Public key is malformed
2. Modulus or exponent encoding is incorrect

**Solution**: Ensure your `parsePublicKey` function returns a valid `*rsa.PublicKey`. The JWKS middleware handles RFC 7517 encoding.

---

## Performance Tips

1. **Index your database**: Ensure the kid column is indexed for fast lookups
2. **Use appropriate cache duration**: Balance between performance and security
3. **Connection pooling**: Configure connection pool to handle concurrent requests
4. **Monitor response times**: Ensure queries complete within your timeout threshold

---

## Security Considerations

1. **Never expose private keys**: The middleware only returns public keys
2. **Treat revoked keys as not found**: Clients cannot distinguish revoked vs non-existent keys
3. **Use HTTPS**: Always serve JWKS endpoints over HTTPS
4. **Validate kid format**: Reject malformed kid strings early
5. **Implement rate limiting**: Add rate limiting at the router/gateway level (not in this middleware)

---

## Additional Resources

- [RFC 7517: JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [JAPIKey Documentation](https://github.com/susu-dot-dev/japikey)
- [Go httptest package](https://pkg.go.dev/net/http/httptest)

---

## Support

For issues or questions:
- Open an issue on GitHub: [github.com/susu-dot-dev/japikey/issues](https://github.com/susu-dot-dev/japikey/issues)
- Check the main documentation: [README.md](../README.md)
