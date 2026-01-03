# JWKS Endpoint Middleware

This package provides HTTP middleware for serving JWKS (JSON Web Key Set) endpoint for JAPIKey verification.

## Installation

```bash
go get github.com/susu-dot-dev/japikey
```

## Quick Start

The JWKS middleware is available at package root level. Import and use:

```go
import (
    "github.com/susu-dot-dev/japikey"
)
```

### Step 1: Implement Database Driver

Implement `japikey.DatabaseDriver` interface to provide key lookup functionality:

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

func (db *MyDatabase) GetKey(ctx context.Context, kid string) (*japikey.KeyLookupResult, error) {
	// 1. Convert kid string to UUID
	kidUUID, err := uuid.Parse(kid)
	if err != nil {
		return nil, errors.NewKeyNotFoundError("invalid kid format")
	}

	// 2. Query your database for the key
	// This is pseudo-code - replace with your actual database query
	keyData, err := db.queryKey(ctx, kidUUID)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, errors.NewKeyNotFoundError("key not found")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.NewDatabaseTimeoutError("database timeout")
		}
		return nil, err
	}

	// 3. Parse your stored public key to *rsa.PublicKey
	// Your storage format determines how you do this
	publicKey, err := parsePublicKey(keyData.PublicKeyPEM)
	if err != nil {
		return nil, err
	}

	// 4. Return KeyLookupResult with public key and revoked status
	return &japikey.KeyLookupResult{
		PublicKey: publicKey,
		Revoked:   keyData.Revoked,
	}, nil
}
```

### Step 2: Create JWKS Handler

Create JWKS handler with your database driver:

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

Expected response:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "550e8400-e29b-41d4-a716-4466554400000",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB"
    }
  ]
}
```

## API Reference

### DatabaseDriver Interface

```go
type DatabaseDriver interface {
	GetKey(ctx context.Context, kid string) (*KeyLookupResult, error)
}
```

Interface that applications must implement to provide key lookup functionality.

### KeyLookupResult

```go
type KeyLookupResult struct {
	PublicKey *rsa.PublicKey
	Revoked   bool
}
```

Contains the result of a database key lookup:
- `PublicKey`: The RSA public key (nil if key not found)
- `Revoked`: Whether the key has been revoked

### CreateJWKSRouter

```go
func CreateJWKSRouter(db DatabaseDriver, maxAgeSeconds int) http.Handler
```

Creates a new JWKS HTTP handler.

**Parameters**:
- `db`: DatabaseDriver implementation for key lookups
- `maxAgeSeconds`: Cache duration in seconds (0 = no caching, negative values clamped to 0)

**Returns**: `http.Handler` that can be mounted in any Go HTTP server

## Error Handling

### Database Error Types

Your database driver should return specific error types:

```go
import "github.com/susu-dot-dev/japikey/errors"

// Key not found (404)
return nil, errors.NewKeyNotFoundError("key not found")

// Database timeout (503)
return nil, errors.NewDatabaseTimeoutError("database timeout")

// Database unavailable (503)
return nil, errors.NewDatabaseUnavailableError("database unavailable")

// Other errors (500)
return nil, errors.New("unexpected error")
```

### Logging

The middleware logs 500-class errors for debugging. For example:

```go
log.Printf("[JWKS] Database timeout: %v", err)
```

## Mock Database Driver for Testing

Here's a simple mock database driver for testing:

```go
type MockDatabaseDriver struct {
	Keys    map[string]*rsa.PublicKey
	Revoked map[string]bool
}

func (m *MockDatabaseDriver) GetKey(ctx context.Context, kid string) (*KeyLookupResult, error) {
	publicKey, ok := m.Keys[kid]
	if !ok {
		return nil, errors.NewKeyNotFoundError("key not found")
	}

	revoked := m.Revoked[kid]
	return &KeyLookupResult{
		PublicKey: publicKey,
		Revoked:   revoked,
	}, nil
}

func NewMockDatabaseDriver() *MockDatabaseDriver {
	return &MockDatabaseDriver{
		Keys:    make(map[string]*rsa.PublicKey),
		Revoked: make(map[string]bool),
	}
}
```

Using the mock:

```go
import (
	"net/http"
	"net/http/httptest"
	"testing"
	"github.com/susu-dot-dev/japikey"
)

func TestJWKSEndpoint(t *testing.T) {
	// Create mock database
	mockDB := NewMockDatabaseDriver()

	// Add a test key
	publicKey := &rsa.PublicKey{N: big.NewInt(12345), E: 65537}
	mockDB.Keys["test-key-id"] = publicKey
	mockDB.Revoked["test-key-id"] = false

	// Create handler
	handler := japikey.CreateJWKSRouter(mockDB, 300)

	// Test request
	req, _ := http.NewRequest("GET", "/test-key-id/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Validate response
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}
```

## Troubleshooting

### Key Not Found (404)

**Problem**: Requests return 404 for valid keys

**Possible Causes**:
1. UUID format mismatch in database
2. Key is marked as revoked
3. Database query returns nil for valid keys

**Solution**: Verify your `GetKey` implementation returns `nil, errors.NewKeyNotFoundError(...))` only when key truly doesn't exist.

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
4. Return `errors.NewDatabaseTimeoutError(...)` for timeouts

## Security Considerations

1. **Never expose private keys**: The middleware only returns public keys
2. **Treat revoked keys as not found**: Clients cannot distinguish revoked vs non-existent keys
3. **Use HTTPS**: Always serve JWKS endpoints over HTTPS
4. **Validate kid format**: Reject malformed kid strings early
5. **Implement rate limiting**: Add rate limiting at the router/gateway level (not in this middleware)

## Additional Resources

- [RFC 7517: JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [JAPIKey Documentation](https://github.com/susu-dot-dev/japikey)
- [Go httptest package](https://pkg.go.dev/net/http/httptest)

## Support

For issues or questions:
- Open an issue on GitHub: [github.com/susu-dot-dev/japikey/issues](https://github.com/susu-dot-dev/japikey/issues)
- Check the main documentation: [README.md](../README.md)
