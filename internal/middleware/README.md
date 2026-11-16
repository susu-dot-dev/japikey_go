# JWKS Endpoint Middleware

An `http.Handler` that serves the JWKS for a JAPIKey at `/{kid}/.well-known/jwks.json`, from your `DatabaseDriver`. Exported from the root `japikey` package.

## Quick Start

### Step 1: Implement Database Driver

Implement `japikey.DatabaseDriver`. `kid` is always the canonical lowercase UUID string.

```go
package main

import (
	"context"
	"errors"
	"uuid"

	"github.com/susu-dot-dev/japikey_go"
	japikeyerrors "github.com/susu-dot-dev/japikey_go/errors"
)

type MyDatabase struct {
	// Your database connection
}

func (db *MyDatabase) GetKey(ctx context.Context, kid string) (*japikey.KeyLookupResult, error) {
	// 1. Convert kid string to UUID
	kidUUID, err := uuid.Parse(kid)
	if err != nil {
		return nil, japikeyerrors.NewKeyNotFoundError("invalid kid format")
	}

	// 2. Query your database for the key
	// This is pseudo-code - replace with your actual database query
	keyData, err := db.queryKey(ctx, kidUUID)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, japikeyerrors.NewKeyNotFoundError("key not found")
		}
		return nil, err // wrapped errors are fine; context.DeadlineExceeded maps to 503
	}

	// 3. Parse your stored public key to an *ecdsa.PublicKey (version 2) or *rsa.PublicKey (version 1)
	publicKey, err := parsePublicKey(keyData.PublicKeyPEM)
	if err != nil {
		return nil, err
	}

	// 4. Return the key; a revoked key is served as 404
	return &japikey.KeyLookupResult{
		PublicKey: publicKey,
		Revoked:   keyData.Revoked,
	}, nil
}
```

### Step 2: Create JWKS Handler

```go
package main

import (
	"log"
	"net/http"

	"github.com/susu-dot-dev/japikey_go"
)

func main() {
	jwksHandler, err := japikey.CreateJWKSRouter(japikey.JWKSRouterConfig{
		DB:            &MyDatabase{},
		MaxAgeSeconds: 300, // Cache-Control max-age on 200s; 0 = no caching
	})
	if err != nil {
		log.Fatal(err)
	}

	// Mount so the full URL is <iss>/.well-known/jwks.json, where
	// iss = <base issuer URL>/<kid>. Here the base issuer URL is
	// https://example.com/jwks
	http.Handle("/jwks/", http.StripPrefix("/jwks", jwksHandler))

	log.Fatal(http.ListenAndServe(":8080", nil))
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
      "kty": "EC",
      "kid": "550e8400-e29b-41d4-a716-446655440000",
      "crv": "P-256",
      "x": "0w6qKrCjP_3e2QIQOKb0Ltfb_82Ty9nWBxhuxBS4oaM",
      "y": "8iZyeydfUoUqrSM5RrY04AkAA3cZqFQyGyYyhS42OUM",
      "alg": "ES256",
      "ver": 2
    }
  ]
}
```

Keys minted by earlier releases (version 1) are RSA, and are served exactly as before, with `kty`, `kid`, `n` and `e` only (no `alg` or `ver`).

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
	PublicKey crypto.PublicKey // *ecdsa.PublicKey (v2) or *rsa.PublicKey (v1)
	Revoked   bool
}
```

Contains the result of a database key lookup:
- `PublicKey`: The public key: an `*ecdsa.PublicKey` for version 2 keys or an `*rsa.PublicKey` for version 1 keys (nil if key not found)
- `Revoked`: Whether the key has been revoked

### CreateJWKSRouter

```go
func CreateJWKSRouter(config JWKSRouterConfig) (http.Handler, error)

type JWKSRouterConfig struct {
	DB            DatabaseDriver
	MaxAgeSeconds int           // 0 = no caching, negative clamped to 0
	Timeout       time.Duration // 0 = 5 seconds
}
```

Returns an error if `DB` is nil. Only the path `/{kid}/.well-known/jwks.json` is served, for any HTTP method. A `kid` that is not a UUID gets 404 without reaching the driver. The key must be a P-256 `*ecdsa.PublicKey` or an RSA key of 2048 to 4096 bits, or the response is 500.

## Error Handling

Driver errors are matched with `errors.As` / `errors.Is`, so wrapping is fine:

| Driver returns | Response |
|---|---|
| `nil` result, `PublicKey == nil` or `Revoked` | 404 |
| `*KeyNotFoundError` | 404 |
| `context.DeadlineExceeded`, `*DatabaseTimeoutError`, `*DatabaseUnavailableError` | 503 |
| anything else | 500 |

Error bodies are `{"code","message"}` with `Cache-Control: no-store`. Timeout, unavailable and other driver errors are logged with the standard `log` package (the full error text, so make sure your driver's errors contain no secrets).

## Mock Database Driver for Testing

Here's a simple mock database driver for testing:

```go
type MockDatabaseDriver struct {
	Keys    map[string]crypto.PublicKey
	Revoked map[string]bool
}

func (m *MockDatabaseDriver) GetKey(ctx context.Context, kid string) (*japikey.KeyLookupResult, error) {
	publicKey, ok := m.Keys[kid]
	if !ok {
		return nil, japikeyerrors.NewKeyNotFoundError("key not found")
	}
	return &japikey.KeyLookupResult{PublicKey: publicKey, Revoked: m.Revoked[kid]}, nil
}

func NewMockDatabaseDriver() *MockDatabaseDriver {
	return &MockDatabaseDriver{
		Keys:    make(map[string]crypto.PublicKey),
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
	"time"

	"github.com/susu-dot-dev/japikey_go"
)

func TestJWKSEndpoint(t *testing.T) {
	// Create mock database
	mockDB := NewMockDatabaseDriver()

	// Add a real key (the handler rejects weak or malformed keys)
	k, err := japikey.NewJAPIKey(japikey.Config{
		Subject:   "test",
		Issuer:    "https://example.com",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	mockDB.Keys[k.KeyID.String()] = k.PublicKey

	handler, err := japikey.CreateJWKSRouter(japikey.JWKSRouterConfig{DB: mockDB, MaxAgeSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("GET", "/"+k.KeyID.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Validate response
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}
```

## Troubleshooting

- **404 for a valid key**: the key is revoked, `GetKey` returned `*KeyNotFoundError` or a nil `PublicKey`, or the handler is mounted without `http.StripPrefix`, so the path doesn't match `/{kid}/.well-known/jwks.json`.
- **500 for a valid key**: the stored key is not a valid P-256 or 2048 to 4096 bit RSA key (logged), or the driver returned a plain error.
- **503**: the driver timed out or reported unavailable; return `*DatabaseTimeoutError` / `*DatabaseUnavailableError` (or let `context.DeadlineExceeded` through).

## Security Considerations

1. The middleware only handles public keys.
2. Revoked and unknown keys give identical 404s.
3. Serve over HTTPS; `Verify` requires an `https` issuer unless `AllowInsecureHTTP` is set.
4. Every valid-looking request reaches your driver, so add rate limiting and caching at the gateway or in the driver.
5. `MaxAgeSeconds` is how long a revoked key's JWKS may stay cached downstream; error responses are never cached.

## Additional Resources

- [RFC 7517: JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [Go httptest package](https://pkg.go.dev/net/http/httptest)

See the [main README](../../README.md).
