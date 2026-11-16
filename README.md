# JAPIKey

JAPIKey is a Go library for minting and verifying API keys as ES256 JWTs. Each key gets its own ECDSA P-256 key pair; the private key is discarded after signing, so only the public key needs to be stored (and served as a JWKS).

New keys are version 2 (`ver: "japikey-v2"`, ES256). Keys minted by earlier releases are version 1 (`japikey-v1`, RS256, 2048-bit RSA) and keep verifying: the token's version picks the algorithm, and both kinds of public key can be stored side by side. See [Upgrading from version 1](#upgrading-from-version-1).

## Installation

```bash
go get github.com/susu-dot-dev/japikey_go
```

## Usage

### Generation

```go
package main

import (
    "fmt"
    "time"
    "github.com/susu-dot-dev/japikey_go"
)

func main() {
    config := japikey.Config{
        Subject: "user-123",
        // Base issuer URL; the token's iss becomes "<Issuer>/<key id>", and its
        // JWKS is served at "<iss>/.well-known/jwks.json". Must be https (see
        // AllowInsecureHTTP), canonical, with no query, fragment or user info.
        Issuer:    "https://myapp.com",
        Audience:  "myapp-users",
        ExpiresAt: time.Now().Add(24 * time.Hour), // at least 5s in the future
    }

    result, err := japikey.NewJAPIKey(config)
    if err != nil {
        // *japikey.ValidationError (bad config, token too large) or *japikey.InternalError
        fmt.Println(err)
        return
    }

    // Give result.JWT to the user once. Store result.PublicKey and result.KeyID;
    // the private key no longer exists. Do not log the JWT: it is the secret.
    fmt.Printf("Key ID: %s\n", result.KeyID)
}
```

### Verification

```go
package main

import (
    "context"
    "crypto"
    "errors"
    "fmt"
    "log"
    "time"
    "uuid"
    "github.com/susu-dot-dev/japikey_go"
)

func main() {
    tokenString := "your.jwt.token.here" // from the request

    config := japikey.VerifyConfig{
        BaseIssuerURL: "https://myapp.com", // same rules as Config.Issuer
        Timeout:       5 * time.Second,     // key retrieval; default 5s
        Audience:      "myapp-users",       // not checked when empty; set it
    }

    // Look up the public key. Honor ctx for any I/O. Return a
    // *japikey.KeyNotFoundError if the key does not exist or is revoked.
    keyFunc := func(ctx context.Context, keyID uuid.UUID) (crypto.PublicKey, error) {
        return retrievePublicKey(ctx, keyID)
    }

    result, err := japikey.Verify(context.Background(), tokenString, config, keyFunc)
    if err != nil {
        // *UnauthorizedError for every rejected token: send the same 401 for
        // all, and log Cause only. *DatabaseTimeoutError and *InternalError
        // are server-side (503 / 500). See japikey/README.md.
        var unauthorized *japikey.UnauthorizedError
        if errors.As(err, &unauthorized) {
            log.Printf("token rejected: %v", unauthorized.Cause)
        }
        return
    }

    fmt.Printf("Claims: %+v, key ID: %s\n", result.Claims, result.KeyID)
}

// retrievePublicKey is yours to implement (database, or a fetch of the JWKS endpoint).
func retrievePublicKey(ctx context.Context, keyID uuid.UUID) (crypto.PublicKey, error) {
    return nil, fmt.Errorf("not implemented")
}
```

### Adding Custom Claims

`sub`, `iss`, `aud`, `exp`, `iat` and `ver` are set by the library and cannot be overridden.

```go
config := japikey.Config{
    Subject:   "user-123",
    Issuer:    "https://myapp.com",
    Audience:  "myapp-users",
    ExpiresAt: time.Now().Add(24 * time.Hour),
    Claims: map[string]interface{}{
        "role": "admin",
        "permissions": []string{"read", "write"},
        "custom_field": "custom_value",
    },
}

result, err := japikey.NewJAPIKey(config)
```

The token must stay within 4096 bytes.

## Error Handling

- `NewJAPIKey`: `*ValidationError` (invalid config, oversized token) or `*InternalError`.
- `Verify`: `*UnauthorizedError` for every rejected token, `*DatabaseTimeoutError`, or `*InternalError`. See [japikey/README.md](japikey/README.md).

Use `errors.As` to match them.

## Serving the JWKS

`japikey.CreateJWKSRouter` serves `/{kid}/.well-known/jwks.json` from your `DatabaseDriver`; see [internal/middleware/README.md](internal/middleware/README.md). Mount it so the full URL is `<iss>/.well-known/jwks.json`.

Third-party verifiers must not trust `iss` to locate the JWKS: check that it equals your configured base URL plus `/<uuid>` before fetching.

## Security

- Each key uses its own P-256 pair; the private key is discarded after signing (it is not zeroed from memory).
- The algorithm is chosen by the token's signed `ver` claim, never by its `alg` header: version 2 is ES256 only, version 1 is RS256 only. Unknown versions (including `japikey-v0`) are rejected, and the key returned by your callback must be the type that version needs. Tokens over 4096 bytes are rejected. `exp` and `nbf` have no clock skew tolerance; `iat` allows 30s.
- Revocation takes effect when the JWKS stops being served (or `MaxAgeSeconds` caches expire). Keys have no maximum lifetime.

## License

This project is licensed under the terms specified in the LICENSE file.

## Upgrading from version 1

- `NewJAPIKey` now mints ES256 / `japikey-v2` keys. `JAPIKey.PublicKey` is a `crypto.PublicKey` holding an `*ecdsa.PublicKey`.
- `JWKCallback`, `KeyLookupResult.PublicKey` and `NewJWKS` take a `crypto.PublicKey` instead of `*rsa.PublicKey`. Return an `*rsa.PublicKey` for existing version 1 keys and an `*ecdsa.PublicKey` for version 2 keys. Storing keys as PKIX (`x509.MarshalPKIXPublicKey` / `ParsePKIXPublicKey`) handles both without a schema change.
- The served JWK of a version 2 key is `{"kty":"EC","crv":"P-256","x":...,"y":...,"alg":"ES256","ver":2,"kid":...}`. Version 1 JWKs are unchanged (no `alg` or `ver`).
- `japikey-v0` tokens are no longer accepted.
