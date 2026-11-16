# JAPIKey Verification

Verification of JAPIKey tokens (ES256 JWTs for version 2 keys, RS256 for version 1) with a caller-supplied key lookup. Everything here is also exported from the root `japikey` package.

## Usage

### Basic Verification

```go
package main

import (
    "context"
    "crypto"
    "errors"
    "fmt"
    "log"
    "net/http"
    "time"
    "uuid"

    "github.com/susu-dot-dev/japikey_go"
)

func authenticate(w http.ResponseWriter, tokenString string) {
    config := japikey.VerifyConfig{
        BaseIssuerURL: "https://example.com",
        Timeout:       5 * time.Second, // key retrieval; default 5s
        Audience:      "example-users", // not checked when empty; set it
    }

    // ctx carries the Timeout deadline; honor it for any I/O. Return a
    // *japikey.KeyNotFoundError if the key does not exist or is revoked
    // (sql.ErrNoRows and fs.ErrNotExist are treated the same way).
    keyFunc := func(ctx context.Context, keyID uuid.UUID) (crypto.PublicKey, error) {
        return retrievePublicKey(ctx, keyID)
    }

    result, err := japikey.Verify(context.Background(), tokenString, config, keyFunc)
    if err != nil {
        var unauthorized *japikey.UnauthorizedError
        var timeout *japikey.DatabaseTimeoutError
        switch {
        case errors.As(err, &unauthorized):
            // Same response for every bad token. Log the cause, never return it.
            log.Printf("token rejected: %v", unauthorized.Cause)
            http.Error(w, "unauthorized", http.StatusUnauthorized)
        case errors.As(err, &timeout):
            http.Error(w, "unavailable", http.StatusServiceUnavailable)
        default: // *japikey.InternalError: misconfiguration or failing callback
            http.Error(w, "internal error", http.StatusInternalServerError)
        }
        return
    }

    fmt.Printf("Claims: %+v, key ID: %s\n", result.Claims, result.KeyID)
}
```

### Pre-validation

`ShouldVerify` runs the same key-free checks as `Verify` (see below, except expiry) to route tokens, e.g. to tell JAPIKeys from other JWTs. It accepts `http` base URLs; `Verify` enforces the scheme.

```go
if japikey.ShouldVerify(tokenString, "https://example.com") {
    result, err := japikey.Verify(ctx, tokenString, config, keyFunc)
}
```

## Error Handling

`Verify` returns one of three error types:

- `*UnauthorizedError`: the token was rejected, for any reason (malformed,
  oversized, wrong `alg`, `kid`, `ver`, `iss` or `sub`, unknown or revoked key,
  weak key, bad signature, expired, not yet valid, wrong audience). Its message
  is always `"unauthorized"`. Respond identically (e.g. HTTP 401) to all of
  them: varying the response by cause lets anyone probe which key IDs exist or
  were revoked. The specific cause (`*ValidationError`, `*KeyNotFoundError`,
  `*TokenExpiredError`) is in `Cause` and reachable with `errors.As`, for
  logging only. `*TokenExpiredError` only means the unverified token claims to
  be expired.
- `*DatabaseTimeoutError`: key retrieval timed out or `ctx` was cancelled.
- `*InternalError`: configuration problem (nil callback, invalid
  `BaseIssuerURL`) or a failing or panicking callback.

## Base issuer URL

`Config.Issuer` and `VerifyConfig.BaseIssuerURL` must be an absolute `https`
URL with a host, no user info, query or fragment, in canonical form (exactly
what `url.Parse(...).String()` returns), ending in at most one `/`. Set
`AllowInsecureHTTP` on the config to permit `http` for local development.
The path must be clean and unescaped: no empty, `.` or `..` segments and no
`%` escapes, because the JWKS route is matched by `http.ServeMux`, which
redirects or decodes such paths. `NewJAPIKey` returns a `*ValidationError` and
`Verify` an `*InternalError` for an invalid value.

## Key requirements

The token's `ver` claim selects the algorithm and the key type: `japikey-v2`
tokens are verified with ES256 and need an `*ecdsa.PublicKey` on P-256 (a valid
curve point), and `japikey-v1` tokens (minted by earlier releases) are verified
with RS256 and need an `*rsa.PublicKey` of 2048 to 4096 bits with an odd modulus
and an odd exponent between 3 and 2^31-1. These are the same rules applied when
building a JWKS. A key of another type, or of the wrong type for the token's
version, causes the token to be rejected. Unknown versions, including
`japikey-v0`, are rejected.

## Order of checks

Size, strict base64url format, `alg`, `kid`, `ver`, `iat`, `sub`, `iss`, `exp`
and `nbf` are checked on the unverified token before the callback is invoked,
so tokens that are malformed, expired or for another issuer never cause a key
lookup. Claims are checked again after the signature is verified. `aud` is
only checked after the key lookup, so a forged token with a well-formed header
and claims can still reach the callback: rate-limit and cache lookups.

## Security Features

- Tokens over 4096 bytes are rejected before parsing; only canonical base64url is accepted
- Exactly one algorithm per version (v1 RS256, v2 ES256), taken from the signed `ver` claim and never from the `alg` header; tokens with a `crit` header are rejected, as no extensions are supported
- `exp` and `nbf` get no clock skew tolerance; `iat` may be up to 30s in the future
- The callback runs synchronously and must honor its context for `Timeout` and cancellation to take effect; concurrent lookups are bounded by your own concurrency (backpressure), with no background goroutines
- Error messages are fixed and never include token contents
