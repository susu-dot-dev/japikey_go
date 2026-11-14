package japikey

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	stderrors "errors"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/susu-dot-dev/japikey/errors"
)

const hardeningKeyID = "123e4567-e89b-12d3-a456-426614174000"

// countingKeyFunc returns pubKey and counts how often it was invoked.
func countingKeyFunc(pubKey *rsa.PublicKey, calls *atomic.Int32) JWKCallback {
	return func(context.Context, uuid.UUID) (*rsa.PublicKey, error) {
		calls.Add(1)
		return pubKey, nil
	}
}

// Tokens that cannot be valid for this issuer must be rejected before the
// key callback runs, so they cause no database or network I/O.
func TestVerifyRejectsBeforeKeyLookup(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c jwt.MapClaims)
		kid    string
	}{
		{"wrong issuer host", func(c jwt.MapClaims) { c["iss"] = "https://evil.example/" + hardeningKeyID }, hardeningKeyID},
		{"issuer for another kid", func(c jwt.MapClaims) { c["iss"] = "https://example.com/" + uuid.New().String() }, hardeningKeyID},
		{"missing issuer", func(c jwt.MapClaims) { delete(c, "iss") }, hardeningKeyID},
		{"wrong version", func(c jwt.MapClaims) { c["ver"] = "japikey-v2" }, hardeningKeyID},
		{"missing version", func(c jwt.MapClaims) { delete(c, "ver") }, hardeningKeyID},
		{"missing iat", func(c jwt.MapClaims) { delete(c, "iat") }, hardeningKeyID},
		{"missing sub", func(c jwt.MapClaims) { delete(c, "sub") }, hardeningKeyID},
		{"random kid, issuer elsewhere", func(c jwt.MapClaims) { c["iss"] = "https://other.example/x" }, uuid.New().String()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := baseTestClaims(hardeningKeyID)
			tt.mutate(claims)
			tokenString, pubKey := signTestToken(t, claims, tt.kid)

			var calls atomic.Int32
			_, err := Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, countingKeyFunc(pubKey, &calls))
			if !isUnauthorizedBecause[*errors.ValidationError](err) {
				t.Errorf("expected UnauthorizedError(ValidationError), got %T: %v", err, err)
			}
			if n := calls.Load(); n != 0 {
				t.Errorf("key callback invoked %d times for a token that fails pre-checks", n)
			}
		})
	}
}

func TestVerifyWrongAlgorithmDoesNotLookUpKey(t *testing.T) {
	claims := baseTestClaims(hardeningKeyID)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = hardeningKeyID
	tokenString, err := token.SignedString([]byte("secret-secret-secret-secret-1234"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	var calls atomic.Int32
	_, err = Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, countingKeyFunc(nil, &calls))
	if !isUnauthorizedBecause[*errors.ValidationError](err) {
		t.Errorf("expected UnauthorizedError, got %T: %v", err, err)
	}
	if calls.Load() != 0 {
		t.Error("key callback invoked for a non-RS256 token")
	}
}

// Every token-related failure must look the same to the caller, so an
// unauthenticated client cannot learn whether a key ID exists or is revoked.
func TestVerifyErrorsAreIndistinguishable(t *testing.T) {
	tokenString, pubKey := signTestToken(t, baseTestClaims(hardeningKeyID), hardeningKeyID)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cfg := VerifyConfig{BaseIssuerURL: "https://example.com/"}

	cases := map[string]JWKCallback{
		"unknown key": func(context.Context, uuid.UUID) (*rsa.PublicKey, error) {
			return nil, errors.NewKeyNotFoundError("no such key " + hardeningKeyID)
		},
		"revoked key (nil, nil)": func(context.Context, uuid.UUID) (*rsa.PublicKey, error) { return nil, nil },
		"wrong key":              mockKeyFunc(&otherKey.PublicKey),
	}
	expired := baseTestClaims(hardeningKeyID)
	expired["exp"] = time.Now().Add(-time.Hour).Unix()
	expiredToken, expiredKey := signTestToken(t, expired, hardeningKeyID)

	var errs []error
	for name, cb := range cases {
		_, err := Verify(context.Background(), tokenString, cfg, cb)
		if _, ok := err.(*errors.UnauthorizedError); !ok {
			t.Fatalf("%s: expected *UnauthorizedError, got %T: %v", name, err, err)
		}
		errs = append(errs, err)
	}
	_, err = Verify(context.Background(), expiredToken, cfg, mockKeyFunc(expiredKey))
	errs = append(errs, err)
	_, err = Verify(context.Background(), "a.b.c", cfg, mockKeyFunc(pubKey))
	errs = append(errs, err)

	for _, e := range errs {
		if e.Error() != errors.UnauthorizedMessage {
			t.Errorf("message = %q, want fixed %q", e.Error(), errors.UnauthorizedMessage)
		}
	}

	// The cause stays available for logging.
	_, err = Verify(context.Background(), tokenString, cfg, cases["unknown key"])
	var nf *errors.KeyNotFoundError
	if !stderrors.As(err, &nf) {
		t.Error("KeyNotFoundError cause should be reachable with errors.As")
	}
	_, err = Verify(context.Background(), expiredToken, cfg, mockKeyFunc(expiredKey))
	var exp *errors.TokenExpiredError
	if !stderrors.As(err, &exp) {
		t.Error("TokenExpiredError cause should be reachable with errors.As")
	}
}

// Keys returned by the callback get the same strength checks as NewJWKS.
func TestVerifyRejectsUnacceptableCallbackKeys(t *testing.T) {
	// A real 1024-bit key: crypto/rsa accepts it, japikey must not.
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey(1024): %v", err)
	}
	claims := baseTestClaims(hardeningKeyID)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = hardeningKeyID
	weakToken, err := token.SignedString(weak)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tokenString, pubKey := signTestToken(t, baseTestClaims(hardeningKeyID), hardeningKeyID)
	huge := new(big.Int).Lsh(big.NewInt(1), 8191)
	huge.Or(huge, big.NewInt(1))

	tests := []struct {
		name  string
		token string
		key   *rsa.PublicKey
	}{
		{"1024-bit key", weakToken, &weak.PublicKey},
		{"8192-bit modulus", tokenString, &rsa.PublicKey{N: huge, E: 65537}},
		{"even exponent", tokenString, &rsa.PublicKey{N: pubKey.N, E: 65536}},
		{"exponent 1", tokenString, &rsa.PublicKey{N: pubKey.N, E: 1}},
		{"even modulus", tokenString, &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(context.Background(), tt.token, VerifyConfig{BaseIssuerURL: "https://example.com/"}, mockKeyFunc(tt.key))
			u, ok := err.(*errors.UnauthorizedError)
			if !ok {
				t.Fatalf("expected *UnauthorizedError, got %T: %v", err, err)
			}
			if u.Cause == nil || u.Cause.Error() != "public key does not meet requirements" {
				t.Errorf("expected key-strength cause, got %v", u.Cause)
			}
		})
	}
}

func TestVerifyRequiresSubject(t *testing.T) {
	tests := []struct {
		name string
		sub  any
	}{
		{"empty string", ""},
		{"number", 42},
		{"null", nil},
		{"array", []string{"user"}},
		{"object", map[string]any{"id": "user"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := baseTestClaims(hardeningKeyID)
			claims["sub"] = tt.sub
			tokenString, pubKey := signTestToken(t, claims, hardeningKeyID)
			_, err := Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: "https://example.com/"}, mockKeyFunc(pubKey))
			if !isUnauthorizedBecause[*errors.ValidationError](err) {
				t.Errorf("expected UnauthorizedError(ValidationError), got %T: %v", err, err)
			}
			if ShouldVerify(tokenString, "https://example.com/") {
				t.Error("ShouldVerify accepted a token without a usable subject")
			}
		})
	}
}

func TestBaseIssuerURLValidation(t *testing.T) {
	tests := []struct {
		name      string
		base      string
		valid     bool
		validHTTP bool // valid when AllowInsecureHTTP is set
	}{
		{"https host", "https://example.com", true, true},
		{"https host trailing slash", "https://example.com/", true, true},
		{"https path", "https://example.com/keys", true, true},
		{"https path trailing slash", "https://example.com/keys/", true, true},
		{"https port", "https://example.com:8443/keys", true, true},
		{"http", "http://127.0.0.1:8080", false, true},
		{"empty", "", false, false},
		{"not a url", "placeholder", false, false},
		{"relative path", "/keys", false, false},
		{"scheme relative", "//example.com/keys", false, false},
		{"other scheme", "ftp://example.com", false, false},
		{"uppercase scheme", "HTTPS://example.com", false, false},
		{"no host", "https:///keys", false, false},
		{"port only", "https://:443", false, false},
		{"opaque", "https:example.com", false, false},
		{"user info", "https://user:pass@example.com", false, false},
		{"user only", "https://user@example.com", false, false},
		{"query", "https://example.com/keys?a=b", false, false},
		{"empty query", "https://example.com/keys?", false, false},
		{"fragment", "https://example.com/keys#frag", false, false},
		{"empty fragment", "https://example.com/keys#", false, false},
		{"double trailing slash", "https://example.com//", false, false},
		{"double trailing slash path", "https://example.com/keys//", false, false},
		{"space in path", "https://example.com/my keys", false, false},
		{"backslash", "https://example.com\\keys", false, false},
		{"control character", "https://example.com/\x00", false, false},
	}
	keyID := uuid.MustParse(hardeningKeyID)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, allowHTTP := range []bool{false, true} {
				want := tt.valid
				if allowHTTP {
					want = tt.validHTTP
				}

				_, err := NewJAPIKey(Config{Subject: "s", Issuer: tt.base, Audience: "a", ExpiresAt: time.Now().Add(time.Hour), AllowInsecureHTTP: allowHTTP})
				if want && err != nil {
					t.Errorf("NewJAPIKey(allowHTTP=%v) rejected %q: %v", allowHTTP, tt.base, err)
				}
				if !want {
					if _, ok := err.(*errors.ValidationError); !ok {
						t.Errorf("NewJAPIKey(allowHTTP=%v) accepted %q (err=%T %v)", allowHTTP, tt.base, err, err)
					}
				}

				// Verify treats a bad base as a server configuration error
				claims := baseTestClaims(hardeningKeyID)
				claims["iss"] = BuildIssuer(tt.base, keyID)
				tokenString, pubKey := signTestToken(t, claims, hardeningKeyID)
				_, err = Verify(context.Background(), tokenString, VerifyConfig{BaseIssuerURL: tt.base, AllowInsecureHTTP: allowHTTP}, mockKeyFunc(pubKey))
				if want && err != nil {
					t.Errorf("Verify(allowHTTP=%v) rejected %q: %v", allowHTTP, tt.base, err)
				}
				if !want {
					if _, ok := err.(*errors.InternalError); !ok {
						t.Errorf("Verify(allowHTTP=%v) with base %q: expected *InternalError, got %T: %v", allowHTTP, tt.base, err, err)
					}
				}
				if err != nil && strings.Contains(err.Error(), tt.base) && tt.base != "" {
					t.Errorf("error echoes the base URL: %q", err.Error())
				}
			}

			// ShouldVerify accepts http and https alike; Verify enforces the scheme
			claims := baseTestClaims(hardeningKeyID)
			claims["iss"] = BuildIssuer(tt.base, keyID)
			tokenString, _ := signTestToken(t, claims, hardeningKeyID)
			if got := ShouldVerify(tokenString, tt.base); got != tt.validHTTP {
				t.Errorf("ShouldVerify(%q) = %v, want %v", tt.base, got, tt.validHTTP)
			}
		})
	}
}
