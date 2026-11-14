// Package integration exercises the complete japikey flow end to end, using a
// third-party JWKS implementation (lestrrat-go/jwx) as an independent oracle:
//
//	mint (NewJAPIKey) -> store public key -> serve JWKS over HTTP
//	  -> third-party library fetches JWKS and verifies the token
//	  -> japikey.Verify validates the same token via the same endpoint
//
// It lives in its own module so the third-party dependency does not leak into
// the library's go.mod.
package integration

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/jwx-go/jwkfetch/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/susu-dot-dev/japikey"
	japikeyerrors "github.com/susu-dot-dev/japikey/errors"
)

// memoryDB is a minimal DatabaseDriver holding only public keys, as a real
// deployment would: the private key is gone once NewJAPIKey returns.
type memoryDB struct {
	mu   sync.Mutex
	keys map[string]*japikey.KeyLookupResult
}

func newMemoryDB() *memoryDB {
	return &memoryDB{keys: map[string]*japikey.KeyLookupResult{}}
}

func (m *memoryDB) store(k *japikey.JAPIKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[k.KeyID.String()] = &japikey.KeyLookupResult{PublicKey: k.PublicKey}
}

func (m *memoryDB) revoke(id uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.keys[id.String()]; ok {
		r.Revoked = true
	}
}

func (m *memoryDB) GetKey(_ context.Context, kid string) (*japikey.KeyLookupResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.keys[kid]
	if !ok {
		return nil, japikeyerrors.NewKeyNotFoundError("key not found")
	}
	cp := *r
	return &cp, nil
}

// env is a running JWKS server plus the base issuer URL that points at it.
type env struct {
	db      *memoryDB
	server  *httptest.Server
	baseURL string // what an operator would configure as the issuer base
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := newMemoryDB()
	handler, err := japikey.CreateJWKSRouter(japikey.JWKSRouterConfig{DB: db, MaxAgeSeconds: 0})
	if err != nil {
		t.Fatalf("CreateJWKSRouter: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &env{db: db, server: srv, baseURL: srv.URL}
}

// mint creates a key through the public API exactly as an application would,
// for an issuer base that points at the JWKS server, and registers its public
// half. It deliberately does not know the key ID in advance, because the
// library generates it.
func (e *env) mint(t *testing.T, mutate func(*japikey.Config)) *japikey.JAPIKey {
	t.Helper()
	cfg := japikey.Config{
		Subject:   "user-123",
		Issuer:    e.baseURL,
		Audience:  "myapp-users",
		ExpiresAt: time.Now().Add(time.Hour),
		// httptest serves plain http on loopback
		AllowInsecureHTTP: true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	k, err := japikey.NewJAPIKey(cfg)
	if err != nil {
		t.Fatalf("NewJAPIKey: %v", err)
	}
	e.db.store(k)
	return k
}

// verifyConfig returns the VerifyConfig for base; httptest serves plain http.
func (e *env) verifyConfig(base string) japikey.VerifyConfig {
	return japikey.VerifyConfig{BaseIssuerURL: base, AllowInsecureHTTP: true}
}

// fetch retrieves a JWKS over HTTP with the third-party client.
func fetch(ctx context.Context, url string) (jwk.Set, error) {
	return jwkfetch.NewClient().Fetch(ctx, url)
}

// jwksURL is where a standards-based client discovers the keys for a token:
// RFC 8414 / OIDC style "<iss>/.well-known/jwks.json".
func jwksURL(iss string) string { return strings.TrimSuffix(iss, "/") + "/.well-known/jwks.json" }

// japikeyCallback fetches the JWKS over HTTP and decodes it with the third-party
// library, so japikey.Verify is exercised against the real served document.
func (e *env) japikeyCallback(t *testing.T) japikey.JWKCallback {
	return func(ctx context.Context, kid uuid.UUID) (*rsa.PublicKey, error) {
		set, err := fetch(ctx, fmt.Sprintf("%s/%s/.well-known/jwks.json", e.baseURL, kid))
		if err != nil {
			return nil, japikeyerrors.NewKeyNotFoundError("jwks fetch failed")
		}
		key, ok := set.LookupKeyID(kid.String())
		if !ok {
			return nil, japikeyerrors.NewKeyNotFoundError("kid not in jwks")
		}
		pub, err := jwk.Export[*rsa.PublicKey](key)
		if err != nil {
			return nil, japikeyerrors.NewKeyNotFoundError("not an rsa key")
		}
		return pub, nil
	}
}

func tokenIssuer(t *testing.T, tok string) string {
	t.Helper()
	parsed, err := jwt.ParseInsecure([]byte(tok))
	if err != nil {
		t.Fatalf("ParseInsecure: %v", err)
	}
	iss, _ := parsed.Issuer()
	return iss
}

// TestMintedTokenVerifiesWithJapikey is the core contract: a token produced by
// NewJAPIKey for an issuer base must be accepted by Verify for that same base.
func TestMintedTokenVerifiesWithJapikey(t *testing.T) {
	e := newEnv(t)
	k := e.mint(t, nil)

	res, err := japikey.Verify(context.Background(), k.JWT,
		japikey.VerifyConfig{BaseIssuerURL: e.baseURL, AllowInsecureHTTP: true, Timeout: 5 * time.Second},
		e.japikeyCallback(t))
	if err != nil {
		t.Fatalf("Verify rejected a token minted by NewJAPIKey: %v", err)
	}
	if res.KeyID != k.KeyID {
		t.Errorf("KeyID = %s, want %s", res.KeyID, k.KeyID)
	}
	if res.Claims["sub"] != "user-123" {
		t.Errorf("sub = %v", res.Claims["sub"])
	}
}

// TestMintedTokenVerifiesWithThirdPartyJWKSFlow verifies the minted token using
// only standards: read iss from the token, derive the JWKS URL from it, fetch
// it with a third-party JWKS client and validate signature + claims.
func TestMintedTokenVerifiesWithThirdPartyJWKSFlow(t *testing.T) {
	e := newEnv(t)
	k := e.mint(t, nil)

	iss := tokenIssuer(t, k.JWT)
	set, err := fetch(context.Background(), jwksURL(iss))
	if err != nil {
		t.Fatalf("a standards-based client could not fetch the JWKS derived from iss=%q: %v", iss, err)
	}

	tok, err := jwt.Parse([]byte(k.JWT),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)), // alg is optional in a JWK (RFC 7517)
		jwt.WithIssuer(iss),
		jwt.WithAudience("myapp-users"),
		jwt.WithValidate(true),
	)
	if err != nil {
		t.Fatalf("third-party library rejected the minted token: %v", err)
	}
	if sub, _ := tok.Subject(); sub != "user-123" {
		t.Errorf("sub = %q", sub)
	}
	if _, ok := set.LookupKeyID(k.KeyID.String()); !ok {
		t.Errorf("kid %s missing from served JWKS", k.KeyID)
	}
}

// TestIssuerIsDiscoverable asserts the iss claim is the JWKS location contract.
func TestIssuerIsDiscoverable(t *testing.T) {
	e := newEnv(t)
	k := e.mint(t, nil)

	want := e.baseURL + "/" + k.KeyID.String()
	if got := tokenIssuer(t, k.JWT); got != want {
		t.Errorf("iss = %q, want %q", got, want)
	}
}

// TestBaseIssuerTrailingSlash: operators write the base with or without "/".
func TestBaseIssuerTrailingSlash(t *testing.T) {
	e := newEnv(t)
	for _, base := range []string{e.baseURL, e.baseURL + "/"} {
		t.Run(fmt.Sprintf("base=%q", base[len(e.baseURL):]), func(t *testing.T) {
			k := e.mint(t, func(c *japikey.Config) { c.Issuer = base })
			if _, err := japikey.Verify(context.Background(), k.JWT,
				e.verifyConfig(base), e.japikeyCallback(t)); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			iss := tokenIssuer(t, k.JWT)
			if strings.Contains(strings.TrimPrefix(iss, "http://"), "//") {
				t.Errorf("iss %q contains a double slash", iss)
			}
		})
	}
}

// TestCustomClaimsSurviveRoundTrip and mandatory claims cannot be overridden.
func TestCustomClaimsSurviveRoundTrip(t *testing.T) {
	e := newEnv(t)
	k := e.mint(t, func(c *japikey.Config) {
		c.Claims = map[string]any{
			"role": "admin",
			"iss":  "https://evil.example/override",
			"ver":  "japikey-v999",
		}
	})
	res, err := japikey.Verify(context.Background(), k.JWT,
		e.verifyConfig(e.baseURL), e.japikeyCallback(t))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Claims["role"] != "admin" {
		t.Errorf("custom claim lost: %v", res.Claims["role"])
	}
	if res.Claims["ver"] != "japikey-v1" {
		t.Errorf("ver overridden: %v", res.Claims["ver"])
	}
}

// TestShouldVerifyAcceptsMintedToken: the cheap pre-check used to route tokens
// to japikey must agree with what NewJAPIKey produces.
func TestShouldVerifyAcceptsMintedToken(t *testing.T) {
	e := newEnv(t)
	k := e.mint(t, nil)
	if !japikey.ShouldVerify(k.JWT, e.baseURL) {
		t.Error("ShouldVerify rejected a token minted by NewJAPIKey")
	}
	if japikey.ShouldVerify(k.JWT, "https://other.example") {
		t.Error("ShouldVerify accepted a token for a different issuer base")
	}
}

// TestRevokedKeyIsRejected: once the server stops serving the key, tokens fail
// in both the third-party flow and japikey.Verify.
func TestRevokedKeyIsRejected(t *testing.T) {
	e := newEnv(t)
	k := e.mint(t, nil)
	e.db.revoke(k.KeyID)

	if _, err := fetch(context.Background(), jwksURL(tokenIssuer(t, k.JWT))); err == nil {
		t.Error("JWKS for a revoked key was still served")
	}
	_, err := japikey.Verify(context.Background(), k.JWT,
		e.verifyConfig(e.baseURL), e.japikeyCallback(t))
	if err == nil {
		t.Fatal("Verify accepted a revoked key")
	}
	// A revoked key must look like any other bad token to the caller
	if _, ok := err.(*japikeyerrors.UnauthorizedError); !ok || err.Error() != japikeyerrors.UnauthorizedMessage {
		t.Errorf("err = %T %q, want the fixed *UnauthorizedError", err, err)
	}
}

// TestKeysAreIsolated: a token must only verify against its own key, even when
// another valid key is served by the same endpoint.
func TestKeysAreIsolated(t *testing.T) {
	e := newEnv(t)
	a := e.mint(t, nil)
	b := e.mint(t, nil)
	if a.KeyID == b.KeyID {
		t.Fatal("two mints produced the same key ID")
	}

	// Serve b's key under a's kid (a compromised/misconfigured store).
	cb := func(ctx context.Context, _ uuid.UUID) (*rsa.PublicKey, error) { return b.PublicKey, nil }
	if _, err := japikey.Verify(context.Background(), a.JWT,
		e.verifyConfig(e.baseURL), cb); err == nil {
		t.Error("token for key A verified against key B's public key")
	}
}

// TestExpiredTokenRejected mints the shortest-lived key the library allows and
// waits for it to lapse. It runs in parallel so the wait overlaps other tests.
func TestExpiredTokenRejected(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	life := 6500 * time.Millisecond // above the library's minimum key lifetime
	k := e.mint(t, func(c *japikey.Config) { c.ExpiresAt = time.Now().Add(life) })
	time.Sleep(life + time.Second)

	_, err := japikey.Verify(context.Background(), k.JWT,
		e.verifyConfig(e.baseURL), e.japikeyCallback(t))
	var expired *japikeyerrors.TokenExpiredError
	if _, ok := err.(*japikeyerrors.UnauthorizedError); !ok || !errors.As(err, &expired) {
		t.Fatalf("err = %T %v, want *UnauthorizedError caused by *TokenExpiredError", err, err)
	}
}

// TestTamperedTokenRejected flips a payload byte.
func TestTamperedTokenRejected(t *testing.T) {
	e := newEnv(t)
	k := e.mint(t, nil)
	parts := strings.Split(k.JWT, ".")
	payload := []byte(parts[1])
	if payload[10] == 'A' {
		payload[10] = 'B'
	} else {
		payload[10] = 'A'
	}
	tampered := parts[0] + "." + string(payload) + "." + parts[2]
	if _, err := japikey.Verify(context.Background(), tampered,
		e.verifyConfig(e.baseURL), e.japikeyCallback(t)); err == nil {
		t.Error("Verify accepted a tampered token")
	}
}

// TestMissingKeyIs404 pins the HTTP contract third-party clients rely on.
func TestMissingKeyIs404(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(fmt.Sprintf("%s/%s/.well-known/jwks.json", e.baseURL, uuid.New()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("closing response body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}
