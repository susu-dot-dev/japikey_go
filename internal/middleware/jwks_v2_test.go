package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"uuid"
)

func serveKey(t *testing.T, result *KeyLookupResult) (*httptest.ResponseRecorder, uuid.UUID) {
	t.Helper()
	handler, err := CreateJWKSRouter(JWKSRouterConfig{DB: &MockDatabaseDriver{
		GetKeyFunc: func(context.Context, string) (*KeyLookupResult, error) { return result, nil },
	}})
	if err != nil {
		t.Fatal(err)
	}
	kid := uuid.New()
	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr, kid
}

func decodeKey(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil || len(doc.Keys) != 1 {
		t.Fatalf("bad JWKS %q: %v", rr.Body.String(), err)
	}
	return doc.Keys[0]
}

// A stored version 2 key is served as an EC JWK carrying alg and ver.
func TestJWKSEndpoint_V2Key_ServesECWithAlgAndVer(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rr, kid := serveKey(t, &KeyLookupResult{PublicKey: &priv.PublicKey})
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	key := decodeKey(t, rr)
	if key["kty"] != "EC" || key["crv"] != "P-256" || key["alg"] != "ES256" || key["ver"] != float64(2) || key["kid"] != kid.String() {
		t.Errorf("unexpected JWK: %v", key)
	}
	if _, ok := key["d"]; ok {
		t.Error("JWK exposes the private scalar")
	}
}

// Existing version 1 RSA keys keep being served exactly as before: no alg, no ver.
func TestJWKSEndpoint_V1RSAKey_ServedUnchanged(t *testing.T) {
	rr, _ := serveKey(t, &KeyLookupResult{PublicKey: &rsa.PublicKey{N: validTestModulus(t), E: 65537}})
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	key := decodeKey(t, rr)
	if len(key) != 4 || key["kty"] != "RSA" {
		t.Errorf("v1 JWK must be exactly kty, kid, n, e: %v", key)
	}
}

func TestJWKSEndpoint_TypedNilKey_IsNotFound(t *testing.T) {
	for name, key := range map[string]*KeyLookupResult{
		"nil ecdsa": {PublicKey: (*ecdsa.PublicKey)(nil)},
		"nil rsa":   {PublicKey: (*rsa.PublicKey)(nil)},
		"nil":       {},
	} {
		t.Run(name, func(t *testing.T) {
			if rr, _ := serveKey(t, key); rr.Code != http.StatusNotFound {
				t.Errorf("status %d, want 404", rr.Code)
			}
		})
	}
}
