package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"uuid"

	"github.com/susu-dot-dev/japikey/errors"
)

func newP256(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return &k.PublicKey
}

func ecJWKSJSON(t *testing.T, kid uuid.UUID, mutate func(map[string]any)) []byte {
	t.Helper()
	set, err := NewJWKS(newP256(t), kid)
	if err != nil {
		t.Fatalf("NewJWKS: %v", err)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if mutate == nil {
		return raw
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	mutate(doc.Keys[0])
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func TestEC_MarshalShape(t *testing.T) {
	pub := newP256(t)
	kid := uuid.New()
	set, err := NewJWKS(pub, kid)
	if err != nil {
		t.Fatalf("NewJWKS: %v", err)
	}
	raw, _ := json.Marshal(set)
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	point, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"kty": "EC", "kid": kid.String(), "crv": "P-256", "alg": "ES256", "ver": float64(2),
		"x": base64.RawURLEncoding.EncodeToString(point[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(point[33:]),
	}
	got := doc.Keys[0]
	if len(got) != len(want) {
		t.Errorf("JWK has %d members, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("member %q = %v, want %v", k, got[k], v)
		}
	}
}

// RSA (version 1) JWKs have neither alg nor ver, exactly as before.
func TestRSA_MarshalShapeUnchanged(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewJWKS(&k.PublicKey, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(set)
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys[0]) != 4 {
		t.Errorf("RSA JWK must have exactly kty, kid, n, e: %v", doc.Keys[0])
	}
}

func TestEC_RoundTrip(t *testing.T) {
	pub := newP256(t)
	kid := uuid.New()
	set, err := NewJWKS(pub, kid)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(set)
	var parsed JWKS
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, err := parsed.GetPublicKey(kid)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(got) {
		t.Error("public key changed in round trip")
	}
	again, _ := json.Marshal(&parsed)
	if string(again) != string(raw) {
		t.Errorf("re-marshal differs:\n%s\n%s", raw, again)
	}
}

// Coordinates are fixed width: a coordinate with leading zero bytes must keep them.
func TestEC_CoordinatesKeepLeadingZeros(t *testing.T) {
	for i := 0; i < 2000; i++ {
		pub := newP256(t)
		if point, _ := pub.Bytes(); point[1] != 0 { // want a zero leading byte in x
			continue
		}
		set, err := NewJWKS(pub, uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		if got := len(set.jwk.x); got != 43 {
			t.Fatalf("x encoded to %d chars, want 43 (32 bytes)", got)
		}
		raw, _ := json.Marshal(set)
		var parsed JWKS
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatalf("round trip failed: %v", err)
		}
		return
	}
	t.Skip("did not generate a key with a short x coordinate")
}

func TestEC_UnmarshalRejects(t *testing.T) {
	kid := uuid.New()
	tests := map[string]func(map[string]any){
		"missing alg":      func(m map[string]any) { delete(m, "alg") },
		"missing ver":      func(m map[string]any) { delete(m, "ver") },
		"missing crv":      func(m map[string]any) { delete(m, "crv") },
		"wrong alg":        func(m map[string]any) { m["alg"] = "ES384" },
		"alg RS256":        func(m map[string]any) { m["alg"] = "RS256" },
		"alg wrong type":   func(m map[string]any) { m["alg"] = 256 },
		"wrong ver":        func(m map[string]any) { m["ver"] = float64(1) },
		"ver 3":            func(m map[string]any) { m["ver"] = float64(3) },
		"ver as string":    func(m map[string]any) { m["ver"] = "2" },
		"ver fractional":   func(m map[string]any) { m["ver"] = 2.5 },
		"wrong crv":        func(m map[string]any) { m["crv"] = "P-384" },
		"extra member":     func(m map[string]any) { m["use"] = "sig" },
		"private scalar d": func(m map[string]any) { m["d"] = m["x"] },
		"rsa member n":     func(m map[string]any) { m["n"] = m["x"] },
		"x too short":      func(m map[string]any) { m["x"] = "AQ" },
		"x too long":       func(m map[string]any) { m["x"] = strings.Repeat("A", 44) },
		"x not base64":     func(m map[string]any) { m["x"] = strings.Repeat("!", 43) },
		"y empty":          func(m map[string]any) { m["y"] = "" },
		"x padded":         func(m map[string]any) { m["x"] = m["x"].(string) + "=" },
		"point off curve":  func(m map[string]any) { m["y"] = m["x"] },
		"point at infinity": func(m map[string]any) {
			z := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			m["x"], m["y"] = z, z
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var j JWKS
			err := json.Unmarshal(ecJWKSJSON(t, kid, mutate), &j)
			if err == nil {
				t.Fatal("expected an error")
			}
			if _, ok := err.(*errors.ValidationError); !ok {
				t.Errorf("expected *ValidationError, got %T: %v", err, err)
			}
		})
	}
}

// An RSA JWK must not smuggle in alg or ver (or EC members).
func TestRSA_UnmarshalRejectsECMembers(t *testing.T) {
	kid := uuid.New()
	for _, extra := range []string{`,"alg":"RS256"`, `,"ver":1`, `,"crv":"P-256"`, `,"x":"AA"`} {
		doc := `{"keys":[{"kty":"RSA","kid":"` + kid.String() + `","n":"` + validTestModulusB64 + `","e":"AQAB"` + extra + `}]}`
		var j JWKS
		if err := json.Unmarshal([]byte(doc), &j); err == nil {
			t.Errorf("accepted RSA JWK with %s", extra)
		}
	}
}

func TestValidatePublicKey_EC(t *testing.T) {
	if err := ValidatePublicKey(newP256(t)); err != nil {
		t.Errorf("valid P-256 key rejected: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	bad := map[string]any{
		"P-384":            &p384.PublicKey,
		"nil":              (*ecdsa.PublicKey)(nil),
		"nil coordinates":  &ecdsa.PublicKey{Curve: elliptic.P256()},
		"nil curve":        &ecdsa.PublicKey{X: big.NewInt(1), Y: big.NewInt(1)},                         //nolint:staticcheck // deliberately malformed
		"not on curve":     &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, //nolint:staticcheck // deliberately malformed
		"unsupported type": "key",
	}
	for name, k := range bad {
		if err := ValidatePublicKey(k); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}
