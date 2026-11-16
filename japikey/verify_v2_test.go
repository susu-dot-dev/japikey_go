package japikey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	stderrors "errors"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/susu-dot-dev/japikey_go/errors"
	"github.com/susu-dot-dev/japikey_go/internal/jwks"
)

const v2BaseIssuer = "https://example.com/"

// signWith signs claims with the given method and private key, with kid header.
func signWith(t *testing.T, method jwt.SigningMethod, key crypto.Signer, claims jwt.MapClaims, kid string) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func newECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return k
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return k
}

func claimsWithVer(ver string) jwt.MapClaims {
	c := baseTestClaims(hardeningKeyID)
	c["ver"] = ver
	return c
}

func keyReturning(k crypto.PublicKey, calls *atomic.Int32) JWKCallback {
	return func(context.Context, uuid.UUID) (crypto.PublicKey, error) {
		if calls != nil {
			calls.Add(1)
		}
		return k, nil
	}
}

func TestNewJAPIKey_MintsVersion2ES256(t *testing.T) {
	k, err := NewJAPIKey(Config{
		Subject:   "user",
		Issuer:    "https://example.com",
		Audience:  "aud",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("NewJAPIKey: %v", err)
	}

	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	tok, _, err := parser.ParseUnverified(k.JWT, claims)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tok.Header["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256", tok.Header["alg"])
	}
	if claims["ver"] != "japikey-v2" {
		t.Errorf("ver = %v, want japikey-v2", claims["ver"])
	}
	pub, ok := k.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("PublicKey = %T, want P-256 *ecdsa.PublicKey", k.PublicKey)
	}

	// The JWKS served for it carries ver and alg
	set, err := k.ToJWKS()
	if err != nil {
		t.Fatalf("ToJWKS: %v", err)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Keys) != 1 {
		t.Fatalf("bad JWKS %s: %v", raw, err)
	}
	jwk := doc.Keys[0]
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["alg"] != "ES256" || jwk["ver"] != float64(2) {
		t.Errorf("unexpected JWK: %v", jwk)
	}
	if _, ok := jwk["d"]; ok {
		t.Error("JWK exposes private scalar d")
	}
}

func TestVerify_V2RoundTripThroughJWKS(t *testing.T) {
	k, err := NewJAPIKey(Config{
		Subject:   "user",
		Issuer:    "https://example.com",
		Audience:  "aud",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("NewJAPIKey: %v", err)
	}
	set, err := k.ToJWKS()
	if err != nil {
		t.Fatalf("ToJWKS: %v", err)
	}
	// Serialize and parse again, as a stored/served JWKS would be
	raw, _ := json.Marshal(set)
	var parsed jwks.JWKS
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	keyFunc := func(_ context.Context, id uuid.UUID) (crypto.PublicKey, error) {
		return parsed.GetPublicKey(id)
	}
	res, err := Verify(context.Background(), k.JWT, VerifyConfig{BaseIssuerURL: "https://example.com", Audience: "aud"}, keyFunc)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.KeyID != k.KeyID {
		t.Errorf("KeyID = %v, want %v", res.KeyID, k.KeyID)
	}
}

// Version 1 keys, minted by earlier releases with RS256, must keep verifying.
func TestVerify_V1RS256StillAccepted(t *testing.T) {
	priv := newRSAKey(t)
	tok := signWith(t, jwt.SigningMethodRS256, priv, claimsWithVer("japikey-v1"), hardeningKeyID)
	if _, err := Verify(context.Background(), tok, VerifyConfig{BaseIssuerURL: v2BaseIssuer}, keyReturning(&priv.PublicKey, nil)); err != nil {
		t.Fatalf("v1 token rejected: %v", err)
	}
}

func TestVerify_V2ES256Accepted(t *testing.T) {
	priv := newECKey(t, elliptic.P256())
	tok := signWith(t, jwt.SigningMethodES256, priv, claimsWithVer("japikey-v2"), hardeningKeyID)
	if _, err := Verify(context.Background(), tok, VerifyConfig{BaseIssuerURL: v2BaseIssuer}, keyReturning(&priv.PublicKey, nil)); err != nil {
		t.Fatalf("v2 token rejected: %v", err)
	}
}

// The version claim picks the algorithm. A token whose alg header disagrees with
// its version must be rejected, and before any key lookup.
func TestVerify_AlgMustMatchVersion(t *testing.T) {
	rsaKey := newRSAKey(t)
	p256 := newECKey(t, elliptic.P256())
	p384 := newECKey(t, elliptic.P384())

	tests := []struct {
		name   string
		ver    string
		method jwt.SigningMethod
		key    crypto.Signer
		pub    crypto.PublicKey
	}{
		{"v1 signed with ES256", "japikey-v1", jwt.SigningMethodES256, p256, &p256.PublicKey},
		{"v2 signed with RS256", "japikey-v2", jwt.SigningMethodRS256, rsaKey, &rsaKey.PublicKey},
		{"v2 signed with PS256", "japikey-v2", jwt.SigningMethodPS256, rsaKey, &rsaKey.PublicKey},
		{"v1 signed with RS512", "japikey-v1", jwt.SigningMethodRS512, rsaKey, &rsaKey.PublicKey},
		{"v2 signed with ES384", "japikey-v2", jwt.SigningMethodES384, p384, &p384.PublicKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := signWith(t, tt.method, tt.key, claimsWithVer(tt.ver), hardeningKeyID)
			var calls atomic.Int32
			_, err := Verify(context.Background(), tok, VerifyConfig{BaseIssuerURL: v2BaseIssuer}, keyReturning(tt.pub, &calls))
			var unauthorized *errors.UnauthorizedError
			if !stderrors.As(err, &unauthorized) {
				t.Fatalf("expected UnauthorizedError, got %T: %v", err, err)
			}
			if calls.Load() != 0 {
				t.Error("key callback invoked for a token with the wrong algorithm")
			}
		})
	}
}

// A callback that returns the wrong key family for the version must be refused,
// even though the signature algorithm matches the version.
func TestVerify_KeyTypeMustMatchVersion(t *testing.T) {
	rsaKey := newRSAKey(t)
	ecKey := newECKey(t, elliptic.P256())

	t.Run("v2 token, RSA key returned", func(t *testing.T) {
		tok := signWith(t, jwt.SigningMethodES256, ecKey, claimsWithVer("japikey-v2"), hardeningKeyID)
		_, err := Verify(context.Background(), tok, VerifyConfig{BaseIssuerURL: v2BaseIssuer}, keyReturning(&rsaKey.PublicKey, nil))
		if !isUnauthorizedBecause[*errors.ValidationError](err) {
			t.Errorf("expected UnauthorizedError(ValidationError), got %T: %v", err, err)
		}
	})
	t.Run("v1 token, EC key returned", func(t *testing.T) {
		tok := signWith(t, jwt.SigningMethodRS256, rsaKey, claimsWithVer("japikey-v1"), hardeningKeyID)
		_, err := Verify(context.Background(), tok, VerifyConfig{BaseIssuerURL: v2BaseIssuer}, keyReturning(&ecKey.PublicKey, nil))
		if !isUnauthorizedBecause[*errors.ValidationError](err) {
			t.Errorf("expected UnauthorizedError(ValidationError), got %T: %v", err, err)
		}
	})
}

func TestVerify_V2RejectsWrongCurveKey(t *testing.T) {
	signer := newECKey(t, elliptic.P256())
	other := newECKey(t, elliptic.P384())
	tok := signWith(t, jwt.SigningMethodES256, signer, claimsWithVer("japikey-v2"), hardeningKeyID)
	_, err := Verify(context.Background(), tok, VerifyConfig{BaseIssuerURL: v2BaseIssuer}, keyReturning(&other.PublicKey, nil))
	if !isUnauthorizedBecause[*errors.ValidationError](err) {
		t.Errorf("expected UnauthorizedError(ValidationError), got %T: %v", err, err)
	}
}

func TestVerify_V2WrongSignature(t *testing.T) {
	signer := newECKey(t, elliptic.P256())
	other := newECKey(t, elliptic.P256())
	tok := signWith(t, jwt.SigningMethodES256, signer, claimsWithVer("japikey-v2"), hardeningKeyID)
	_, err := Verify(context.Background(), tok, VerifyConfig{BaseIssuerURL: v2BaseIssuer}, keyReturning(&other.PublicKey, nil))
	var unauthorized *errors.UnauthorizedError
	if !stderrors.As(err, &unauthorized) {
		t.Fatalf("expected UnauthorizedError, got %T: %v", err, err)
	}
}

func TestVerify_TypedNilKeyIsNotFound(t *testing.T) {
	signer := newECKey(t, elliptic.P256())
	tok := signWith(t, jwt.SigningMethodES256, signer, claimsWithVer("japikey-v2"), hardeningKeyID)
	for name, key := range map[string]crypto.PublicKey{
		"nil":            nil,
		"nil ecdsa":      (*ecdsa.PublicKey)(nil),
		"nil rsa":        (*rsa.PublicKey)(nil),
		"unsupported":    "not a key",
		"ecdsa no point": &ecdsa.PublicKey{Curve: elliptic.P256()},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(context.Background(), tok, VerifyConfig{BaseIssuerURL: v2BaseIssuer}, keyReturning(key, nil))
			var unauthorized *errors.UnauthorizedError
			if !stderrors.As(err, &unauthorized) {
				t.Fatalf("expected UnauthorizedError, got %T: %v", err, err)
			}
		})
	}
}

func TestShouldVerify_AcceptsV1AndV2(t *testing.T) {
	rsaKey := newRSAKey(t)
	ecKey := newECKey(t, elliptic.P256())
	v1 := signWith(t, jwt.SigningMethodRS256, rsaKey, claimsWithVer("japikey-v1"), hardeningKeyID)
	v2 := signWith(t, jwt.SigningMethodES256, ecKey, claimsWithVer("japikey-v2"), hardeningKeyID)
	v0 := signWith(t, jwt.SigningMethodRS256, rsaKey, claimsWithVer("japikey-v0"), hardeningKeyID)
	if !ShouldVerify(v1, "https://example.com") {
		t.Error("ShouldVerify rejected a v1 token")
	}
	if !ShouldVerify(v2, "https://example.com") {
		t.Error("ShouldVerify rejected a v2 token")
	}
	if ShouldVerify(v0, "https://example.com") {
		t.Error("ShouldVerify accepted a v0 token")
	}
}
