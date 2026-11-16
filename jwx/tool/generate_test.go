package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

const testKID = "123e4567-e89b-12d3-a456-426614174000"

// runGenerate runs the generate command with the given stdin and flags and
// returns what it printed.
func runGenerate(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	inR, inW, _ := os.Pipe()
	_, _ = inW.WriteString(stdin)
	_ = inW.Close()
	outR, outW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	app := &cli.Command{
		Name: "jwx",
		Commands: []*cli.Command{{
			Name:   "generate",
			Flags:  []cli.Flag{&cli.StringFlag{Name: "alg", Value: "auto"}},
			Action: generateAction,
		}},
	}
	err := app.Run(context.Background(), append([]string{"jwx", "generate"}, args...))
	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	return strings.TrimSpace(buf.String()), err
}

func decodeJWK(t *testing.T, out string) map[string]any {
	t.Helper()
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Keys) != 1 {
		t.Fatalf("bad JWKS %q: %v", out, err)
	}
	return doc.Keys[0]
}

func TestGenerateES256(t *testing.T) {
	pubB64, err := GenerateExampleECKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{testKID}, {"--alg", "ES256", testKID}, {"--alg", "auto", testKID}} {
		out, err := runGenerate(t, pubB64+"\n", args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		jwk := decodeJWK(t, out)
		if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["alg"] != "ES256" || jwk["ver"] != float64(2) || jwk["kid"] != testKID {
			t.Errorf("%v: unexpected JWK %v", args, jwk)
		}
		if len(jwk) != 7 {
			t.Errorf("%v: JWK must have exactly kty, kid, crv, x, y, alg, ver: %v", args, jwk)
		}
		for _, m := range []string{"x", "y"} {
			b, err := base64.RawURLEncoding.Strict().DecodeString(jwk[m].(string))
			if err != nil || len(b) != 32 {
				t.Errorf("%s is not a 32-byte base64url value: %v", m, err)
			}
		}
	}
}

// parse then generate must give back the same key.
func TestGenerateES256RoundTripsThroughParse(t *testing.T) {
	pubB64, _ := GenerateExampleECKeys()
	out, err := runGenerate(t, pubB64, testKID)
	if err != nil {
		t.Fatal(err)
	}
	jwk := decodeJWK(t, out)
	got, err := stdoutOf(func() error { return parseEC(jwk) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) != pubB64 {
		t.Errorf("round trip changed the key:\n%s\n%s", pubB64, got)
	}
}

func TestGenerateRS256Unchanged(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	modB64 := base64.StdEncoding.EncodeToString(k.N.Bytes())
	for _, args := range [][]string{{testKID}, {"--alg", "RS256", testKID}} {
		out, err := runGenerate(t, modB64, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		jwk := decodeJWK(t, out)
		if jwk["kty"] != "RSA" || jwk["e"] != "AQAB" || len(jwk) != 4 {
			t.Errorf("%v: RSA JWK must be exactly kty, kid, n, e: %v", args, jwk)
		}
	}
}

func TestGenerateRejects(t *testing.T) {
	ec, _ := ecdh.P256().GenerateKey(rand.Reader)
	point := ec.PublicKey().Bytes()
	offCurve := append([]byte{}, point...)
	offCurve[64] ^= 0x01
	short := base64.StdEncoding.EncodeToString(point[:64])
	b64 := base64.StdEncoding.EncodeToString

	tests := map[string]struct {
		stdin string
		args  []string
	}{
		"point off curve":         {b64(offCurve), []string{testKID}},
		"ES256 forced, bad point": {b64(offCurve), []string{"--alg", "ES256", testKID}},
		"ES256 forced, wrong len": {short, []string{"--alg", "ES256", testKID}},
		"ES256 forced, RSA-sized": {b64(make([]byte, 256)), []string{"--alg", "ES256", testKID}},
		"compressed point":        {b64(append([]byte{0x02}, point[1:33]...)), []string{"--alg", "ES256", testKID}},
		"unknown alg":             {b64(point), []string{"--alg", "ES384", testKID}},
		"invalid kid":             {b64(point), []string{"not-a-uuid"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if out, err := runGenerate(t, tt.stdin, tt.args...); err == nil {
				t.Fatalf("expected an error, got output %q", out)
			}
		})
	}
}
