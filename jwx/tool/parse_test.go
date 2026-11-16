package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
)

func TestReadLimited(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		got, err := readLimited(strings.NewReader("hello"), 5)
		if err != nil || got != "hello" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("one byte over limit is rejected, not truncated", func(t *testing.T) {
		_, err := readLimited(strings.NewReader("hello!"), 5)
		if err == nil {
			t.Fatal("expected error for oversized input")
		}
	})

	t.Run("endless input terminates", func(t *testing.T) {
		_, err := readLimited(endlessReader{}, maxInputSize)
		if err == nil {
			t.Fatal("expected error for endless input")
		}
	})

	t.Run("multi-line input is preserved", func(t *testing.T) {
		got, err := readLimited(strings.NewReader("a\nb\n"), 16)
		if err != nil || got != "a\nb\n" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
}

type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestParseEC(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(n *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32)))
	}
	jwk := func(mutate func(map[string]interface{})) map[string]interface{} {
		m := map[string]interface{}{"kty": "EC", "crv": "P-256", "x": enc(priv.X), "y": enc(priv.Y)}
		if mutate != nil {
			mutate(m)
		}
		return m
	}

	stdout := stdoutOf

	t.Run("valid point", func(t *testing.T) {
		out, err := stdout(func() error { return parseEC(jwk(nil)) })
		if err != nil {
			t.Fatal(err)
		}
		got, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
		if err != nil || len(got) != 65 || got[0] != 0x04 {
			t.Fatalf("unexpected output %q: %v", out, err)
		}
	})
	for name, mutate := range map[string]func(map[string]interface{}){
		"wrong curve": func(m map[string]interface{}) { m["crv"] = "P-384" },
		"missing x":   func(m map[string]interface{}) { delete(m, "x") },
		"short y":     func(m map[string]interface{}) { m["y"] = "AQ" },
		"off curve":   func(m map[string]interface{}) { m["y"] = m["x"] },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := stdout(func() error { return parseEC(jwk(mutate)) }); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// stdoutOf runs f and returns what it wrote to os.Stdout.
func stdoutOf(f func() error) (string, error) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := f()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out), err
}
