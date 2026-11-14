package japikey

import (
	"context"
	"strings"
	"testing"
	"time"
)

const base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func TestCheckTokenFormat(t *testing.T) {
	tests := []struct {
		name  string
		token string
		valid bool
	}{
		{"valid three segments", "abc.def.ghi", true},
		{"valid with dash and underscore", "a-b_c.d-e_f.g-h_i", true},
		{"empty", "", false},
		{"one segment", "abc", false},
		{"two segments", "abc.def", false},
		{"four segments", "a.b.c.d", false},
		{"empty first segment", ".b.c", false},
		{"empty middle segment", "a..c", false},
		{"empty last segment", "a.b.", false},
		{"padding character", "abc=.def.ghi", false},
		{"standard base64 plus", "ab+c.def.ghi", false},
		{"standard base64 slash", "ab/c.def.ghi", false},
		{"space", "ab c.def.ghi", false},
		{"newline in segment", "ab\nc.def.ghi", false},
		{"carriage return in segment", "abc.de\rf.ghi", false},
		{"trailing newline", "abc.def.ghi\n", false},
		{"non-ASCII", "abc.d\u00e9f.ghi", false},
		{"NUL byte", "abc.def.g\x00hi", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkTokenFormat(tt.token)
			if tt.valid && err != nil {
				t.Errorf("expected %q to be valid, got: %v", tt.token, err)
			}
			if !tt.valid && err == nil {
				t.Errorf("expected %q to be rejected", tt.token)
			}
		})
	}
}

// The signature segment must have exactly one accepted encoding: neither the
// 16 last-character variants nor embedded line breaks may still verify.
func TestVerifyRejectsSignatureEncodingVariants(t *testing.T) {
	tokenString, pubKey, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}

	config := VerifyConfig{BaseIssuerURL: "https://example.com/", Timeout: 5 * time.Second}
	ctx := context.Background()

	if _, err := Verify(ctx, tokenString, config, mockKeyFunc(pubKey)); err != nil {
		t.Fatalf("Baseline token should verify, got: %v", err)
	}

	t.Run("non-canonical trailing bits", func(t *testing.T) {
		original := tokenString[len(tokenString)-1]
		accepted := 0
		for _, c := range base64urlAlphabet {
			if byte(c) == original {
				continue
			}
			variant := tokenString[:len(tokenString)-1] + string(c)
			if _, err := Verify(ctx, variant, config, mockKeyFunc(pubKey)); err == nil {
				accepted++
			}
		}
		if accepted != 0 {
			t.Errorf("expected 0 last-character variants to verify, %d did", accepted)
		}
	})

	t.Run("embedded line breaks", func(t *testing.T) {
		sigStart := strings.LastIndex(tokenString, ".") + 1
		for _, ws := range []string{"\r\n", "\n", "\r", " ", "\t"} {
			variant := tokenString[:sigStart+10] + ws + tokenString[sigStart+10:]
			if _, err := Verify(ctx, variant, config, mockKeyFunc(pubKey)); err == nil {
				t.Errorf("token with %q inside the signature must be rejected", ws)
			}
		}
	})

	t.Run("trailing newline", func(t *testing.T) {
		if _, err := Verify(ctx, tokenString+"\n", config, mockKeyFunc(pubKey)); err == nil {
			t.Error("token with trailing newline must be rejected")
		}
	})
}

func TestShouldVerifyRejectsNonCanonicalTokens(t *testing.T) {
	tokenString, _, _, err := createValidToken()
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}

	if !ShouldVerify(tokenString, "https://example.com/") {
		t.Fatal("Baseline token should pass ShouldVerify")
	}

	sigStart := strings.LastIndex(tokenString, ".") + 1
	withCRLF := tokenString[:sigStart+10] + "\r\n" + tokenString[sigStart+10:]
	if ShouldVerify(withCRLF, "https://example.com/") {
		t.Error("ShouldVerify must reject a token with line breaks")
	}

	if ShouldVerify(tokenString+"\n", "https://example.com/") {
		t.Error("ShouldVerify must reject a token with a trailing newline")
	}
}
