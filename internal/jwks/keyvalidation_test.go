package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"uuid"

	"github.com/susu-dot-dev/japikey_go/errors"
)

// modulusWithBits returns an odd modulus with exactly the requested bit length.
// It is not a real RSA modulus; it only exercises the size and parity checks.
func modulusWithBits(bits int) *big.Int {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return n.Or(n, big.NewInt(1))
}

func TestNewJWKS_KeyValidation(t *testing.T) {
	even2048 := new(big.Int).Lsh(big.NewInt(1), 2047) // exactly 2048 bits, even

	tests := []struct {
		name  string
		key   *rsa.PublicKey
		valid bool
	}{
		{"2048 bits, e=65537", &rsa.PublicKey{N: modulusWithBits(2048), E: 65537}, true},
		{"3072 bits", &rsa.PublicKey{N: modulusWithBits(3072), E: 65537}, true},
		{"4096 bits (upper bound)", &rsa.PublicKey{N: modulusWithBits(4096), E: 65537}, true},
		{"2047 bits", &rsa.PublicKey{N: modulusWithBits(2047), E: 65537}, false},
		{"1024 bits", &rsa.PublicKey{N: modulusWithBits(1024), E: 65537}, false},
		{"256 bits", &rsa.PublicKey{N: modulusWithBits(256), E: 65537}, false},
		{"4097 bits", &rsa.PublicKey{N: modulusWithBits(4097), E: 65537}, false},
		{"8192 bits", &rsa.PublicKey{N: modulusWithBits(8192), E: 65537}, false},
		{"even modulus", &rsa.PublicKey{N: even2048, E: 65537}, false},
		{"zero modulus", &rsa.PublicKey{N: big.NewInt(0), E: 65537}, false},
		{"negative modulus", &rsa.PublicKey{N: new(big.Int).Neg(modulusWithBits(2048)), E: 65537}, false},
		{"nil modulus", &rsa.PublicKey{N: nil, E: 65537}, false},
		{"e=3 (lower bound)", &rsa.PublicKey{N: modulusWithBits(2048), E: 3}, true},
		{"e=2^31-1 (upper bound)", &rsa.PublicKey{N: modulusWithBits(2048), E: 1<<31 - 1}, true},
		{"e=0", &rsa.PublicKey{N: modulusWithBits(2048), E: 0}, false},
		{"e=1", &rsa.PublicKey{N: modulusWithBits(2048), E: 1}, false},
		{"e=2", &rsa.PublicKey{N: modulusWithBits(2048), E: 2}, false},
		{"e even (65536)", &rsa.PublicKey{N: modulusWithBits(2048), E: 65536}, false},
		{"e negative", &rsa.PublicKey{N: modulusWithBits(2048), E: -65537}, false},
		{"e=2^31 (above Go limit)", &rsa.PublicKey{N: modulusWithBits(2048), E: 1 << 31}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewJWKS(tt.key, uuid.New())
			if tt.valid && err != nil {
				t.Errorf("expected key to be accepted, got: %v", err)
			}
			if !tt.valid {
				if err == nil {
					t.Fatal("expected key to be rejected")
				}
				if _, ok := err.(*errors.ValidationError); !ok {
					t.Errorf("expected ValidationError, got %T", err)
				}
			}
		})
	}
}

func TestJWKS_UnmarshalRejectsUnusableKeys(t *testing.T) {
	kid := uuid.New().String()
	enc := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.Bytes()) }
	goodN := enc(modulusWithBits(2048))

	// An exponent that does not fit in int64; before the range check this could
	// have been truncated into a small valid-looking value.
	hugeE := enc(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(3)))

	tests := []struct {
		name string
		n, e string
	}{
		{"e=1", goodN, "AQ"},
		{"e=0", goodN, "AA"},
		{"e=2", goodN, "Ag"},
		{"e even", goodN, "AQAA"}, // 65536
		{"e overflows int64", goodN, hugeE},
		{"e=2^31", goodN, enc(new(big.Int).Lsh(big.NewInt(1), 31))},
		{"n=0", "AA", "AQAB"},
		{"n 256 bits", enc(modulusWithBits(256)), "AQAB"},
		{"n 4097 bits", enc(modulusWithBits(4097)), "AQAB"},
		{"n even", enc(new(big.Int).Lsh(big.NewInt(1), 2047)), "AQAB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			js := `{"keys":[{"kty":"RSA","kid":"` + kid + `","n":"` + tt.n + `","e":"` + tt.e + `"}]}`
			var j JWKS
			err := json.Unmarshal([]byte(js), &j)
			if err == nil {
				t.Fatal("expected unusable key to be rejected")
			}
			if _, ok := err.(*errors.ValidationError); !ok {
				t.Errorf("expected ValidationError, got %T: %v", err, err)
			}
		})
	}
}

func TestJWKS_UnmarshalAcceptsGeneratedKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	original, err := NewJWKS(&priv.PublicKey, uuid.New())
	if err != nil {
		t.Fatalf("NewJWKS rejected a generated key: %v", err)
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var parsed JWKS
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal rejected a generated key: %v", err)
	}
}
