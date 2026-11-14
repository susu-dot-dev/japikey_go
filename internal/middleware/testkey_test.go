package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"sync"
	"testing"
)

var (
	testModulusOnce sync.Once
	testModulus     *big.Int
)

// validTestModulus returns the modulus of a real, generated 2048-bit RSA key. The JWKS
// code rejects weak or malformed keys, so tests that only need "some valid public key"
// must not use toy values. The key is generated once and shared, and a fresh copy of the
// modulus is returned each call.
func validTestModulus(t testing.TB) *big.Int {
	t.Helper()
	testModulusOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate test key: %v", err)
		}
		testModulus = key.N
	})
	return new(big.Int).Set(testModulus)
}
