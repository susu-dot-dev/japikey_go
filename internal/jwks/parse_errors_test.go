package jwks

import (
	"crypto/rsa"
	"strings"
	"testing"
	"uuid"

	"github.com/susu-dot-dev/japikey/errors"
)

// Parse errors must use fixed messages: errors from encoding/json, encoding/base64
// and uuid can quote parts of the (untrusted) input.
func TestUnmarshalJSON_ErrorsDoNotEchoInput(t *testing.T) {
	const marker = "INJECTEDMARKER"
	validN := base64urlUIntEncode(modulusWithBits(2048))
	kid := uuid.New().String()

	inputs := map[string]string{
		"json syntax":         `{"keys":[` + marker + `]}`,
		"wrong type for keys": `{"keys":"` + marker + `"}`,
		"kid not a uuid":      `{"keys":[{"kty":"RSA","kid":"` + marker + `","n":"` + validN + `","e":"AQAB"}]}`,
		"kid wrong type":      `{"keys":[{"kty":"RSA","kid":["` + marker + `"],"n":"` + validN + `","e":"AQAB"}]}`,
		"n bad base64":        `{"keys":[{"kty":"RSA","kid":"` + kid + `","n":"` + marker + `!!","e":"AQAB"}]}`,
		"e bad base64":        `{"keys":[{"kty":"RSA","kid":"` + kid + `","n":"` + validN + `","e":"` + marker + `!!"}]}`,
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			var j JWKS
			err := j.UnmarshalJSON([]byte(input))
			if err == nil {
				t.Fatal("expected an error")
			}
			if _, ok := err.(*errors.ValidationError); !ok {
				t.Errorf("expected *ValidationError, got %T: %v", err, err)
			}
			if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "!!") {
				t.Errorf("error echoes input: %q", err.Error())
			}
		})
	}
}

func TestValidatePublicKey_Nil(t *testing.T) {
	if err := ValidatePublicKey(nil); err == nil {
		t.Error("expected error for nil key")
	}
	if err := ValidatePublicKey(&rsa.PublicKey{E: 65537}); err == nil {
		t.Error("expected error for nil modulus")
	}
}
