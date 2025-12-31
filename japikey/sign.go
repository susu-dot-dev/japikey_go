package japikey

import (
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Config struct {
	Subject   string
	Issuer    string
	Audience  string
	ExpiresAt time.Time
	Claims    jwt.MapClaims
}

type JAPIKey struct {
	JWT       string
	PublicKey *rsa.PublicKey
	KeyID     string
}

func NewJAPIKey(config Config) (*JAPIKey, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, &JAPIKeyGenerationError{
			Message: "failed to generate RSA key pair",
			Code:    "KeyGenerationError",
		}
	}

	keyID := uuid.New().String()

	claims := jwt.MapClaims{
		"sub": config.Subject,
		"iss": config.Issuer,
		"aud": config.Audience,
		"exp": config.ExpiresAt.Unix(),
		"ver": "japikey-v1",
	}

	// Add user claims, but ensure they don't override the mandatory config claims or version
	for k, v := range config.Claims {
		// Skip if the key is one of the mandatory claims that should not be overridden
		switch k {
		case "sub", "iss", "aud", "exp", "ver":
			// Skip these keys as they are protected and should not be overridden
			continue
		default:
			claims[k] = v
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token.Header["kid"] = keyID

	jwtString, err := token.SignedString(privateKey)
	if err != nil {
		return nil, &JAPIKeySigningError{
			Message: "failed to sign JWT",
			Code:    "SigningError",
		}
	}

	result := &JAPIKey{
		JWT:       jwtString,
		PublicKey: &privateKey.PublicKey,
		KeyID:     keyID,
	}

	return result, nil
}

func validateConfig(config Config) error {
	if config.Subject == "" {
		return &JAPIKeyValidationError{
			Message: "subject cannot be empty",
			Code:    "ValidationError",
		}
	}

	if config.ExpiresAt.Before(time.Now()) {
		return &JAPIKeyValidationError{
			Message: "expiration time must be in the future",
			Code:    "ValidationError",
		}
	}

	return nil
}

type JAPIKeyValidationError struct {
	Message string
	Code    string
}

func (e *JAPIKeyValidationError) Error() string {
	return e.Message
}

type JAPIKeyGenerationError struct {
	Message string
	Code    string
}

func (e *JAPIKeyGenerationError) Error() string {
	return e.Message
}

type JAPIKeySigningError struct {
	Message string
	Code    string
}

func (e *JAPIKeySigningError) Error() string {
	return e.Message
}
