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

	claims := jwt.MapClaims{}
	for k, v := range config.Claims {
		claims[k] = v
	}
	// Add the mandatory claims last, to ensure that user-provided claims cannot override them
	claims["sub"] = config.Subject
	claims["iss"] = config.Issuer
	claims["aud"] = config.Audience
	claims["exp"] = config.ExpiresAt.Unix()
	claims["ver"] = "japikey-v1"
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
