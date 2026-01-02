package japikey

import (
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/susu-dot-dev/japikey/errors"
	"github.com/susu-dot-dev/japikey/internal/jwks"
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
	KeyID     uuid.UUID
}

func (j *JAPIKey) ToJWKS() (*jwks.JWKS, error) {
	if j.KeyID == uuid.Nil {
		return nil, errors.NewValidationError("key ID cannot be empty")
	}

	if j.PublicKey == nil {
		return nil, errors.NewValidationError("RSA public key cannot be nil")
	}

	return jwks.NewJWKS(j.PublicKey, j.KeyID)
}

func NewJAPIKey(config Config) (*JAPIKey, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.NewInternalError("failed to generate RSA key pair")
	}

	keyID := uuid.New()

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
		return nil, errors.NewInternalError("failed to sign JWT")
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
		return errors.NewValidationError("subject cannot be empty")
	}

	if config.ExpiresAt.Before(time.Now()) {
		return errors.NewValidationError("expiration time must be in the future")
	}

	return nil
}
