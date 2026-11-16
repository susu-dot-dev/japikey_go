package japikey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/susu-dot-dev/japikey_go/errors"
	"github.com/susu-dot-dev/japikey_go/internal/jwks"
)

type Config struct {
	Subject string
	// Issuer is the base issuer URL, not the final "iss" claim. The key ID is
	// appended to it (see BuildIssuer). It must be an absolute https URL with a
	// host and no user info, query or fragment, in canonical form, ending in at
	// most one "/" (see AllowInsecureHTTP for http).
	Issuer    string
	Audience  string
	ExpiresAt time.Time
	Claims    jwt.MapClaims

	// AllowInsecureHTTP permits an http:// Issuer. It exists for local
	// development and tests only; never enable it in production.
	AllowInsecureHTTP bool
}

type JAPIKey struct {
	JWT string
	// PublicKey is the public half of the key pair, to be stored and served as
	// a JWKS. Keys minted by this version are *ecdsa.PublicKey (P-256).
	PublicKey crypto.PublicKey
	KeyID     uuid.UUID
}

func (j *JAPIKey) ToJWKS() (*jwks.JWKS, error) {
	if j.KeyID == uuid.Nil() {
		return nil, errors.NewValidationError("key ID cannot be empty")
	}

	if j.PublicKey == nil {
		return nil, errors.NewValidationError("public key cannot be nil")
	}

	return jwks.NewJWKS(j.PublicKey, j.KeyID)
}

// BuildIssuer returns the issuer claim for a key: the base issuer URL joined
// with the key ID by exactly one "/". A trailing slash on baseIssuerURL is
// optional. The JWKS for the key is served at BuildIssuer(...)+"/.well-known/jwks.json".
//
// NewJAPIKey uses it to set "iss" and Verify uses it to check "iss", so the two
// always agree.
func BuildIssuer(baseIssuerURL string, keyID uuid.UUID) string {
	return strings.TrimSuffix(baseIssuerURL, "/") + "/" + keyID.String()
}

// validateBaseIssuerURL checks that baseIssuerURL is a URL from which both
// japikey and third-party verifiers derive the same issuer and JWKS location
// (BuildIssuer(...)+"/.well-known/jwks.json"). It must:
//   - parse as an absolute URL with an https scheme (http only when
//     allowInsecureHTTP is set);
//   - have a host, and no user info, query or fragment;
//   - end with at most one "/";
//   - be in canonical form (url.Parse + String round-trips exactly), so that
//     the string placed in "iss" is exactly what a URL parser produces;
//   - have a clean path with no escapes: no empty, "." or ".." segments.
//
// Error messages are fixed and never include the input.
func validateBaseIssuerURL(baseIssuerURL string, allowInsecureHTTP bool) error {
	if baseIssuerURL == "" {
		return errors.NewValidationError("base issuer URL cannot be empty")
	}
	// Checked on the raw string: url.Parse drops an empty query ("?") or fragment ("#")
	if strings.ContainsAny(baseIssuerURL, "?#") {
		return errors.NewValidationError("base issuer URL must not contain a query or fragment")
	}
	u, err := url.Parse(baseIssuerURL)
	if err != nil {
		return errors.NewValidationError("base issuer URL is not a valid URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecureHTTP {
			return errors.NewValidationError("base issuer URL must use https")
		}
	default:
		return errors.NewValidationError("base issuer URL must use https")
	}
	if u.Opaque != "" || u.Hostname() == "" {
		return errors.NewValidationError("base issuer URL must be absolute and include a host")
	}
	if u.User != nil {
		return errors.NewValidationError("base issuer URL must not contain user info")
	}
	if strings.HasSuffix(baseIssuerURL, "//") {
		return errors.NewValidationError("base issuer URL must not end with more than one slash")
	}
	if u.String() != baseIssuerURL {
		return errors.NewValidationError("base issuer URL must be in canonical form")
	}
	// The JWKS route is matched by http.ServeMux, which redirects paths that are
	// not clean (//, /./, /../) and decodes escapes, and HTTP clients may
	// normalise dot segments, so such an issuer would not lead back to the
	// JWKS. Require a clean, unescaped path. A single trailing "/" is allowed.
	if u.RawPath != "" || strings.Contains(u.Path, "%") {
		return errors.NewValidationError("base issuer URL path must not contain escaped characters")
	}
	if u.Path != "" {
		cleaned := path.Clean(u.Path)
		if strings.HasSuffix(u.Path, "/") && cleaned != "/" {
			cleaned += "/"
		}
		if cleaned != u.Path {
			return errors.NewValidationError("base issuer URL path must be clean (no empty, . or .. segments)")
		}
	}
	return nil
}

// NewJAPIKey creates a new API key. Config.Issuer is the base issuer URL (for
// example "https://api.example.com/keys"); the token's "iss" claim becomes
// "<Issuer>/<key id>", which must match VerifyConfig.BaseIssuerURL when
// verifying.
func NewJAPIKey(config Config) (*JAPIKey, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.NewInternalError("failed to generate EC key pair")
	}

	// Key IDs are UUIDv7 (time-ordered), per the spec.
	keyID := uuid.NewV7()

	claims := jwt.MapClaims{}
	for k, v := range config.Claims {
		claims[k] = v
	}
	// Add the mandatory claims last, to ensure that user-provided claims cannot override them
	claims["sub"] = config.Subject
	// The issuer is the base issuer URL joined with the key ID. Verify requires
	// exactly this form, and it makes the JWKS location derivable from the token
	// alone (<iss>/.well-known/jwks.json). The key ID is generated above, so the
	// caller cannot supply the full issuer themselves.
	claims["iss"] = BuildIssuer(config.Issuer, keyID)
	claims["aud"] = config.Audience
	claims["exp"] = config.ExpiresAt.Unix()
	claims["iat"] = time.Now().Unix()
	claims["ver"] = fmt.Sprintf("%s%d", VersionPrefix, CurrentVersion)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	token.Header["kid"] = keyID

	jwtString, err := token.SignedString(privateKey)
	if err != nil {
		return nil, errors.NewInternalError("failed to sign JWT")
	}

	// Reject tokens that Verify would refuse anyway (e.g. oversized custom claims)
	if len(jwtString) > MaxTokenSize {
		return nil, errors.NewValidationError(fmt.Sprintf("generated token exceeds maximum allowed size of %d bytes", MaxTokenSize))
	}

	// Copy the public key out of the private key struct. Returning
	// &privateKey.PublicKey would be an interior pointer, which keeps the entire
	// ecdsa.PrivateKey (the scalar D) reachable by the GC for as
	// long as the caller holds the public key. The private key is meant to be
	// discarded as soon as this function returns.
	publicKey, err := copyPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, errors.NewInternalError("failed to export public key")
	}

	result := &JAPIKey{
		JWT:       jwtString,
		PublicKey: publicKey,
		KeyID:     keyID,
	}

	return result, nil
}

// copyPublicKey returns an independent copy of pub, sharing no memory with the
// private key it came from.
func copyPublicKey(pub *ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	point, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
}

func validateConfig(config Config) error {
	if config.Subject == "" {
		return errors.NewValidationError("subject cannot be empty")
	}

	if err := validateBaseIssuerURL(config.Issuer, config.AllowInsecureHTTP); err != nil {
		return err
	}

	if config.ExpiresAt.Before(time.Now().Add(MinKeyLifetime)) {
		return errors.NewValidationError(fmt.Sprintf("expiration time must be at least %s in the future", MinKeyLifetime))
	}

	return nil
}
