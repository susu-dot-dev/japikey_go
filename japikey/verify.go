package japikey

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	japikeyerrors "github.com/susu-dot-dev/japikey/errors"
)

// JWKCallback is a function that retrieves the JWK (JSON Web Key) given the key ID.
// This function is used during token verification to get the appropriate public key
// for signature verification.
type JWKCallback func(keyID uuid.UUID) (*rsa.PublicKey, error)

// VerificationResult holds the result of a successful token verification.
type VerificationResult struct {
	// Claims contains the validated claims from the token
	Claims jwt.MapClaims

	// KeyID is the key identifier from the token header
	KeyID uuid.UUID
}

// VerifyConfig holds the configuration for verifying a JAPIKey.
// It contains the required and optional parameters for API key verification.
type VerifyConfig struct {
	// BaseIssuerURL is the base URL for the issuer that should be present in the token
	BaseIssuerURL string

	// Timeout is the timeout for retrieving cryptographic keys from the callback function
	// It should be a value > 0
	Timeout time.Duration
}

// validateJAPIKeyClaims validates JAPIKey-specific requirements on the claims map.
func validateJAPIKeyClaims(claims jwt.MapClaims, baseIssuerURL string, keyID uuid.UUID) error {
	// FR-002: Validate version format
	versionRaw, ok := claims[VersionClaim]
	if !ok {
		return japikeyerrors.NewValidationError("token missing version claim")
	}
	version, ok := versionRaw.(string)
	if !ok {
		return japikeyerrors.NewValidationError("token version claim must be a string")
	}

	if !strings.HasPrefix(version, VersionPrefix) {
		return japikeyerrors.NewValidationError(fmt.Sprintf("invalid version format: %s, expected prefix %s", version, VersionPrefix))
	}

	// FR-008: Validate version number doesn't exceed maximum
	if len(version) > len(VersionPrefix) {
		var versionNum int
		_, err := fmt.Sscanf(version[len(VersionPrefix):], "%d", &versionNum)
		if err != nil || versionNum > MaxVersion {
			return japikeyerrors.NewValidationError(fmt.Sprintf("invalid version number: %s", version))
		}
	}

	// FR-003: Validate issuer format
	issuerRaw, ok := claims[IssuerClaim]
	if !ok {
		return japikeyerrors.NewValidationError("token missing issuer claim")
	}
	issuer, ok := issuerRaw.(string)
	if !ok {
		return japikeyerrors.NewValidationError("token issuer claim must be a string")
	}

	if baseIssuerURL != "" && !strings.HasPrefix(issuer, baseIssuerURL) {
		return japikeyerrors.NewValidationError(fmt.Sprintf("invalid issuer: %s, expected to start with %s", issuer, baseIssuerURL))
	}

	// FR-004: Validate that key ID matches UUID part of issuer
	issuerParts := strings.Split(issuer, "/")
	if len(issuerParts) > 0 {
		issuerUUIDStr := issuerParts[len(issuerParts)-1]
		issuerUUID, err := uuid.Parse(issuerUUIDStr)
		if err != nil {
			return japikeyerrors.NewValidationError("issuer does not contain a valid UUID")
		}
		if issuerUUID != keyID {
			return japikeyerrors.NewValidationError("key ID in header does not match UUID in issuer")
		}
	}

	return nil
}

// Verify takes in the JWT string, the config, as well as a callback function which retrieves the JWK if given the key id.
// It either returns the validated claims, or an appropriate error.
func Verify(tokenString string, config VerifyConfig, keyFunc JWKCallback) (*VerificationResult, error) {
	// FR-020: Enforce maximum token size limit BEFORE any parsing
	if len(tokenString) > MaxTokenSize {
		return nil, japikeyerrors.NewValidationError(fmt.Sprintf("token size exceeds maximum allowed size of %d bytes", MaxTokenSize))
	}

	// FR-014: Use golang-jwt library for parsing and validation
	// FR-010, FR-022: Validate algorithm is exactly RS256
	// FR-016: Validate exp claim is present and not expired (no clock skew)
	// FR-017: Validate nbf if present (no clock skew)
	// FR-018: Validate iat if present (no clock skew)
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{AlgorithmRS256}),
		jwt.WithExpirationRequired(),
	)

	claims := jwt.MapClaims{}
	var keyID uuid.UUID
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// FR-027: Validate key ID is present and properly formatted
		keyIDRaw, ok := token.Header[KeyIDHeader]
		if !ok {
			return nil, japikeyerrors.NewValidationError("token header missing key ID")
		}

		keyIDStr, ok := keyIDRaw.(string)
		if !ok {
			return nil, japikeyerrors.NewValidationError("token header contains invalid key ID type")
		}

		var parseErr error
		keyID, parseErr = uuid.Parse(keyIDStr)
		if parseErr != nil {
			return nil, japikeyerrors.NewValidationError("token header contains invalid key ID format")
		}

		// Retrieve the public key using the callback
		publicKey, err := keyFunc(keyID)
		if err != nil {
			if _, ok := err.(*japikeyerrors.KeyNotFoundError); ok {
				return nil, err
			}
			return nil, japikeyerrors.NewKeyNotFoundError("failed to retrieve public key")
		}

		return publicKey, nil
	})

	if err != nil {
		// FR-028: Prevent information leakage - map library errors to generic messages
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, japikeyerrors.NewValidationError("token has expired")
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, japikeyerrors.NewValidationError("token is not yet valid")
		}
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, japikeyerrors.NewValidationError("token is malformed")
		}
		// Check if it's a validation error from our custom validation
		if validationErr, ok := err.(*japikeyerrors.ValidationError); ok {
			return nil, validationErr
		}
		return nil, japikeyerrors.NewValidationError("signature verification failed")
	}

	if !token.Valid {
		return nil, japikeyerrors.NewValidationError("token signature is invalid")
	}

	// Validate JAPIKey-specific requirements
	if err := validateJAPIKeyClaims(claims, config.BaseIssuerURL, keyID); err != nil {
		return nil, err
	}

	// Return the validated claims (preserving all custom claims)
	result := &VerificationResult{
		Claims: claims,
		KeyID:  keyID,
	}

	return result, nil
}

// ShouldVerify is a pre-validation function that checks if a token has the correct format before full verification.
func ShouldVerify(tokenString string, baseIssuer string) bool {
	// FR-020: Check token size
	if len(tokenString) > MaxTokenSize {
		return false
	}

	// FR-025: Validate token structure (header.payload.signature)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return false
	}

	return true
}
