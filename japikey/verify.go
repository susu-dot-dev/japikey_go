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

// validateVersion validates the version claim format and number.
func validateVersion(claims jwt.MapClaims) error {
	_, err := ValidateVersionFromClaims(claims)
	return err
}

// validateIssuer validates that the issuer claim exactly matches baseIssuerURL/keyID.
// baseIssuerURL is required for security - issuer validation is mandatory.
func validateIssuer(claims jwt.MapClaims, baseIssuerURL string, keyID uuid.UUID) error {
	if baseIssuerURL == "" {
		return japikeyerrors.NewInternalError("base issuer URL is required for issuer validation")
	}

	issuerRaw, ok := claims[IssuerClaim]
	if !ok {
		return japikeyerrors.NewValidationError("token missing issuer claim")
	}
	issuer, ok := issuerRaw.(string)
	if !ok || issuer == "" {
		return japikeyerrors.NewValidationError("token issuer claim must be a string")
	}

	// Normalize baseIssuerURL to always end with /
	normalizedBaseURL := baseIssuerURL
	if !strings.HasSuffix(normalizedBaseURL, "/") {
		normalizedBaseURL += "/"
	}

	// Expected issuer is exactly baseIssuerURL/keyID
	expectedIssuer := normalizedBaseURL + keyID.String()

	// Exact string match
	if issuer != expectedIssuer {
		return japikeyerrors.NewValidationError(fmt.Sprintf("invalid issuer: %s, expected %s", issuer, expectedIssuer))
	}

	return nil
}

// extractKeyIDFromHeader extracts and validates the key ID from the token header.
func extractKeyIDFromHeader(header map[string]interface{}) (uuid.UUID, error) {
	keyIDRaw, ok := header[KeyIDHeader]
	if !ok {
		return uuid.Nil, japikeyerrors.NewValidationError("token header missing key ID")
	}

	keyIDStr, ok := keyIDRaw.(string)
	if !ok {
		return uuid.Nil, japikeyerrors.NewValidationError("token header contains invalid key ID type")
	}

	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		return uuid.Nil, japikeyerrors.NewValidationError("token header contains invalid key ID format")
	}

	return keyID, nil
}

// validateJAPIKeyClaims validates JAPIKey-specific requirements on the claims map.
func validateJAPIKeyClaims(claims jwt.MapClaims, baseIssuerURL string, keyID uuid.UUID) error {
	if err := validateVersion(claims); err != nil {
		return err
	}

	if err := validateIssuer(claims, baseIssuerURL, keyID); err != nil {
		return err
	}

	return nil
}

// checkTokenSize validates that the token size is within the maximum allowed limit.
func checkTokenSize(tokenString string) error {
	if len(tokenString) > MaxTokenSize {
		return japikeyerrors.NewValidationError(fmt.Sprintf("token size exceeds maximum allowed size of %d bytes", MaxTokenSize))
	}
	return nil
}

// Verify takes in the JWT string, the config, as well as a callback function which retrieves the JWK if given the key id.
// It either returns the validated claims, or an appropriate error.
func Verify(tokenString string, config VerifyConfig, keyFunc JWKCallback) (*VerificationResult, error) {
	// FR-020: Enforce maximum token size limit BEFORE any parsing
	if err := checkTokenSize(tokenString); err != nil {
		return nil, err
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
		var extractErr error
		keyID, extractErr = extractKeyIDFromHeader(token.Header)
		if extractErr != nil {
			return nil, extractErr
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
			return nil, japikeyerrors.NewTokenExpiredError("token has expired")
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
// It decodes the token without verification and validates version, issuer format, and kid matching.
// Based on the JavaScript implementation: https://github.com/susu-dot-dev/japikey_js/blob/main/packages/authenticate/src/index.ts
func ShouldVerify(tokenString string, baseIssuer string) bool {
	// FR-020: Check token size
	if len(tokenString) > MaxTokenSize {
		return false
	}

	// Decode token without verification (similar to jose.decodeJwt and jose.decodeProtectedHeader)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	claims := jwt.MapClaims{}
	token, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		return false
	}

	// Validate version format and number
	if validateVersion(claims) != nil {
		return false
	}

	// Validate kid is present and is a valid UUID
	keyID, err := extractKeyIDFromHeader(token.Header)
	if err != nil {
		return false
	}

	// Validate issuer format matches baseIssuer/keyID exactly
	if err := validateIssuer(claims, baseIssuer, keyID); err != nil {
		return false
	}

	return true
}
