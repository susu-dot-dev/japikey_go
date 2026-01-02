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

	return nil
}

// validateIssuer validates issuer format and extracts the UUID from it.
// Returns the issuer string and the UUID extracted from it.
// baseIssuerURL is required for security - issuer validation is mandatory.
func validateIssuer(claims jwt.MapClaims, baseIssuerURL string) (string, uuid.UUID, error) {
	if baseIssuerURL == "" {
		return "", uuid.Nil, japikeyerrors.NewValidationError("base issuer URL is required for issuer validation")
	}

	issuerRaw, ok := claims[IssuerClaim]
	if !ok {
		return "", uuid.Nil, japikeyerrors.NewValidationError("token missing issuer claim")
	}
	issuer, ok := issuerRaw.(string)
	if !ok {
		return "", uuid.Nil, japikeyerrors.NewValidationError("token issuer claim must be a string")
	}

	// Normalize baseIssuerURL to always end with /
	normalizedBaseURL := baseIssuerURL
	if !strings.HasSuffix(normalizedBaseURL, "/") {
		normalizedBaseURL += "/"
	}

	// Validate issuer starts with baseIssuerURL
	if !strings.HasPrefix(issuer, normalizedBaseURL) {
		return "", uuid.Nil, japikeyerrors.NewValidationError(fmt.Sprintf("invalid issuer: %s, expected to start with %s", issuer, normalizedBaseURL))
	}

	// Extract UUID from issuer (last part after /)
	issuerParts := strings.Split(issuer, "/")
	if len(issuerParts) == 0 {
		return "", uuid.Nil, japikeyerrors.NewValidationError("issuer does not contain a valid UUID")
	}
	issuerUUIDStr := issuerParts[len(issuerParts)-1]
	issuerUUID, err := uuid.Parse(issuerUUIDStr)
	if err != nil {
		return "", uuid.Nil, japikeyerrors.NewValidationError("issuer does not contain a valid UUID")
	}

	return issuer, issuerUUID, nil
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

// validateKidMatchesIssuer validates that the key ID matches the UUID extracted from the issuer.
func validateKidMatchesIssuer(keyID uuid.UUID, issuerUUID uuid.UUID) error {
	if keyID != issuerUUID {
		return japikeyerrors.NewValidationError("key ID in header does not match UUID in issuer")
	}
	return nil
}

// validateJAPIKeyClaims validates JAPIKey-specific requirements on the claims map.
func validateJAPIKeyClaims(claims jwt.MapClaims, baseIssuerURL string, keyID uuid.UUID) error {
	if err := validateVersion(claims); err != nil {
		return err
	}

	_, issuerUUID, err := validateIssuer(claims, baseIssuerURL)
	if err != nil {
		return err
	}

	if err := validateKidMatchesIssuer(keyID, issuerUUID); err != nil {
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

	// Validate issuer format and extract UUID (baseIssuer is required)
	issuer, issuerUUID, err := validateIssuer(claims, baseIssuer)
	if err != nil || issuer == "" {
		return false
	}

	// Validate kid is present and is a valid UUID
	keyID, err := extractKeyIDFromHeader(token.Header)
	if err != nil {
		return false
	}

	// Validate that kid matches issuer UUID
	if keyID != issuerUUID {
		return false
	}

	return true
}
