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
	Claims map[string]interface{}

	// KeyID is the key identifier from the token header
	KeyID uuid.UUID

	// Algorithm is the algorithm used in the token
	Algorithm string
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

// Verify takes in the JWT string, the config, as well as a callback function which retrieves the JWK if given the key id.
// It either returns the validated claims, or an appropriate error.
func Verify(tokenString string, config VerifyConfig, keyFunc JWKCallback) (*VerificationResult, error) {
	// First, validate the token size
	if len(tokenString) > MaxTokenSize {
		return nil, japikeyerrors.NewValidationError(fmt.Sprintf("token size exceeds maximum allowed size of %d bytes", MaxTokenSize))
	}

	// Parse and verify the token using golang-jwt library
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{AlgorithmRS256}),
		jwt.WithExpirationRequired(),
	)

	token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Extract key ID from header
		keyIDRaw, ok := token.Header[KeyIDHeader]
		if !ok {
			return nil, japikeyerrors.NewValidationError("token header missing key ID")
		}

		// Parse key ID - it can be a string or UUID
		var keyID uuid.UUID
		switch v := keyIDRaw.(type) {
		case string:
			var parseErr error
			keyID, parseErr = uuid.Parse(v)
			if parseErr != nil {
				return nil, japikeyerrors.NewValidationError("token header contains invalid key ID format")
			}
		case uuid.UUID:
			keyID = v
		default:
			return nil, japikeyerrors.NewValidationError("token header contains invalid key ID type")
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
		// Map common jwt library errors to our error types
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, japikeyerrors.NewValidationError("token has expired")
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, japikeyerrors.NewValidationError("token is not yet valid")
		}
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, japikeyerrors.NewValidationError("failed to decode token: " + err.Error())
		}
		return nil, japikeyerrors.NewValidationError("signature verification failed")
	}

	if !token.Valid {
		return nil, japikeyerrors.NewValidationError("token signature is invalid")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, japikeyerrors.NewValidationError("failed to parse token claims")
	}

	// Extract algorithm from header
	algorithm, ok := token.Header["alg"].(string)
	if !ok {
		return nil, japikeyerrors.NewValidationError("token header missing algorithm")
	}

	// Extract key ID for result
	keyIDRaw, ok := token.Header[KeyIDHeader]
	if !ok {
		return nil, japikeyerrors.NewValidationError("token header missing key ID")
	}

	var keyID uuid.UUID
	switch v := keyIDRaw.(type) {
	case string:
		var parseErr error
		keyID, parseErr = uuid.Parse(v)
		if parseErr != nil {
			return nil, japikeyerrors.NewValidationError("token header contains invalid key ID format")
		}
	case uuid.UUID:
		keyID = v
	default:
		return nil, japikeyerrors.NewValidationError("token header contains invalid key ID type")
	}

	// Validate type header if present
	if tokenType, exists := token.Header[TypeHeader].(string); exists {
		if tokenType != TokenType {
			return nil, japikeyerrors.NewValidationError(fmt.Sprintf("invalid token type: %s, expected %s", tokenType, TokenType))
		}
	}

	// Validate version format
	version, ok := claims[VersionClaim].(string)
	if !ok {
		return nil, japikeyerrors.NewValidationError("token missing version claim")
	}

	if !strings.HasPrefix(version, VersionPrefix) {
		return nil, japikeyerrors.NewValidationError(fmt.Sprintf("invalid version format: %s, expected prefix %s", version, VersionPrefix))
	}

	// Extract version number and validate it's not exceeding max
	if len(version) > len(VersionPrefix) {
		var versionNum int
		_, err := fmt.Sscanf(version[len(VersionPrefix):], "%d", &versionNum)
		if err != nil || versionNum > MaxVersion {
			return nil, japikeyerrors.NewValidationError(fmt.Sprintf("invalid version number: %s", version))
		}
	}

	// Validate issuer
	issuer, ok := claims[IssuerClaim].(string)
	if !ok {
		return nil, japikeyerrors.NewValidationError("token missing issuer claim")
	}

	if config.BaseIssuerURL != "" && !strings.HasPrefix(issuer, config.BaseIssuerURL) {
		return nil, japikeyerrors.NewValidationError(fmt.Sprintf("invalid issuer: %s, expected to start with %s", issuer, config.BaseIssuerURL))
	}

	// Validate that key ID in header matches the UUID part of the issuer
	issuerParts := strings.Split(issuer, "/")
	if len(issuerParts) > 0 {
		issuerUUIDStr := issuerParts[len(issuerParts)-1]
		issuerUUID, err := uuid.Parse(issuerUUIDStr)
		if err != nil {
			return nil, japikeyerrors.NewValidationError("issuer does not contain a valid UUID")
		}
		if issuerUUID != keyID {
			return nil, japikeyerrors.NewValidationError("key ID in header does not match UUID in issuer")
		}
	}

	// Input sanitization to prevent injection attacks
	if strings.Contains(issuer, "../") || strings.Contains(issuer, "..\\") {
		return nil, japikeyerrors.NewValidationError("issuer contains invalid path traversal characters")
	}

	if strings.Contains(version, "<") || strings.Contains(version, ">") {
		return nil, japikeyerrors.NewValidationError("version contains invalid characters")
	}

	// Additional sanitization for other claims
	for k, v := range claims {
		if strings.Contains(k, "<") || strings.Contains(k, ">") {
			return nil, japikeyerrors.NewValidationError("claim name contains invalid characters")
		}

		if strVal, ok := v.(string); ok {
			if strings.Contains(strVal, "<script") || strings.Contains(strVal, "javascript:") {
				return nil, japikeyerrors.NewValidationError("claim value contains potential injection")
			}
		}
	}

	// Validate time-based claims (library handles exp, but we check for excessive values)
	if exp, ok := claims[ExpirationClaim].(float64); ok {
		if exp > float64(^uint32(0)) {
			return nil, japikeyerrors.NewValidationError("token contains excessively large numeric value")
		}
	}

	if nbf, ok := claims[NotBeforeClaim].(float64); ok {
		if nbf > float64(^uint32(0)) {
			return nil, japikeyerrors.NewValidationError("token contains excessively large numeric value")
		}
	}

	if iat, ok := claims[IssuedAtClaim].(float64); ok {
		if iat > float64(^uint32(0)) {
			return nil, japikeyerrors.NewValidationError("token contains excessively large numeric value")
		}
		if int64(iat) > time.Now().Unix() {
			return nil, japikeyerrors.NewValidationError("token was issued in the future")
		}
	}

	// Return the validated claims
	result := &VerificationResult{
		Claims:    claims,
		KeyID:     keyID,
		Algorithm: algorithm,
	}

	return result, nil
}

// ShouldVerify is a pre-validation function that checks if a token has the correct format before full verification.
func ShouldVerify(tokenString string, baseIssuer string) bool {
	// Check if token has correct JWT format (header.payload.signature)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return false
	}

	// Check if token size is within limits
	if len(tokenString) > MaxTokenSize {
		return false
	}

	return true
}
