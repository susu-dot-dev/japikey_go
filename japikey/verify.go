package japikey

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/susu-dot-dev/japikey/errors"
)

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
		return nil, errors.NewValidationError(fmt.Sprintf("token size exceeds maximum allowed size of %d bytes", MaxTokenSize))
	}

	// Decode the token without verification to extract header and payload
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, errors.NewValidationError("failed to decode token: " + err.Error())
	}

	// Extract header and claims
	header := token.Header
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.NewValidationError("failed to parse token claims")
	}

	// Extract key ID from header - it can be a string or UUID
	var keyID uuid.UUID
	keyIDRaw, ok := header[KeyIDHeader]
	if !ok {
		return nil, errors.NewValidationError("token header missing key ID")
	}

	// Handle both string and UUID types in header
	switch v := keyIDRaw.(type) {
	case string:
		keyID, err = uuid.Parse(v)
		if err != nil {
			return nil, errors.NewValidationError("token header contains invalid key ID format")
		}
	case uuid.UUID:
		keyID = v
	default:
		return nil, errors.NewValidationError("token header contains invalid key ID type")
	}

	// Extract algorithm from header
	algorithm, ok := header["alg"].(string)
	if !ok {
		return nil, errors.NewValidationError("token header missing algorithm")
	}

	// Validate algorithm is RS256
	if algorithm != AlgorithmRS256 {
		return nil, errors.NewValidationError(fmt.Sprintf("invalid algorithm: %s, expected %s", algorithm, AlgorithmRS256))
	}

	// Validate the token structure (header.payload.signature)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.NewValidationError("invalid token format: expected 3 parts separated by dots")
	}

	// Validate type header if present
	if tokenType, exists := header[TypeHeader].(string); exists {
		if tokenType != TokenType {
			return nil, errors.NewValidationError(fmt.Sprintf("invalid token type: %s, expected %s", tokenType, TokenType))
		}
	}

	// Validate version format
	version, ok := claims[VersionClaim].(string)
	if !ok {
		return nil, errors.NewValidationError("token missing version claim")
	}

	// Check if version has the correct prefix
	if !strings.HasPrefix(version, VersionPrefix) {
		return nil, errors.NewValidationError(fmt.Sprintf("invalid version format: %s, expected prefix %s", version, VersionPrefix))
	}

	// Extract version number and validate it's not exceeding max
	versionNum := 0
	if len(version) > len(VersionPrefix) {
		// Extract the number after the prefix
		_, err := fmt.Sscanf(version[len(VersionPrefix):], "%d", &versionNum)
		if err != nil || versionNum > MaxVersion {
			return nil, errors.NewValidationError(fmt.Sprintf("invalid version number: %s", version))
		}
	}

	// Validate issuer
	issuer, ok := claims[IssuerClaim].(string)
	if !ok {
		return nil, errors.NewValidationError("token missing issuer claim")
	}

	// Check if issuer starts with the base issuer URL from config
	if config.BaseIssuerURL != "" && !strings.HasPrefix(issuer, config.BaseIssuerURL) {
		return nil, errors.NewValidationError(fmt.Sprintf("invalid issuer: %s, expected to start with %s", issuer, config.BaseIssuerURL))
	}

	// Validate that key ID in header matches the UUID part of the issuer
	// Assuming the issuer format is like: https://example.com/uuid
	issuerParts := strings.Split(issuer, "/")
	if len(issuerParts) > 0 {
		issuerUUIDStr := issuerParts[len(issuerParts)-1]
		issuerUUID, err := uuid.Parse(issuerUUIDStr)
		if err != nil {
			return nil, errors.NewValidationError("issuer does not contain a valid UUID")
		}
		if issuerUUID != keyID {
			return nil, errors.NewValidationError("key ID in header does not match UUID in issuer")
		}
	}

	// Input sanitization to prevent injection attacks
	// Sanitize issuer
	if strings.Contains(issuer, "../") || strings.Contains(issuer, "..\\") {
		return nil, errors.NewValidationError("issuer contains invalid path traversal characters")
	}

	// Sanitize version
	if strings.Contains(version, "<") || strings.Contains(version, ">") {
		return nil, errors.NewValidationError("version contains invalid characters")
	}

	// Additional sanitization for other claims can be added here
	for k, v := range claims {
		// Check for potentially dangerous claim names
		if strings.Contains(k, "<") || strings.Contains(k, ">") {
			return nil, errors.NewValidationError("claim name contains invalid characters")
		}

		// Check for potentially dangerous claim values
		if strVal, ok := v.(string); ok {
			if strings.Contains(strVal, "<script") || strings.Contains(strVal, "javascript:") {
				return nil, errors.NewValidationError("claim value contains potential injection")
			}
		}
	}

	// Validate time-based claims
	// Check expiration (exp)
	if exp, ok := claims[ExpirationClaim].(float64); ok {
		// Check for excessively large numeric values
		if exp > float64(^uint32(0)) { // Check if value is too large
			return nil, errors.NewValidationError("token contains excessively large numeric value")
		}
		if int64(exp) < time.Now().Unix() {
			return nil, errors.NewValidationError("token has expired")
		}
	} else {
		return nil, errors.NewValidationError("token missing expiration claim")
	}

	// Check not-before (nbf) if present
	if nbf, ok := claims[NotBeforeClaim].(float64); ok {
		// Check for excessively large numeric values
		if nbf > float64(^uint32(0)) { // Check if value is too large
			return nil, errors.NewValidationError("token contains excessively large numeric value")
		}
		if int64(nbf) > time.Now().Unix() {
			return nil, errors.NewValidationError("token is not yet valid")
		}
	}

	// Check issued-at (iat) if present
	if iat, ok := claims[IssuedAtClaim].(float64); ok {
		// Check for excessively large numeric values
		if iat > float64(^uint32(0)) { // Check if value is too large
			return nil, errors.NewValidationError("token contains excessively large numeric value")
		}
		if int64(iat) > time.Now().Unix() {
			return nil, errors.NewValidationError("token was issued in the future")
		}
	}

	// Retrieve the appropriate cryptographic key using the keyFunc callback
	publicKey, err := keyFunc(keyID)
	if err != nil {
		// Check if it's already a KeyNotFoundError, otherwise wrap it
		if _, ok := err.(*errors.KeyNotFoundError); ok {
			return nil, err
		}
		return nil, errors.NewKeyNotFoundError("failed to retrieve public key")
	}

	// Verify the token signature
	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.NewValidationError(fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}
		return publicKey, nil
	})
	if err != nil {
		// Don't expose internal details about signature verification failure to prevent information leakage
		return nil, errors.NewValidationError("signature verification failed")
	}

	if !token.Valid {
		return nil, errors.NewValidationError("token signature is invalid")
	}

	// Extract claims again after successful verification
	claims, ok = token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.NewValidationError("failed to parse token claims after verification")
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

	// Additional pre-validation checks can be added here

	return true
}
