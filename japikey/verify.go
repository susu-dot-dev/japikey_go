package japikey

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
		return nil, &JAPIKeyVerificationError{
			Message: fmt.Sprintf("token size exceeds maximum allowed size of %d bytes", MaxTokenSize),
			Code:    "TokenSizeError",
		}
	}

	// Decode the token without verification to extract header and payload
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, &JAPIKeyVerificationError{
			Message: "failed to decode token: " + err.Error(),
			Code:    "TokenFormatError",
		}
	}

	// Extract header and claims
	header := token.Header
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &JAPIKeyVerificationError{
			Message: "failed to parse token claims",
			Code:    "TokenFormatError",
		}
	}

	// Extract key ID from header
	keyID, ok := header[KeyIDHeader].(string)
	if !ok {
		return nil, &JAPIKeyVerificationError{
			Message: "token header missing key ID",
			Code:    "HeaderValidationError",
		}
	}

	// Extract algorithm from header
	algorithm, ok := header["alg"].(string)
	if !ok {
		return nil, &JAPIKeyVerificationError{
			Message: "token header missing algorithm",
			Code:    "HeaderValidationError",
		}
	}

	// Validate algorithm is RS256
	if algorithm != AlgorithmRS256 {
		return nil, &JAPIKeyVerificationError{
			Message: fmt.Sprintf("invalid algorithm: %s, expected %s", algorithm, AlgorithmRS256),
			Code:    "AlgorithmError",
		}
	}

	// Validate the token structure (header.payload.signature)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, &JAPIKeyVerificationError{
			Message: "invalid token format: expected 3 parts separated by dots",
			Code:    "TokenFormatError",
		}
	}

	// Validate type header if present
	if tokenType, exists := header[TypeHeader].(string); exists {
		if tokenType != TokenType {
			return nil, &JAPIKeyVerificationError{
				Message: fmt.Sprintf("invalid token type: %s, expected %s", tokenType, TokenType),
				Code:    "HeaderValidationError",
			}
		}
	}

	// Validate version format
	version, ok := claims[VersionClaim].(string)
	if !ok {
		return nil, &JAPIKeyVerificationError{
			Message: "token missing version claim",
			Code:    "VersionValidationError",
		}
	}

	// Check if version has the correct prefix
	if !strings.HasPrefix(version, VersionPrefix) {
		return nil, &JAPIKeyVerificationError{
			Message: fmt.Sprintf("invalid version format: %s, expected prefix %s", version, VersionPrefix),
			Code:    "VersionValidationError",
		}
	}

	// Extract version number and validate it's not exceeding max
	versionNum := 0
	if len(version) > len(VersionPrefix) {
		// Extract the number after the prefix
		_, err := fmt.Sscanf(version[len(VersionPrefix):], "%d", &versionNum)
		if err != nil || versionNum > MaxVersion {
			return nil, &JAPIKeyVerificationError{
				Message: fmt.Sprintf("invalid version number: %s", version),
				Code:    "VersionValidationError",
			}
		}
	}

	// Validate issuer
	issuer, ok := claims[IssuerClaim].(string)
	if !ok {
		return nil, &JAPIKeyVerificationError{
			Message: "token missing issuer claim",
			Code:    "IssuerValidationError",
		}
	}

	// Check if issuer starts with the base issuer URL from config
	if config.BaseIssuerURL != "" && !strings.HasPrefix(issuer, config.BaseIssuerURL) {
		return nil, &JAPIKeyVerificationError{
			Message: fmt.Sprintf("invalid issuer: %s, expected to start with %s", issuer, config.BaseIssuerURL),
			Code:    "IssuerValidationError",
		}
	}

	// Validate that key ID in header matches the UUID part of the issuer
	// Assuming the issuer format is like: https://example.com/uuid
	issuerParts := strings.Split(issuer, "/")
	if len(issuerParts) > 0 {
		issuerUUID := issuerParts[len(issuerParts)-1]
		if issuerUUID != keyID {
			return nil, &JAPIKeyVerificationError{
				Message: "key ID in header does not match UUID in issuer",
				Code:    "KeyIDMismatchError",
			}
		}
	}

	// Input sanitization to prevent injection attacks
	// Sanitize issuer
	if strings.Contains(issuer, "../") || strings.Contains(issuer, "..\\") {
		return nil, &JAPIKeyVerificationError{
			Message: "issuer contains invalid path traversal characters",
			Code:    "InjectionError",
		}
	}

	// Sanitize version
	if strings.Contains(version, "<") || strings.Contains(version, ">") {
		return nil, &JAPIKeyVerificationError{
			Message: "version contains invalid characters",
			Code:    "InjectionError",
		}
	}

	// Additional sanitization for other claims can be added here
	for k, v := range claims {
		// Check for potentially dangerous claim names
		if strings.Contains(k, "<") || strings.Contains(k, ">") {
			return nil, &JAPIKeyVerificationError{
				Message: "claim name contains invalid characters",
				Code:    "InjectionError",
			}
		}

		// Check for potentially dangerous claim values
		if strVal, ok := v.(string); ok {
			if strings.Contains(strVal, "<script") || strings.Contains(strVal, "javascript:") {
				return nil, &JAPIKeyVerificationError{
					Message: "claim value contains potential injection",
					Code:    "InjectionError",
				}
			}
		}
	}

	// Validate time-based claims
	// Check expiration (exp)
	if exp, ok := claims[ExpirationClaim].(float64); ok {
		// Check for excessively large numeric values
		if exp > float64(^uint32(0)) { // Check if value is too large
			return nil, &JAPIKeyVerificationError{
				Message: "token contains excessively large numeric value",
				Code:    "NumericValueError",
			}
		}
		if int64(exp) < time.Now().Unix() {
			return nil, &JAPIKeyVerificationError{
				Message: "token has expired",
				Code:    "ExpirationError",
			}
		}
	} else {
		return nil, &JAPIKeyVerificationError{
			Message: "token missing expiration claim",
			Code:    "ExpirationError",
		}
	}

	// Check not-before (nbf) if present
	if nbf, ok := claims[NotBeforeClaim].(float64); ok {
		// Check for excessively large numeric values
		if nbf > float64(^uint32(0)) { // Check if value is too large
			return nil, &JAPIKeyVerificationError{
				Message: "token contains excessively large numeric value",
				Code:    "NumericValueError",
			}
		}
		if int64(nbf) > time.Now().Unix() {
			return nil, &JAPIKeyVerificationError{
				Message: "token is not yet valid",
				Code:    "NotBeforeError",
			}
		}
	}

	// Check issued-at (iat) if present
	if iat, ok := claims[IssuedAtClaim].(float64); ok {
		// Check for excessively large numeric values
		if iat > float64(^uint32(0)) { // Check if value is too large
			return nil, &JAPIKeyVerificationError{
				Message: "token contains excessively large numeric value",
				Code:    "NumericValueError",
			}
		}
		if int64(iat) > time.Now().Unix() {
			return nil, &JAPIKeyVerificationError{
				Message: "token was issued in the future",
				Code:    "IssuedAtError",
			}
		}
	}

	// Retrieve the appropriate cryptographic key using the keyFunc callback
	publicKey, err := keyFunc(keyID)
	if err != nil {
		// Don't expose internal details about why key retrieval failed to prevent information leakage
		return nil, &JAPIKeyVerificationError{
			Message: "failed to retrieve public key",
			Code:    "KeyRetrievalError",
		}
	}

	// Verify the token signature
	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, &JAPIKeyVerificationError{
				Message: fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]),
				Code:    "AlgorithmError",
			}
		}
		return publicKey, nil
	})
	if err != nil {
		// Don't expose internal details about signature verification failure to prevent information leakage
		return nil, &JAPIKeyVerificationError{
			Message: "signature verification failed",
			Code:    "SignatureValidationError",
		}
	}

	if !token.Valid {
		return nil, &JAPIKeyVerificationError{
			Message: "token signature is invalid",
			Code:    "SignatureValidationError",
		}
	}

	// Extract claims again after successful verification
	claims, ok = token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &JAPIKeyVerificationError{
			Message: "failed to parse token claims after verification",
			Code:    "TokenFormatError",
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

	// Additional pre-validation checks can be added here

	return true
}