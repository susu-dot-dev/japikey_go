package japikey

import (
	"strings"

	"github.com/susu-dot-dev/japikey/errors"
)

// ValidateTokenFormat validates the basic JWT format (header.payload.signature)
func ValidateTokenFormat(tokenString string) bool {
	parts := strings.Split(tokenString, ".")
	return len(parts) == 3
}

// ValidateHeader validates the header fields (alg and kid)
func ValidateHeader(header map[string]interface{}) error {
	// Check if algorithm is present and is RS256
	algorithm, ok := header["alg"].(string)
	if !ok {
		return errors.NewValidationError("token header missing algorithm")
	}

	if algorithm != AlgorithmRS256 {
		return errors.NewValidationError("invalid algorithm: " + algorithm + ", expected " + AlgorithmRS256)
	}

	// Check if key ID is present
	keyID, ok := header[KeyIDHeader].(string)
	if !ok || keyID == "" {
		return errors.NewValidationError("token header missing key ID")
	}

	return nil
}

// ValidatePayload validates the payload claims (ver and iss)
func ValidatePayload(claims map[string]interface{}) error {
	// Check if version is present
	version, ok := claims[VersionClaim].(string)
	if !ok {
		return errors.NewValidationError("token missing version claim")
	}

	// Check if version has the correct prefix
	if !strings.HasPrefix(version, VersionPrefix) {
		return errors.NewValidationError("invalid version format: " + version + ", expected prefix " + VersionPrefix)
	}

	// Check if issuer is present
	issuer, ok := claims[IssuerClaim].(string)
	if !ok {
		return errors.NewValidationError("token missing issuer claim")
	}

	if issuer == "" {
		return errors.NewValidationError("token issuer claim is empty")
	}

	return nil
}
