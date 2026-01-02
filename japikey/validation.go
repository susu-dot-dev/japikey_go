package japikey

import (
	"strings"
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
		return &JAPIKeyVerificationError{
			Message: "token header missing algorithm",
			Code:    "HeaderValidationError",
		}
	}

	if algorithm != AlgorithmRS256 {
		return &JAPIKeyVerificationError{
			Message: "invalid algorithm: " + algorithm + ", expected " + AlgorithmRS256,
			Code:    "AlgorithmError",
		}
	}

	// Check if key ID is present
	keyID, ok := header[KeyIDHeader].(string)
	if !ok || keyID == "" {
		return &JAPIKeyVerificationError{
			Message: "token header missing key ID",
			Code:    "HeaderValidationError",
		}
	}

	return nil
}

// ValidatePayload validates the payload claims (ver and iss)
func ValidatePayload(claims map[string]interface{}) error {
	// Check if version is present
	version, ok := claims[VersionClaim].(string)
	if !ok {
		return &JAPIKeyVerificationError{
			Message: "token missing version claim",
			Code:    "PayloadValidationError",
		}
	}

	// Check if version has the correct prefix
	if !strings.HasPrefix(version, VersionPrefix) {
		return &JAPIKeyVerificationError{
			Message: "invalid version format: " + version + ", expected prefix " + VersionPrefix,
			Code:    "VersionValidationError",
		}
	}

	// Check if issuer is present
	issuer, ok := claims[IssuerClaim].(string)
	if !ok {
		return &JAPIKeyVerificationError{
			Message: "token missing issuer claim",
			Code:    "IssuerValidationError",
		}
	}

	if issuer == "" {
		return &JAPIKeyVerificationError{
			Message: "token issuer claim is empty",
			Code:    "IssuerValidationError",
		}
	}

	return nil
}