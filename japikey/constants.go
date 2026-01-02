package japikey

// JAPIKey constants
const (
	// AlgorithmRS256 is the required algorithm for JAPIKey tokens
	AlgorithmRS256 = "RS256"

	// MaxTokenSize is the maximum allowed token size to prevent resource exhaustion (4KB)
	MaxTokenSize = 4096

	// VersionClaim is the JWT claim key for the version identifier
	VersionClaim = "ver"

	// IssuerClaim is the JWT claim key for the issuer
	IssuerClaim = "iss"

	// KeyIDHeader is the JWT header key for the key identifier
	KeyIDHeader = "kid"
)
