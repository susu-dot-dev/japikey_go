package japikey

// JAPIKey constants
const (
	// AlgorithmRS256 is the required algorithm for JAPIKey tokens
	AlgorithmRS256 = "RS256"
	
	// VersionPrefix is the prefix for JAPIKey version identifiers
	VersionPrefix = "japikey-v"
	
	// MaxTokenSize is the maximum allowed token size to prevent resource exhaustion (4KB)
	MaxTokenSize = 4096
	
	// MaxVersion is the maximum allowed version number
	MaxVersion = 1
	
	// VersionClaim is the JWT claim key for the version identifier
	VersionClaim = "ver"
	
	// IssuerClaim is the JWT claim key for the issuer
	IssuerClaim = "iss"
	
	// ExpirationClaim is the JWT claim key for the expiration time
	ExpirationClaim = "exp"
	
	// NotBeforeClaim is the JWT claim key for the not-before time
	NotBeforeClaim = "nbf"
	
	// IssuedAtClaim is the JWT claim key for the issued-at time
	IssuedAtClaim = "iat"
	
	// KeyIDHeader is the JWT header key for the key identifier
	KeyIDHeader = "kid"
	
	// TypeHeader is the JWT header key for the token type
	TypeHeader = "typ"
	
	// TokenType is the expected value for the 'typ' header
	TokenType = "JWT"
)
