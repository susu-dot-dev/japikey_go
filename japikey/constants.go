package japikey

import "time"

// JAPIKey constants
const (
	// AlgorithmRS256 is the required algorithm for JAPIKey tokens
	AlgorithmRS256 = "RS256"

	// MaxTokenSize is the maximum allowed token size to prevent resource exhaustion (4KB)
	MaxTokenSize = 4096

	// DefaultKeyLookupTimeout is applied to key retrieval when VerifyConfig.Timeout is not set
	DefaultKeyLookupTimeout = 5 * time.Second

	// MinKeyLifetime is the minimum time a new key must remain valid. exp is
	// truncated to whole seconds, so anything shorter than this can mint a key
	// that is already expired (or expires before it can reasonably be used).
	MinKeyLifetime = 5 * time.Second

	// IssuedAtLeeway is the clock skew tolerated on the "iat" claim only. A key
	// that is minted on one host and used immediately on another whose clock is
	// slightly behind would otherwise be rejected as issued in the future.
	// exp and nbf get no leeway.
	IssuedAtLeeway = 30 * time.Second

	// VersionClaim is the JWT claim key for the version identifier
	VersionClaim = "ver"

	// IssuerClaim is the JWT claim key for the issuer
	IssuerClaim = "iss"

	// KeyIDHeader is the JWT header key for the key identifier
	KeyIDHeader = "kid"
)
