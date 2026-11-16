package japikey

import "time"

// JAPIKey constants
const (
	// AlgorithmRS256 is the signing algorithm of version 1 keys (no longer minted)
	AlgorithmRS256 = "RS256"

	// AlgorithmES256 is the signing algorithm of version 2 keys (ECDSA P-256 with
	// SHA-256), the version NewJAPIKey mints
	AlgorithmES256 = "ES256"

	// CurrentVersion is the key version NewJAPIKey mints
	CurrentVersion = 2

	// VersionPrefix precedes the version number in the "ver" claim
	VersionPrefix = "japikey-v"

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

// algorithmByVersion gives the signing algorithm of every supported key
// version. The version claim of a token selects the one algorithm it is
// verified with, never the token's own "alg" header, so a token cannot pick
// its algorithm. Version 0 and unknown versions are not present, so they are
// rejected.
//
//   - v1: RS256. No longer minted. Their JWKs have no "ver" or "alg" members.
//   - v2: ES256. Their JWKs carry "ver": 2 and "alg": "ES256".
var algorithmByVersion = map[int]string{
	1: AlgorithmRS256,
	2: AlgorithmES256,
}
