package japikey

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"runtime/debug"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	japikeyerrors "github.com/susu-dot-dev/japikey/errors"
	"github.com/susu-dot-dev/japikey/internal/jwks"
)

// JWKCallback is a function that retrieves the JWK (JSON Web Key) given the key ID.
// This function is used during token verification to get the appropriate public key
// for signature verification.
//
// The context carries the deadline derived from VerifyConfig.Timeout (and any
// deadline or cancellation on the context passed to Verify). Implementations
// must honor it for any I/O they perform: the callback is called synchronously
// and trusted to return promptly once ctx is done. A callback that ignores ctx
// blocks Verify (and its caller) for as long as it runs; Verify does not
// abandon it in the background.
//
// The callback can be reached by forged tokens: any token with a well-formed
// header and claims for the configured issuer triggers a lookup, whether or not
// its signature is genuine. It should be cheap for unknown key IDs, and
// callers that need to cap concurrent lookups should bound their own
// concurrency or enforce a limit inside the callback.
//
// Implementations should return a *KeyNotFoundError when the key does not exist
// (or is revoked). sql.ErrNoRows and fs.ErrNotExist (also when wrapped) are
// accepted as equivalent, so that an unknown key is never answered differently
// from a revoked one. Any other error is treated as a retrieval failure
// (*InternalError). A nil key with a nil error is treated as key-not-found. The returned key must be an RSA
// key of 2048 to 4096 bits with a sane exponent (see jwks.ValidatePublicKey),
// or the token is rejected.
type JWKCallback func(ctx context.Context, keyID uuid.UUID) (*rsa.PublicKey, error)

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
	// BaseIssuerURL is the base URL for the issuer that should be present in the
	// token. It must satisfy the same rules as Config.Issuer: an absolute https
	// URL with a host, no user info, query or fragment, in canonical form,
	// ending in at most one "/". An invalid value makes Verify return an
	// *InternalError.
	BaseIssuerURL string

	// AllowInsecureHTTP permits an http:// BaseIssuerURL. It exists for local
	// development and tests only; never enable it in production.
	AllowInsecureHTTP bool

	// Timeout bounds the time spent retrieving the cryptographic key from the
	// callback function. A value <= 0 means DefaultKeyLookupTimeout is used. It
	// is passed to the callback as a context deadline, so it only takes effect
	// if the callback honors its context (see JWKCallback).
	Timeout time.Duration

	// Audience is the expected audience ("aud" claim). When non-empty, the token
	// must list this value in its audience claim. When empty, the audience is not
	// checked, so services that share an issuer base URL should set it to avoid
	// accepting each other's keys.
	Audience string
}

// validateVersion validates the version claim from MapClaims.
func validateVersion(claims jwt.MapClaims) error {
	versionRaw, ok := claims[VersionClaim]
	if !ok {
		return japikeyerrors.NewValidationError("token missing version claim")
	}

	version, ok := versionRaw.(string)
	if !ok {
		return japikeyerrors.NewValidationError("token version claim must be a string")
	}

	if version != "japikey-v1" {
		// Fixed message: never echo attacker-controlled token contents into errors
		return japikeyerrors.NewValidationError("token has an unsupported version")
	}

	return nil
}

// validateIssuer validates that the issuer claim exactly matches baseIssuerURL/keyID.
// baseIssuerURL is required for security - issuer validation is mandatory.
func validateIssuer(issuer string, baseIssuerURL string, keyID uuid.UUID) error {
	if baseIssuerURL == "" {
		return japikeyerrors.NewInternalError("base issuer URL is required for issuer validation")
	}

	if issuer == "" {
		return japikeyerrors.NewValidationError("token missing issuer claim")
	}

	// Expected issuer is exactly baseIssuerURL/keyID. Shared with NewJAPIKey so
	// minting and verification cannot disagree.
	expectedIssuer := BuildIssuer(baseIssuerURL, keyID)

	// Exact string match
	if issuer != expectedIssuer {
		// Fixed message: never echo attacker-controlled token contents into errors
		return japikeyerrors.NewValidationError("token issuer is invalid")
	}

	return nil
}

// extractKeyIDFromHeader extracts and validates the key ID from the token header.
func extractKeyIDFromHeader(header map[string]interface{}) (uuid.UUID, error) {
	keyIDRaw, ok := header[KeyIDHeader]
	if !ok {
		return uuid.Nil(), japikeyerrors.NewValidationError("token header missing key ID")
	}

	keyIDStr, ok := keyIDRaw.(string)
	if !ok {
		return uuid.Nil(), japikeyerrors.NewValidationError("token header contains invalid key ID type")
	}

	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		return uuid.Nil(), japikeyerrors.NewValidationError("token header contains invalid key ID format")
	}

	// The nil UUID is never a valid key ID (NewJWKS rejects it too); reject it
	// before it can trigger a key lookup.
	if keyID == uuid.Nil() {
		return uuid.Nil(), japikeyerrors.NewValidationError("token header contains invalid key ID")
	}

	return keyID, nil
}

// validateIssuedAt requires the iat claim to be present, a valid numeric date,
// and not further in the future than IssuedAtLeeway. The leeway applies to iat
// only; exp and nbf are checked with none.
func validateIssuedAt(claims jwt.MapClaims, now time.Time) error {
	if _, ok := claims["iat"]; !ok {
		return japikeyerrors.NewValidationError("token missing issued-at claim")
	}

	iat, err := claims.GetIssuedAt()
	if err != nil || iat == nil {
		return japikeyerrors.NewValidationError("token issued-at claim is invalid")
	}

	if iat.After(now.Add(IssuedAtLeeway)) {
		return japikeyerrors.NewValidationError("token was issued in the future")
	}

	return nil
}

// validateTimeClaims checks exp (required) and nbf (optional) with no leeway.
// It is used on the unverified token so that an expired or not-yet-valid
// token is rejected before any key lookup, and the parser repeats the same
// checks once the signature has been verified. The error for an expired token
// is a *TokenExpiredError; callers only see it once the token is also known to
// be well formed for this issuer, and Verify wraps it in an UnauthorizedError.
func validateTimeClaims(claims jwt.MapClaims, now time.Time) error {
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return japikeyerrors.NewValidationError("token expiration claim is missing or invalid")
	}
	if !now.Before(exp.Time) {
		return japikeyerrors.NewTokenExpiredError("token has expired")
	}

	nbf, err := claims.GetNotBefore()
	if err != nil {
		return japikeyerrors.NewValidationError("token not-before claim is invalid")
	}
	if nbf != nil && now.Before(nbf.Time) {
		return japikeyerrors.NewValidationError("token is not yet valid")
	}

	return nil
}

// validateSubject requires the sub claim to be a non-empty string. Consumers
// treat sub as the identity the key was issued to, so a token without one
// must never authenticate.
func validateSubject(claims jwt.MapClaims) error {
	subRaw, ok := claims["sub"]
	if !ok {
		return japikeyerrors.NewValidationError("token missing subject claim")
	}
	sub, ok := subRaw.(string)
	if !ok || sub == "" {
		return japikeyerrors.NewValidationError("token subject claim must be a non-empty string")
	}
	return nil
}

// validateJAPIKeyClaims validates JAPIKey-specific requirements on the claims.
func validateJAPIKeyClaims(claims jwt.MapClaims, baseIssuerURL string, keyID uuid.UUID) error {
	if err := validateVersion(claims); err != nil {
		return err
	}

	if err := validateIssuedAt(claims, time.Now()); err != nil {
		return err
	}

	if err := validateSubject(claims); err != nil {
		return err
	}

	issuer, err := claims.GetIssuer()
	if err != nil {
		return japikeyerrors.NewValidationError("Invalid issuer")
	}

	if err := validateIssuer(issuer, baseIssuerURL, keyID); err != nil {
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

// checkTokenFormat validates that the token is exactly three non-empty, dot-separated
// segments consisting only of base64url characters (A-Z a-z 0-9 - _), with no padding,
// whitespace or line breaks. The base64 decoder used by the JWT library silently skips
// CR/LF (even in strict mode), which would otherwise let one token be written as many
// different strings. Rejecting them up front means exactly one string is accepted per token.
func checkTokenFormat(tokenString string) error {
	segments, segmentLen := 0, 0
	for i := 0; i < len(tokenString); i++ {
		c := tokenString[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			segmentLen++
		case c == '.':
			if segmentLen == 0 {
				return japikeyerrors.NewValidationError("token is malformed")
			}
			segments++
			segmentLen = 0
		default:
			return japikeyerrors.NewValidationError("token is malformed")
		}
	}
	if segments != 2 || segmentLen == 0 {
		return japikeyerrors.NewValidationError("token is malformed")
	}
	return nil
}

// lookupKey invokes the callback with a deadline-bound context and converts the
// outcome into a usable public key or an error.
//
// The callback runs synchronously on the caller's goroutine. The callback is
// trusted code supplied by the application, and it must honor ctx: that is how
// Timeout and cancellation take effect, exactly as with database/sql or
// net/http. A callback that ignores ctx makes Verify block for as long as the
// callback does; that is a bug in the callback, not something Verify can
// paper over without abandoning goroutines.
//
// Running synchronously is also what gives callers backpressure. The number of
// concurrent lookups is bounded by the number of concurrent Verify calls, so a
// slow database slows its callers down instead of accumulating unbounded
// background work. Callers that need a tighter cap should bound their own
// concurrency or have the callback enforce one (for example a connection pool
// limit).
//
// Verify only calls lookupKey for tokens that passed every check that does not
// need the key (see precheckToken and validateTimeClaims). That does not mean
// the token is genuine: anyone can mint a token with a random key ID and a
// garbage signature that passes those checks, so forged tokens do reach the
// callback.
//
// The returned key is checked with jwks.ValidatePublicKey, the same check
// applied when building a JWKS, so a weak (<2048-bit) or oversized (>4096-bit)
// key is refused whatever source the callback got it from.
func lookupKey(ctx context.Context, keyFunc JWKCallback, keyID uuid.UUID) (key *rsa.PublicKey, err error) {
	// Do not start I/O on behalf of a caller that has already gone away
	if ctx.Err() != nil {
		return nil, japikeyerrors.NewDatabaseTimeoutError("key retrieval timed out")
	}

	key, err = callKeyFunc(ctx, keyFunc, keyID)

	// A result that arrives after the deadline or cancellation is not trusted,
	// whatever the callback returned: report the timeout, consistently.
	if ctx.Err() != nil {
		return nil, japikeyerrors.NewDatabaseTimeoutError("key retrieval timed out")
	}

	if err != nil {
		if isNotFound(err) {
			var notFound *japikeyerrors.KeyNotFoundError
			if errors.As(err, &notFound) {
				return nil, notFound
			}
			return nil, japikeyerrors.NewKeyNotFoundError("public key not found")
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, japikeyerrors.NewDatabaseTimeoutError("key retrieval timed out")
		}
		var internalErr *japikeyerrors.InternalError
		if errors.As(err, &internalErr) {
			return nil, internalErr
		}
		return nil, japikeyerrors.NewInternalError("failed to retrieve public key")
	}
	if key == nil || key.N == nil {
		return nil, japikeyerrors.NewKeyNotFoundError("public key not found")
	}
	if err := jwks.ValidatePublicKey(key); err != nil {
		return nil, japikeyerrors.NewValidationError("public key does not meet requirements")
	}
	return key, nil
}

// callKeyFunc calls the callback and converts a panic into an InternalError so
// a buggy callback cannot crash the process through Verify. The panic value and
// stack are logged (never returned) so the bug stays diagnosable, as it would
// be with net/http's own recovery.
func callKeyFunc(ctx context.Context, keyFunc JWKCallback, keyID uuid.UUID) (key *rsa.PublicKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[japikey] key callback panicked: %v\n%s", r, debug.Stack())
			key, err = nil, japikeyerrors.NewInternalError("key retrieval failed")
		}
	}()
	return keyFunc(ctx, keyID)
}

// isNotFound reports whether a callback error means "this key does not exist".
// Besides *KeyNotFoundError it accepts the standard library's own not-found
// sentinels (sql.ErrNoRows, fs.ErrNotExist), because returning one of those
// unwrapped is the most likely integration mistake. Treating it as an internal
// error would answer unknown keys with a server error while revoked or valid
// ones get a 401, which reopens the key-existence oracle. Any other error stays
// an internal error: a failing database must not look like a missing key.
func isNotFound(err error) bool {
	var notFound *japikeyerrors.KeyNotFoundError
	return errors.As(err, &notFound) || errors.Is(err, sql.ErrNoRows) || errors.Is(err, fs.ErrNotExist)
}

// precheckToken runs every check that does not need the public key, on the
// decoded but not yet verified token: size, strict format, kid, version,
// issued-at, subject and issuer. It returns the key ID from the header and the
// decoded (unverified) claims. Expiry is deliberately not checked here so that
// ShouldVerify, which only routes tokens, keeps accepting expired ones.
//
// Verify runs it before any key lookup, so malformed tokens and tokens that
// are not addressed to this issuer never reach the callback. It cannot tell a
// genuine token from a forged one: a token with a random key ID, matching
// claims and a garbage signature passes, and Verify then looks the key up.
// The same claim checks run again after the signature is verified.
func precheckToken(tokenString string, baseIssuerURL string) (uuid.UUID, jwt.MapClaims, error) {
	// FR-020: Enforce maximum token size limit BEFORE any parsing
	if err := checkTokenSize(tokenString); err != nil {
		return uuid.Nil(), nil, err
	}

	// Reject anything that is not plain base64url before parsing (see checkTokenFormat)
	if err := checkTokenFormat(tokenString); err != nil {
		return uuid.Nil(), nil, err
	}

	parser := jwt.NewParser(jwt.WithStrictDecoding())
	claims := jwt.MapClaims{}
	token, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		return uuid.Nil(), nil, japikeyerrors.NewValidationError("token is malformed")
	}

	// RFC 7515 4.1.11: a verifier must reject a token whose "crit" header lists
	// extensions it does not understand, and japikey understands none. The
	// library does not enforce this itself.
	if _, ok := token.Header["crit"]; ok {
		return uuid.Nil(), nil, japikeyerrors.NewValidationError("token uses unsupported critical header extensions")
	}

	// FR-027: Validate key ID is present and properly formatted
	keyID, err := extractKeyIDFromHeader(token.Header)
	if err != nil {
		return uuid.Nil(), nil, err
	}

	if err := validateJAPIKeyClaims(claims, baseIssuerURL, keyID); err != nil {
		return uuid.Nil(), nil, err
	}

	return keyID, claims, nil
}

// classifyParseError maps an error from the verifying JWT parser to one of our
// typed errors with a fixed message (FR-028: never surface library messages).
func classifyParseError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return japikeyerrors.NewTokenExpiredError("token has expired")
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return japikeyerrors.NewValidationError("token is not yet valid")
	case errors.Is(err, jwt.ErrTokenMalformed):
		return japikeyerrors.NewValidationError("token is malformed")
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return japikeyerrors.NewValidationError("token audience is invalid")
	}
	// Our own typed errors from the keyfunc. jwt wraps keyfunc errors, so use
	// errors.As rather than a direct type assertion.
	var validationErr *japikeyerrors.ValidationError
	if errors.As(err, &validationErr) {
		return validationErr
	}
	var notFoundErr *japikeyerrors.KeyNotFoundError
	if errors.As(err, &notFoundErr) {
		return notFoundErr
	}
	return japikeyerrors.NewValidationError("signature verification failed")
}

// Verify takes in the JWT string, the config, as well as a callback function which retrieves the JWK if given the key id.
// It either returns the validated claims, or an appropriate error.
//
// Errors:
//   - *UnauthorizedError for every rejected token, whatever the reason
//     (malformed, wrong version/issuer/subject, unknown or revoked key, weak
//     key, bad signature, expired, wrong audience, ...). Its message is fixed,
//     and callers must send the same response (e.g. HTTP 401) for all of them.
//     The specific cause is available through errors.As (for example
//     *KeyNotFoundError or *TokenExpiredError) for logging only; do not vary
//     the response on it, or callers can probe which key IDs exist.
//   - *DatabaseTimeoutError when key retrieval times out or ctx is cancelled.
//   - *InternalError for configuration problems (nil callback, invalid
//     BaseIssuerURL) or a failing/panicking callback.
//
// Every check that does not need the key (size, format, kid, version,
// issued-at, subject, issuer, exp, nbf) runs on the unverified token before the
// callback is invoked, and again after the signature has been verified. A
// *TokenExpiredError cause therefore only means "this token claims to have
// expired"; it is not proof of a valid signature.
//
// The ctx bounds the whole key retrieval; config.Timeout (default
// DefaultKeyLookupTimeout) is applied on top of any deadline already on ctx.
// The callback is invoked synchronously and must honor that context; Verify
// blocks until it returns. Concurrent lookups are therefore bounded by the
// caller's own concurrency. Tokens that pass the key-free checks reach the
// callback even if their signature is forged.
func Verify(ctx context.Context, tokenString string, config VerifyConfig, keyFunc JWKCallback) (*VerificationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if keyFunc == nil {
		return nil, japikeyerrors.NewInternalError("key callback is required")
	}
	// A bad base issuer is a server configuration problem, not a token problem
	if err := validateBaseIssuerURL(config.BaseIssuerURL, config.AllowInsecureHTTP); err != nil {
		return nil, japikeyerrors.NewInternalError("base issuer URL is invalid: " + err.Error())
	}

	// Reject everything we can without the key, before any I/O
	keyID, unverified, err := precheckToken(tokenString, config.BaseIssuerURL)
	if err != nil {
		return nil, japikeyerrors.NewUnauthorizedError(err)
	}
	// Expired and not-yet-valid tokens must not cost a key lookup either. These
	// claims are still unverified here; the parser checks them again below,
	// after the signature has been verified.
	if err := validateTimeClaims(unverified, time.Now()); err != nil {
		return nil, japikeyerrors.NewUnauthorizedError(err)
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = DefaultKeyLookupTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// FR-014: Use golang-jwt library for parsing and validation
	// FR-010, FR-022: Validate algorithm is exactly RS256 (checked by the
	// parser before the keyfunc runs, so a wrong alg never triggers a lookup)
	// FR-016: Validate exp claim is present and not expired (no clock skew)
	// FR-017: Validate nbf if present (no clock skew)
	// FR-018: Validate iat is present and not in the future (IssuedAtLeeway);
	// done in validateJAPIKeyClaims, because the parser's leeway cannot be
	// applied to iat alone
	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{AlgorithmRS256}),
		jwt.WithExpirationRequired(),
		// Reject non-canonical base64url (non-zero trailing bits), so a token's
		// signature segment has exactly one valid encoding
		jwt.WithStrictDecoding(),
	}
	if config.Audience != "" {
		parserOptions = append(parserOptions, jwt.WithAudience(config.Audience))
	}
	parser := jwt.NewParser(parserOptions...)

	claims := jwt.MapClaims{}
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Defence in depth: the header was already checked by precheckToken and
		// must still name the same key.
		headerKeyID, err := extractKeyIDFromHeader(token.Header)
		if err != nil {
			return nil, err
		}
		if headerKeyID != keyID {
			return nil, japikeyerrors.NewValidationError("token header contains invalid key ID")
		}

		// Retrieve the public key using the callback (bounded by ctx)
		publicKey, err := lookupKey(ctx, keyFunc, keyID)
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	})

	if err != nil {
		// Server-side failures are reported as such: they say nothing about the
		// token or about whether its key exists.
		var timeoutErr *japikeyerrors.DatabaseTimeoutError
		if errors.As(err, &timeoutErr) {
			return nil, timeoutErr
		}
		var internalErr *japikeyerrors.InternalError
		if errors.As(err, &internalErr) {
			return nil, internalErr
		}
		return nil, japikeyerrors.NewUnauthorizedError(classifyParseError(err))
	}

	if !token.Valid {
		return nil, japikeyerrors.NewUnauthorizedError(japikeyerrors.NewValidationError("token signature is invalid"))
	}

	// Validate JAPIKey-specific requirements again, on the verified claims
	if err := validateJAPIKeyClaims(claims, config.BaseIssuerURL, keyID); err != nil {
		return nil, japikeyerrors.NewUnauthorizedError(err)
	}

	// Return the validated claims (preserving all custom claims)
	result := &VerificationResult{
		Claims: claims,
		KeyID:  keyID,
	}

	return result, nil
}

// ShouldVerify is a pre-validation function that checks if a token has the correct format before full verification.
// It decodes the token without verification and validates size, format, kid,
// version, issued-at, subject and issuer: the same checks Verify runs before
// looking up the key.
// Based on the JavaScript implementation: https://github.com/susu-dot-dev/japikey_js/blob/main/packages/authenticate/src/index.ts
//
// baseIssuer must pass the same URL checks as VerifyConfig.BaseIssuerURL,
// except that http is accepted as well as https: ShouldVerify only routes
// tokens, and Verify enforces the scheme (see VerifyConfig.AllowInsecureHTTP).
func ShouldVerify(tokenString string, baseIssuer string) bool {
	if validateBaseIssuerURL(baseIssuer, true) != nil {
		return false
	}
	_, _, err := precheckToken(tokenString, baseIssuer)
	return err == nil
}
