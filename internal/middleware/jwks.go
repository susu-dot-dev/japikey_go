package middleware

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"
	"uuid"

	japikeyerrors "github.com/susu-dot-dev/japikey_go/errors"
	internaljwks "github.com/susu-dot-dev/japikey_go/internal/jwks"
)

type KeyLookupResult struct {
	// PublicKey is an *ecdsa.PublicKey (P-256) for version 2 keys, or an
	// *rsa.PublicKey for version 1 keys. Both can be stored side by side.
	PublicKey crypto.PublicKey
	Revoked   bool
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type JWKSRouterConfig struct {
	DB            DatabaseDriver
	MaxAgeSeconds int           // 0 = no caching, negative values clamped to 0
	Timeout       time.Duration // 0 = 5-second default applied
}

type DatabaseDriver interface {
	GetKey(ctx context.Context, kid string) (*KeyLookupResult, error)
}

type JWKSHandler struct {
	JWKSRouterConfig
}

func CreateJWKSRouter(config JWKSRouterConfig) (http.Handler, error) {
	if config.DB == nil {
		return nil, japikeyerrors.NewValidationError("DatabaseDriver is required")
	}
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Second
	}
	config.MaxAgeSeconds = clampMaxAge(config.MaxAgeSeconds)

	handler := &JWKSHandler{JWKSRouterConfig: config}

	mux := http.NewServeMux()
	mux.HandleFunc("/{kid}/.well-known/jwks.json", handler.ServeHTTP)

	return mux, nil
}

func clampMaxAge(maxAge int) int {
	if maxAge < 0 {
		return 0
	}
	return maxAge
}

func sendErrorResponse(w http.ResponseWriter, statusCode int, code, message string) {
	// Error responses must never be cached: a transient 404/503 cached by a CDN
	// or proxy for max-age would otherwise extend an outage or hide a valid key.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(ErrorResponse{Code: code, Message: message}); err != nil {
		log.Printf("[JWKS] Error encoding response: %v", err)
	}
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.Timeout)
	defer cancel()

	w.Header().Set("Content-Type", "application/json")

	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			sendErrorResponse(w, http.StatusServiceUnavailable, "Timeout", "Request timeout")
			return
		}
	default:
	}

	// Validate the untrusted path value before it reaches the database driver.
	// uuid.Parse also accepts non-canonical forms (uppercase, urn:uuid:, braces,
	// no dashes), so pass the canonical string form to the driver rather than the
	// raw input. This keeps arbitrary attacker-controlled strings out of driver
	// queries and keeps lookups, caches and revocation keyed consistently.
	kidUUID, err := uuid.Parse(r.PathValue("kid"))
	if err != nil || kidUUID == uuid.Nil() {
		sendErrorResponse(w, http.StatusNotFound, "KeyNotFoundError", "API key not found")
		return
	}
	kid := kidUUID.String()

	result, err := h.DB.GetKey(ctx, kid)
	if err != nil {
		// Drivers commonly wrap errors (fmt.Errorf("...: %w", err)), so match with
		// errors.Is / errors.As rather than == or a type switch.
		var (
			notFoundErr    *japikeyerrors.KeyNotFoundError
			timeoutErr     *japikeyerrors.DatabaseTimeoutError
			unavailableErr *japikeyerrors.DatabaseUnavailableError
		)
		switch {
		case errors.As(err, &notFoundErr):
			sendErrorResponse(w, http.StatusNotFound, "KeyNotFoundError", "API key not found")
		case errors.Is(err, context.DeadlineExceeded):
			sendErrorResponse(w, http.StatusServiceUnavailable, "Timeout", "Request timeout")
		case errors.Is(err, context.Canceled):
			// The client went away (or the server is shutting down). That is not
			// a database failure: do not log it as one. The status is mostly
			// for tests and proxies, as nobody is left to read the response.
			sendErrorResponse(w, http.StatusServiceUnavailable, "Canceled", "Request canceled")
		case errors.As(err, &timeoutErr):
			log.Printf("[JWKS] Database timeout: %v", err)
			sendErrorResponse(w, http.StatusServiceUnavailable, "InternalError", "Database temporarily unavailable")
		case errors.As(err, &unavailableErr):
			log.Printf("[JWKS] Database unavailable: %v", err)
			sendErrorResponse(w, http.StatusServiceUnavailable, "InternalError", "Database temporarily unavailable")
		default:
			log.Printf("[JWKS] Database error: %v", err)
			sendErrorResponse(w, http.StatusInternalServerError, "InternalError", "Internal server error")
		}
		return
	}

	if result == nil || isNilPublicKey(result.PublicKey) || result.Revoked {
		sendErrorResponse(w, http.StatusNotFound, "KeyNotFoundError", "API key not found")
		return
	}

	jwks, err := internaljwks.NewJWKS(result.PublicKey, kidUUID)
	if err != nil {
		log.Printf("[JWKS] Error generating JWKS: %v", err)
		sendErrorResponse(w, http.StatusInternalServerError, "InternalError", "Internal server error")
		return
	}

	jsonData, err := jwks.MarshalJSON()
	if err != nil {
		log.Printf("[JWKS] Error marshaling JWKS: %v", err)
		sendErrorResponse(w, http.StatusInternalServerError, "InternalError", "Internal server error")
		return
	}

	// Only successful responses are cacheable
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(h.MaxAgeSeconds))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(jsonData); err != nil {
		log.Printf("[JWKS] Error writing response: %v", err)
	}
}

// isNilPublicKey reports whether key is nil, including a typed nil pointer held
// in the interface (for example a driver returning a nil *ecdsa.PublicKey for a
// missing row), which must be answered as "not found" like any other absent key.
func isNilPublicKey(key crypto.PublicKey) bool {
	switch k := key.(type) {
	case nil:
		return true
	case *rsa.PublicKey:
		return k == nil
	case *ecdsa.PublicKey:
		return k == nil
	}
	return false
}
