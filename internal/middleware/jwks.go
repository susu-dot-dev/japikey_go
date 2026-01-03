package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/susu-dot-dev/japikey/errors"
	internaljwks "github.com/susu-dot-dev/japikey/internal/jwks"
)

type KeyLookupResult struct {
	PublicKey *rsa.PublicKey
	Revoked   bool
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type DatabaseDriver interface {
	GetKey(ctx context.Context, kid string) (*KeyLookupResult, error)
}

type JWKSHandler struct {
	db            DatabaseDriver
	maxAgeSeconds int
}

func CreateJWKSRouter(db DatabaseDriver, maxAgeSeconds int) http.Handler {
	clampedMaxAge := clampMaxAge(maxAgeSeconds)

	handler := &JWKSHandler{
		db:            db,
		maxAgeSeconds: clampedMaxAge,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{kid}/.well-known/jwks.json", handler.ServeHTTP)

	return mux
}

func clampMaxAge(maxAge int) int {
	if maxAge < 0 {
		return 0
	}
	return maxAge
}

func sendErrorResponse(w http.ResponseWriter, statusCode int, code, message string) {
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(ErrorResponse{Code: code, Message: message}); err != nil {
		log.Printf("[JWKS] Error encoding response: %v", err)
	}
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(h.maxAgeSeconds))

	kid := r.PathValue("kid")

	ctx := r.Context()

	result, err := h.db.GetKey(ctx, kid)
	if err != nil {
		switch err.(type) {
		case *errors.KeyNotFoundError:
			sendErrorResponse(w, http.StatusNotFound, "KeyNotFoundError", "API key not found")
		case *errors.DatabaseTimeoutError:
			log.Printf("[JWKS] Database timeout: %v", err)
			sendErrorResponse(w, http.StatusServiceUnavailable, "InternalError", "Database temporarily unavailable")
		case *errors.DatabaseUnavailableError:
			log.Printf("[JWKS] Database unavailable: %v", err)
			sendErrorResponse(w, http.StatusServiceUnavailable, "InternalError", "Database temporarily unavailable")
		default:
			log.Printf("[JWKS] Database error: %v", err)
			sendErrorResponse(w, http.StatusInternalServerError, "InternalError", "Internal server error")
		}
		return
	}

	if result == nil || result.PublicKey == nil || result.Revoked {
		sendErrorResponse(w, http.StatusNotFound, "KeyNotFoundError", "API key not found")
		return
	}

	kidUUID, err := uuid.Parse(kid)
	if err != nil {
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

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(jsonData); err != nil {
		log.Printf("[JWKS] Error writing response: %v", err)
	}
}
