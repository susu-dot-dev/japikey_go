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

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(h.maxAgeSeconds))

	kid := r.PathValue("kid")

	ctx := r.Context()

	result, err := h.db.GetKey(ctx, kid)
	if err != nil {
		if _, ok := err.(*errors.KeyNotFoundError); ok {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{
				Code:    "KeyNotFoundError",
				Message: "API key not found",
			})
			return
		}
		if _, ok := err.(*errors.DatabaseTimeoutError); ok {
			log.Printf("[JWKS] Database timeout: %v", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(ErrorResponse{
				Code:    "InternalError",
				Message: "Database temporarily unavailable",
			})
			return
		}
		if _, ok := err.(*errors.DatabaseUnavailableError); ok {
			log.Printf("[JWKS] Database unavailable: %v", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(ErrorResponse{
				Code:    "InternalError",
				Message: "Database temporarily unavailable",
			})
			return
		}
		log.Printf("[JWKS] Database error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{
			Code:    "InternalError",
			Message: "Internal server error",
		})
		return
	}

	if result == nil || result.PublicKey == nil || result.Revoked {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{
			Code:    "KeyNotFoundError",
			Message: "API key not found",
		})
		return
	}

	kidUUID, err := uuid.Parse(kid)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{
			Code:    "KeyNotFoundError",
			Message: "API key not found",
		})
		return
	}

	jwks, err := internaljwks.NewJWKS(result.PublicKey, kidUUID)
	if err != nil {
		log.Printf("[JWKS] Error generating JWKS: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{
			Code:    "InternalError",
			Message: "Internal server error",
		})
		return
	}

	jsonData, err := jwks.MarshalJSON()
	if err != nil {
		log.Printf("[JWKS] Error marshaling JWKS: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{
			Code:    "InternalError",
			Message: "Internal server error",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}
