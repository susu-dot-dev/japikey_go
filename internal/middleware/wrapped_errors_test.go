package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"uuid"

	"github.com/susu-dot-dev/japikey_go/errors"
)

// Drivers commonly wrap their errors; the router must still classify them.
func TestJWKSEndpoint_WrappedDriverErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{"wrapped key not found", fmt.Errorf("query: %w", errors.NewKeyNotFoundError("nf")), http.StatusNotFound, "KeyNotFoundError"},
		{"doubly wrapped key not found", fmt.Errorf("a: %w", fmt.Errorf("b: %w", errors.NewKeyNotFoundError("nf"))), http.StatusNotFound, "KeyNotFoundError"},
		{"wrapped deadline", fmt.Errorf("query: %w", context.DeadlineExceeded), http.StatusServiceUnavailable, "Timeout"},
		{"wrapped database timeout", fmt.Errorf("query: %w", errors.NewDatabaseTimeoutError("t")), http.StatusServiceUnavailable, "InternalError"},
		{"wrapped database unavailable", fmt.Errorf("query: %w", errors.NewDatabaseUnavailableError("u")), http.StatusServiceUnavailable, "InternalError"},
		{"plain error", fmt.Errorf("boom"), http.StatusInternalServerError, "InternalError"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := CreateJWKSRouter(JWKSRouterConfig{
				DB: &MockDatabaseDriver{GetKeyFunc: func(context.Context, string) (*KeyLookupResult, error) {
					return nil, tt.err
				}},
				Timeout: 5 * time.Second,
			})
			if err != nil {
				t.Fatalf("Failed to create handler: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/"+uuid.New().String()+"/.well-known/jwks.json", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantCode)
			}
			var body ErrorResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("Failed to parse error response: %v", err)
			}
			if body.Code != tt.wantBody {
				t.Errorf("code = %q, want %q", body.Code, tt.wantBody)
			}
		})
	}
}
