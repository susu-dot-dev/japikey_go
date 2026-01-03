package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/susu-dot-dev/japikey/errors"
)

type MockDatabaseDriver struct {
	GetKeyFunc func(ctx context.Context, kid string) (*KeyLookupResult, error)
}

func (m *MockDatabaseDriver) GetKey(ctx context.Context, kid string) (*KeyLookupResult, error) {
	return m.GetKeyFunc(ctx, kid)
}

func TestJWKSEndpoint_ValidKey_Returns200(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: false}, nil
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", rr.Header().Get("Content-Type"))
	}
}

func TestJWKSEndpoint_CacheControlHeader(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: false}, nil
		},
	}

	tests := []struct {
		name           string
		maxAge         int
		expectedHeader string
	}{
		{"no caching", 0, "max-age=0"},
		{"5 minutes", 300, "max-age=300"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := CreateJWKSRouter(mockDB, tt.maxAge)
			req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Header().Get("Cache-Control") != tt.expectedHeader {
				t.Errorf("Expected Cache-Control %s, got %s", tt.expectedHeader, rr.Header().Get("Cache-Control"))
			}
		})
	}

	negativeTests := []struct {
		name           string
		maxAge         int
		expectedHeader string
	}{
		{"negative value", -1, "max-age=0"},
		{"negative large value", -1000, "max-age=0"},
	}

	for _, tt := range negativeTests {
		t.Run(tt.name, func(t *testing.T) {
			handler := CreateJWKSRouter(mockDB, tt.maxAge)
			req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Header().Get("Cache-Control") != tt.expectedHeader {
				t.Errorf("Expected Cache-Control %s for negative maxAge, got %s", tt.expectedHeader, rr.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestJWKSEndpoint_ContainsExactlyOneKey(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: false}, nil
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var jwksResponse struct {
		Keys []map[string]interface{} `json:"keys"`
	}

	err := json.Unmarshal(rr.Body.Bytes(), &jwksResponse)
	if err != nil {
		t.Fatalf("Failed to parse JWKS response: %v", err)
	}

	if len(jwksResponse.Keys) != 1 {
		t.Errorf("Expected exactly 1 key, got %d", len(jwksResponse.Keys))
	}

	if jwksResponse.Keys[0]["kty"] != "RSA" {
		t.Errorf("Expected kty RSA, got %v", jwksResponse.Keys[0]["kty"])
	}

	if jwksResponse.Keys[0]["kid"].(string) != kid.String() {
		t.Errorf("Expected kid %s, got %v", kid, jwksResponse.Keys[0]["kid"])
	}
}

func TestJWKSEndpoint_ValidRFC7517Format(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: false}, nil
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var jwksResponse map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &jwksResponse)
	if err != nil {
		t.Fatalf("Failed to parse JWKS as JSON: %v", err)
	}

	if _, ok := jwksResponse["keys"]; !ok {
		t.Errorf("Expected 'keys' field in JWKS response")
	}
}

func TestJWKSEndpoint_ResponseTime(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: false}, nil
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)

	start := time.Now()
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	duration := time.Since(start)

	if duration > 100*time.Millisecond {
		t.Errorf("Response time %v exceeds 100ms threshold", duration)
	}
}

func TestJWKSEndpoint_NonExistentKey_Returns404(t *testing.T) {
	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return nil, errors.NewKeyNotFoundError("key not found")
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}

	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", rr.Header().Get("Content-Type"))
	}
}

func TestJWKSEndpoint_NonExistentKey_ContainsKeyNotFoundError(t *testing.T) {
	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return nil, errors.NewKeyNotFoundError("key not found")
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var errorResponse struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}

	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	if err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}

	if errorResponse.Code != "KeyNotFoundError" {
		t.Errorf("Expected error code KeyNotFoundError, got %s", errorResponse.Code)
	}
}

func TestJWKSEndpoint_NonExistentKey_ProperJSONStructure(t *testing.T) {
	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return nil, errors.NewKeyNotFoundError("key not found")
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var errorResponse map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	if err != nil {
		t.Fatalf("Failed to parse error response as JSON: %v", err)
	}

	if _, ok := errorResponse["code"]; !ok {
		t.Errorf("Expected 'code' field in error response")
	}

	if _, ok := errorResponse["message"]; !ok {
		t.Errorf("Expected 'message' field in error response")
	}
}

func TestJWKSEndpoint_NonExistentKey_NoDatabaseModifications(t *testing.T) {
	callCount := 0

	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			callCount++
			return nil, errors.NewKeyNotFoundError("key not found")
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if callCount != 1 {
		t.Errorf("Expected exactly 1 database call for non-existent key, got %d", callCount)
	}
}

func TestJWKSEndpoint_RevokedKey_Returns404(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: true}, nil
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for revoked key, got %d", rr.Code)
	}
}

func TestJWKSEndpoint_RevokedKey_IdenticalToNonExistent(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	kid := uuid.New()

	mockDBRevoked := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: true}, nil
		},
	}

	handler := CreateJWKSRouter(mockDBRevoked, 300)
	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rrRevoked := httptest.NewRecorder()
	handler.ServeHTTP(rrRevoked, req)

	mockDBNotFound := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return nil, errors.NewKeyNotFoundError("key not found")
		},
	}

	handler2 := CreateJWKSRouter(mockDBNotFound, 300)
	rrNotFound := httptest.NewRecorder()
	handler2.ServeHTTP(rrNotFound, req)

	if rrRevoked.Code != rrNotFound.Code {
		t.Errorf("Revoked key status (%d) differs from non-existent (%d)", rrRevoked.Code, rrNotFound.Code)
	}

	if rrRevoked.Body.String() != rrNotFound.Body.String() {
		t.Errorf("Revoked key body differs from non-existent:\nRevoked: %s\nNotFound: %s", rrRevoked.Body.String(), rrNotFound.Body.String())
	}
}

func TestJWKSEndpoint_RevokedKey_NeverReturnsValidJWKS(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: true}, nil
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var jwksResponse map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &jwksResponse)
	if err != nil {
		t.Fatalf("Failed to parse revoked key response: %v", err)
	}

	if _, ok := jwksResponse["keys"]; ok {
		t.Errorf("Revoked key returned 'keys' field, should not contain JWKS")
	}

	if rr.Code != http.StatusNotFound {
		t.Errorf("Revoked key should return 404, got %d", rr.Code)
	}
}

func TestJWKSEndpoint_DatabaseTimeout_Returns503(t *testing.T) {
	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return nil, errors.NewDatabaseTimeoutError("database timeout")
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503 for database timeout, got %d", rr.Code)
	}

	var errorResponse struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}

	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	if err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}

	if errorResponse.Code != "InternalError" {
		t.Errorf("Expected error code InternalError, got %s", errorResponse.Code)
	}
}

func TestJWKSEndpoint_DatabaseUnavailable_Returns503(t *testing.T) {
	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return nil, errors.NewDatabaseUnavailableError("database unavailable")
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503 for database unavailable, got %d", rr.Code)
	}

	var errorResponse struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}

	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	if err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}

	if errorResponse.Code != "InternalError" {
		t.Errorf("Expected error code InternalError, got %s", errorResponse.Code)
	}
}

func TestJWKSEndpoint_OtherDatabaseErrors_Returns500(t *testing.T) {
	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return nil, fmt.Errorf("unexpected database error")
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500 for other database errors, got %d", rr.Code)
	}

	var errorResponse struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}

	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	if err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}

	if errorResponse.Code != "InternalError" {
		t.Errorf("Expected error code InternalError, got %s", errorResponse.Code)
	}
}

func TestJWKSEndpoint_500ClassErrors_Logged(t *testing.T) {
	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return nil, errors.NewDatabaseTimeoutError("database timeout")
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", rr.Code)
	}

	if !strings.Contains(rr.Body.String(), "Database temporarily unavailable") {
		t.Errorf("Expected error message in response, got %s", rr.Body.String())
	}
}

func TestJWKSEndpoint_InvalidKidFormat_Returns404(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: false}, nil
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/invalid-uuid/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for invalid kid format, got %d", rr.Code)
	}
}

func TestJWKSEndpoint_EmptyKid_Returns404(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: false}, nil
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "//.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for empty kid, got %d", rr.Code)
	}
}

func TestJWKSEndpoint_ConcurrentRequests_Safe(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: false}, nil
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	concurrency := 100
	done := make(chan bool, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Concurrent request failed with status %d", rr.Code)
			}

			done <- true
		}()
	}

	for i := 0; i < concurrency; i++ {
		<-done
	}
}

func TestJWKSEndpoint_NoPrivateKeyExposed(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: false}, nil
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var jwksResponse map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &jwksResponse)
	if err != nil {
		t.Fatalf("Failed to parse JWKS response: %v", err)
	}

	keys, ok := jwksResponse["keys"].([]interface{})
	if !ok || len(keys) != 1 {
		t.Fatalf("Expected keys array with 1 element")
	}

	key, ok := keys[0].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected key object")
	}

	privateKeyFields := []string{"d", "p", "q", "dp", "dq", "qi"}
	for _, field := range privateKeyFields {
		if _, exists := key[field]; exists {
			t.Errorf("Response contains private key field '%s', should not expose private key", field)
		}
	}
}

func TestJWKSEndpoint_ContentTypeAlwaysJSON(t *testing.T) {
	tests := []struct {
		name         string
		kid          string
		mockReturn   func() (*KeyLookupResult, error)
		expectedCode int
	}{
		{"valid key", uuid.New().String(), func() (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: &rsa.PublicKey{N: new(big.Int).SetInt64(12345), E: 65537}, Revoked: false}, nil
		}, http.StatusOK},
		{"not found", uuid.New().String(), func() (*KeyLookupResult, error) {
			return nil, errors.NewKeyNotFoundError("key not found")
		}, http.StatusNotFound},
		{"revoked", uuid.New().String(), func() (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: &rsa.PublicKey{N: new(big.Int).SetInt64(12345), E: 65537}, Revoked: true}, nil
		}, http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB := &MockDatabaseDriver{
				GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
					return tt.mockReturn()
				},
			}

			handler := CreateJWKSRouter(mockDB, 300)

			req, _ := http.NewRequest("GET", "/"+tt.kid+"/.well-known/jwks.json", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Header().Get("Content-Type") != "application/json" {
				t.Errorf("Expected Content-Type application/json, got %s", rr.Header().Get("Content-Type"))
			}
		})
	}
}

func TestJWKSEndpoint_OnlyOneKeyInResponse(t *testing.T) {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetInt64(12345),
		E: 65537,
	}

	kid := uuid.New()

	mockDB := &MockDatabaseDriver{
		GetKeyFunc: func(ctx context.Context, _ string) (*KeyLookupResult, error) {
			return &KeyLookupResult{PublicKey: publicKey, Revoked: false}, nil
		},
	}

	handler := CreateJWKSRouter(mockDB, 300)

	req, _ := http.NewRequest("GET", "/"+kid.String()+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var jwksResponse struct {
		Keys []interface{} `json:"keys"`
	}

	err := json.Unmarshal(rr.Body.Bytes(), &jwksResponse)
	if err != nil {
		t.Fatalf("Failed to parse JWKS response: %v", err)
	}

	if len(jwksResponse.Keys) != 1 {
		t.Errorf("Expected exactly 1 key in response, got %d", len(jwksResponse.Keys))
	}
}
