package japikey

import (
	"testing"

	"github.com/susu-dot-dev/japikey/errors"
)

func TestNewJapiKeyVersion_ValidVersions(t *testing.T) {
	testCases := []struct {
		name           string
		versionStr     string
		expectedNumber int
		expectedString string
	}{
		{
			name:           "version 1",
			versionStr:     "japikey-v1",
			expectedNumber: 1,
			expectedString: "japikey-v1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, err := NewJapiKeyVersion(tc.versionStr)
			if err != nil {
				t.Errorf("Expected no error for valid version %s, got: %v", tc.versionStr, err)
			}
			if version == nil {
				t.Fatal("Expected version to not be nil")
			}
			if version.Version() != tc.expectedNumber {
				t.Errorf("Expected version number %d, got %d", tc.expectedNumber, version.Version())
			}
			if version.String() != tc.expectedString {
				t.Errorf("Expected version string %s, got %s", tc.expectedString, version.String())
			}
		})
	}
}

func TestNewJapiKeyVersion_InvalidFormat(t *testing.T) {
	testCases := []struct {
		name        string
		versionStr  string
		expectError bool
	}{
		{
			name:        "empty string",
			versionStr:  "",
			expectError: true,
		},
		{
			name:        "wrong prefix",
			versionStr:  "jwt-v1",
			expectError: true,
		},
		{
			name:        "missing prefix",
			versionStr:  "v1",
			expectError: true,
		},
		{
			name:        "only prefix",
			versionStr:  "japikey-v",
			expectError: true,
		},
		{
			name:        "prefix with dash but no number",
			versionStr:  "japikey-v-",
			expectError: true,
		},
		{
			name:        "lowercase prefix",
			versionStr:  "JAPIKEY-V1",
			expectError: true,
		},
		{
			name:        "mixed case prefix",
			versionStr:  "Japikey-v1",
			expectError: true,
		},
		{
			name:        "extra characters before prefix",
			versionStr:  "prefix-japikey-v1",
			expectError: true,
		},
		{
			name:        "extra characters after number",
			versionStr:  "japikey-v1extra",
			expectError: true,
		},
		{
			name:        "version with letter after number",
			versionStr:  "japikey-v1a",
			expectError: true,
		},
		{
			name:        "version with letter before number",
			versionStr:  "japikey-va1",
			expectError: true,
		},
		{
			name:        "non-numeric version",
			versionStr:  "japikey-vabc",
			expectError: true,
		},
		{
			name:        "negative version",
			versionStr:  "japikey-v-1",
			expectError: true,
		},
		{
			name:        "zero version",
			versionStr:  "japikey-v0",
			expectError: true,
		},
		{
			name:        "version with leading zeros single",
			versionStr:  "japikey-v01",
			expectError: true,
		},
		{
			name:        "version with leading zeros multiple",
			versionStr:  "japikey-v0001",
			expectError: true,
		},
		{
			name:        "version exceeds maximum",
			versionStr:  "japikey-v2",
			expectError: true,
		},
		{
			name:        "very large version number",
			versionStr:  "japikey-v999",
			expectError: true,
		},
		{
			name:        "version with decimal",
			versionStr:  "japikey-v1.5",
			expectError: true,
		},
		{
			name:        "version with spaces",
			versionStr:  "japikey-v 1",
			expectError: true,
		},
		{
			name:        "version with multiple dashes",
			versionStr:  "japikey-v-1",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, err := NewJapiKeyVersion(tc.versionStr)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for invalid version %s, got none", tc.versionStr)
				}
				if version != nil {
					t.Errorf("Expected version to be nil for invalid version %s", tc.versionStr)
				}
				if _, ok := err.(*errors.ValidationError); !ok {
					t.Errorf("Expected ValidationError, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for version %s, got: %v", tc.versionStr, err)
				}
				if version == nil {
					t.Error("Expected version to not be nil")
				}
			}
		})
	}
}

func TestValidateVersionFromClaims_Valid(t *testing.T) {
	claims := map[string]interface{}{
		"ver": "japikey-v1",
		"sub": "test-user",
	}

	version, err := ValidateVersionFromClaims(claims)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if version == nil {
		t.Fatal("Expected version to not be nil")
	}
	if version.Version() != 1 {
		t.Errorf("Expected version number 1, got %d", version.Version())
	}
}

func TestValidateVersionFromClaims_MissingClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub": "test-user",
		// Missing "ver" claim
	}

	version, err := ValidateVersionFromClaims(claims)
	if err == nil {
		t.Error("Expected error for missing version claim, got none")
	}
	if version != nil {
		t.Error("Expected version to be nil for missing claim")
	}
	if _, ok := err.(*errors.ValidationError); !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
}

func TestValidateVersionFromClaims_NonStringClaim(t *testing.T) {
	testCases := []struct {
		name  string
		value interface{}
	}{
		{
			name:  "integer",
			value: 1,
		},
		{
			name:  "float",
			value: 1.0,
		},
		{
			name:  "boolean",
			value: true,
		},
		{
			name:  "map",
			value: map[string]interface{}{"version": "japikey-v1"},
		},
		{
			name:  "array",
			value: []string{"japikey-v1"},
		},
		{
			name:  "nil",
			value: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]interface{}{
				"ver": tc.value,
			}

			version, err := ValidateVersionFromClaims(claims)
			if err == nil {
				t.Errorf("Expected error for non-string version claim (%T), got none", tc.value)
			}
			if version != nil {
				t.Errorf("Expected version to be nil for non-string claim (%T)", tc.value)
			}
			if _, ok := err.(*errors.ValidationError); !ok {
				t.Errorf("Expected ValidationError, got %T", err)
			}
		})
	}
}

func TestValidateVersionFromClaims_InvalidVersionString(t *testing.T) {
	testCases := []struct {
		name       string
		versionStr string
	}{
		{
			name:       "empty string",
			versionStr: "",
		},
		{
			name:       "wrong prefix",
			versionStr: "jwt-v1",
		},
		{
			name:       "exceeds maximum",
			versionStr: "japikey-v2",
		},
		{
			name:       "zero version",
			versionStr: "japikey-v0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]interface{}{
				"ver": tc.versionStr,
			}

			version, err := ValidateVersionFromClaims(claims)
			if err == nil {
				t.Errorf("Expected error for invalid version string %s, got none", tc.versionStr)
			}
			if version != nil {
				t.Errorf("Expected version to be nil for invalid version string %s", tc.versionStr)
			}
			if _, ok := err.(*errors.ValidationError); !ok {
				t.Errorf("Expected ValidationError, got %T", err)
			}
		})
	}
}

func TestJapiKeyVersion_String(t *testing.T) {
	version, err := NewJapiKeyVersion("japikey-v1")
	if err != nil {
		t.Fatalf("Failed to create version: %v", err)
	}

	expected := "japikey-v1"
	if version.String() != expected {
		t.Errorf("Expected String() to return %s, got %s", expected, version.String())
	}
}

func TestJapiKeyVersion_Version(t *testing.T) {
	version, err := NewJapiKeyVersion("japikey-v1")
	if err != nil {
		t.Fatalf("Failed to create version: %v", err)
	}

	expected := 1
	if version.Version() != expected {
		t.Errorf("Expected Version() to return %d, got %d", expected, version.Version())
	}
}

func TestNewJapiKeyVersion_WithMaxVersionOverride(t *testing.T) {
	// Save original override
	originalOverride := maxVersionOverride
	defer func() {
		maxVersionOverride = originalOverride
	}()

	// Test with higher max version
	maxVersion := 100
	maxVersionOverride = &maxVersion

	testCases := []struct {
		name           string
		versionStr     string
		expectedNumber int
		expectedString string
	}{
		{
			name:           "version 1",
			versionStr:     "japikey-v1",
			expectedNumber: 1,
			expectedString: "japikey-v1",
		},
		{
			name:           "version 10",
			versionStr:     "japikey-v10",
			expectedNumber: 10,
			expectedString: "japikey-v10",
		},
		{
			name:           "version 100",
			versionStr:     "japikey-v100",
			expectedNumber: 100,
			expectedString: "japikey-v100",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, err := NewJapiKeyVersion(tc.versionStr)
			if err != nil {
				t.Errorf("Expected no error for valid version %s, got: %v", tc.versionStr, err)
			}
			if version == nil {
				t.Fatal("Expected version to not be nil")
			}
			if version.Version() != tc.expectedNumber {
				t.Errorf("Expected version number %d, got %d", tc.expectedNumber, version.Version())
			}
			if version.String() != tc.expectedString {
				t.Errorf("Expected version string %s, got %s", tc.expectedString, version.String())
			}
		})
	}

	// Test that version exceeding override still fails
	version, err := NewJapiKeyVersion("japikey-v101")
	if err == nil {
		t.Error("Expected error for version exceeding override max, got none")
	}
	if version != nil {
		t.Error("Expected version to be nil for version exceeding override max")
	}
}
