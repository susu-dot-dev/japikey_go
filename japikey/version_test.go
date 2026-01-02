package japikey

import (
	"testing"

	"github.com/susu-dot-dev/japikey/errors"
)

func TestNewJapiKeyVersion_ValidVersions(t *testing.T) {
	testCases := []struct {
		name           string
		versionStr     string
		maxVersion     int
		expectedNumber int
		expectedString string
	}{
		{
			name:           "version 1",
			versionStr:     "japikey-v1",
			maxVersion:     1,
			expectedNumber: 1,
			expectedString: "japikey-v1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, err := NewJapiKeyVersion(tc.versionStr, tc.maxVersion)
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
		maxVersion  int
		expectError bool
	}{
		{
			name:        "empty string",
			versionStr:  "",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "wrong prefix",
			versionStr:  "jwt-v1",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "missing prefix",
			versionStr:  "v1",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "only prefix",
			versionStr:  "japikey-v",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "prefix with dash but no number",
			versionStr:  "japikey-v-",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "lowercase prefix",
			versionStr:  "JAPIKEY-V1",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "mixed case prefix",
			versionStr:  "Japikey-v1",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "extra characters before prefix",
			versionStr:  "prefix-japikey-v1",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "extra characters after number",
			versionStr:  "japikey-v1extra",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "version with letter after number",
			versionStr:  "japikey-v1a",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "version with letter before number",
			versionStr:  "japikey-va1",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "non-numeric version",
			versionStr:  "japikey-vabc",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "negative version",
			versionStr:  "japikey-v-1",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "zero version",
			versionStr:  "japikey-v0",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "version with leading zeros single",
			versionStr:  "japikey-v01",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "version with leading zeros multiple",
			versionStr:  "japikey-v0001",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "version exceeds maximum",
			versionStr:  "japikey-v2",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "very large version number",
			versionStr:  "japikey-v999",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "version with decimal",
			versionStr:  "japikey-v1.5",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "version with spaces",
			versionStr:  "japikey-v 1",
			maxVersion:  1,
			expectError: true,
		},
		{
			name:        "version with multiple dashes",
			versionStr:  "japikey-v-1",
			maxVersion:  1,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, err := NewJapiKeyVersion(tc.versionStr, tc.maxVersion)
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


func TestJapiKeyVersion_String(t *testing.T) {
	version, err := NewJapiKeyVersion("japikey-v1", 1)
	if err != nil {
		t.Fatalf("Failed to create version: %v", err)
	}

	expected := "japikey-v1"
	if version.String() != expected {
		t.Errorf("Expected String() to return %s, got %s", expected, version.String())
	}
}

func TestJapiKeyVersion_Version(t *testing.T) {
	version, err := NewJapiKeyVersion("japikey-v1", 1)
	if err != nil {
		t.Fatalf("Failed to create version: %v", err)
	}

	expected := 1
	if version.Version() != expected {
		t.Errorf("Expected Version() to return %d, got %d", expected, version.Version())
	}
}

func TestNewJapiKeyVersion_WithMaxVersion(t *testing.T) {
	maxVersion := 100

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
			version, err := NewJapiKeyVersion(tc.versionStr, maxVersion)
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

	// Test that version exceeding max still fails
	version, err := NewJapiKeyVersion("japikey-v101", maxVersion)
	if err == nil {
		t.Error("Expected error for version exceeding max, got none")
	}
	if version != nil {
		t.Error("Expected version to be nil for version exceeding max")
	}
}

func TestNewJapiKeyVersion_OverflowProtection(t *testing.T) {
	// Test that very large version numbers are rejected by regex before parsing
	// This prevents potential integer overflow issues
	maxVersion := 999

	testCases := []struct {
		name        string
		versionStr  string
		expectError bool
		description string
	}{
		{
			name:        "version exceeds max by one digit",
			versionStr:  "japikey-v1000",
			expectError: true,
			description: "Version with 4 digits when max is 3 digits should be rejected by regex",
		},
		{
			name:        "very large version number",
			versionStr:  "japikey-v999999999",
			expectError: true,
			description: "Extremely large version should be rejected by regex",
		},
		{
			name:        "version at max boundary",
			versionStr:  "japikey-v999",
			expectError: false,
			description: "Version at max should be accepted",
		},
		{
			name:        "version just below max",
			versionStr:  "japikey-v998",
			expectError: false,
			description: "Version just below max should be accepted",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, err := NewJapiKeyVersion(tc.versionStr, maxVersion)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for %s (%s), got none", tc.versionStr, tc.description)
				}
				if version != nil {
					t.Errorf("Expected version to be nil for %s", tc.versionStr)
				}
				if _, ok := err.(*errors.ValidationError); !ok {
					t.Errorf("Expected ValidationError, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s (%s), got: %v", tc.versionStr, tc.description, err)
				}
				if version == nil {
					t.Error("Expected version to not be nil")
				}
			}
		})
	}
}
