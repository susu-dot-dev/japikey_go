package japikey

import (
	"fmt"
	"regexp"
	"strings"

	japikeyerrors "github.com/susu-dot-dev/japikey/errors"
)

var versionNumberRegex = regexp.MustCompile(`^[1-9][0-9]*$`)

// maxVersionOverride allows tests to override the maximum version.
// It defaults to nil, which means use the constant MaxVersion.
var maxVersionOverride *int

// getMaximumVersion returns the maximum allowed version number.
// For testing, maxVersionOverride can be set to override the default.
func getMaximumVersion() int {
	if maxVersionOverride != nil {
		return *maxVersionOverride
	}
	return MaxVersion
}

// JapiKeyVersion represents a validated JAPIKey version.
type JapiKeyVersion struct {
	version int
}

// Version returns the numeric version number.
func (v *JapiKeyVersion) Version() int {
	return v.version
}

// String returns the version string in the format "japikey-v{number}".
func (v *JapiKeyVersion) String() string {
	return fmt.Sprintf("%s%d", VersionPrefix, v.version)
}

// NewJapiKeyVersion validates and creates a new JapiKeyVersion from a version string.
// Returns an error if the version format is invalid or exceeds the maximum allowed version.
func NewJapiKeyVersion(versionStr string) (*JapiKeyVersion, error) {
	if versionStr == "" {
		return nil, japikeyerrors.NewValidationError("version string cannot be empty")
	}

	if !strings.HasPrefix(versionStr, VersionPrefix) {
		return nil, japikeyerrors.NewValidationError(fmt.Sprintf("invalid version format: %s, expected prefix %s", versionStr, VersionPrefix))
	}

	// Extract version number
	if len(versionStr) <= len(VersionPrefix) {
		return nil, japikeyerrors.NewValidationError(fmt.Sprintf("invalid version format: %s, missing version number", versionStr))
	}

	versionNumStr := versionStr[len(VersionPrefix):]

	// Validate that the version number string contains only digits (no leading zeros, no negatives, no decimals)
	if !versionNumberRegex.MatchString(versionNumStr) {
		return nil, japikeyerrors.NewValidationError(fmt.Sprintf("invalid version number: %s", versionStr))
	}

	// Parse the version number (we know it's valid digits at this point)
	var versionNum int
	_, err := fmt.Sscanf(versionNumStr, "%d", &versionNum)
	if err != nil {
		return nil, japikeyerrors.NewValidationError(fmt.Sprintf("invalid version number: %s", versionStr))
	}

	// Validate version number doesn't exceed maximum
	// Note: versionNum is guaranteed to be >= 1 by the regex pattern
	maxVersion := getMaximumVersion()
	if versionNum > maxVersion {
		return nil, japikeyerrors.NewValidationError(fmt.Sprintf("invalid version number: %s, exceeds maximum version %d", versionStr, maxVersion))
	}

	return &JapiKeyVersion{version: versionNum}, nil
}

// ValidateVersionFromClaims validates the version claim from JWT claims and returns a JapiKeyVersion.
func ValidateVersionFromClaims(claims map[string]interface{}) (*JapiKeyVersion, error) {
	versionRaw, ok := claims[VersionClaim]
	if !ok {
		return nil, japikeyerrors.NewValidationError("token missing version claim")
	}

	version, ok := versionRaw.(string)
	if !ok {
		return nil, japikeyerrors.NewValidationError("token version claim must be a string")
	}

	return NewJapiKeyVersion(version)
}
