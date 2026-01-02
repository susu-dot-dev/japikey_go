package japikey

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	japikeyerrors "github.com/susu-dot-dev/japikey/errors"
)

func buildVersionNumberRegex(maxVersion int) *regexp.Regexp {
	maxVersionStr := strconv.Itoa(maxVersion)
	maxDigits := len(maxVersionStr)
	return regexp.MustCompile(fmt.Sprintf(`^[1-9][0-9]{0,%d}$`, maxDigits-1))
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
// maxVersion specifies the maximum allowed version number.
// Returns an error if the version format is invalid or exceeds the maximum allowed version.
func NewJapiKeyVersion(versionStr string, maxVersion int) (*JapiKeyVersion, error) {
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

	// Build regex based on maxVersion to guard against very large versions
	versionNumberRegex := buildVersionNumberRegex(maxVersion)

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
	if versionNum > maxVersion {
		return nil, japikeyerrors.NewValidationError(fmt.Sprintf("invalid version number: %s, exceeds maximum version %d", versionStr, maxVersion))
	}

	return &JapiKeyVersion{version: versionNum}, nil
}
