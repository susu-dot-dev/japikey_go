package jwks

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"uuid"
)

// The jwx tool's `generate` output for a P-256 key must be a JWKS this package
// accepts (the integration module checks third-party libraries too).
func TestJWXToolGenerateES256IsAcceptedByLibrary(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	kid := uuid.New()

	// The P-256 generator point, as the base64 of its uncompressed encoding
	const point = "BGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU="
	cmd := exec.Command("go", "run", ".", "generate", kid.String())
	cmd.Dir = "../../jwx/tool"
	cmd.Stdin = strings.NewReader(point)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("jwx generate failed: %v\n%s", err, out)
	}

	var set JWKS
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &set); err != nil {
		t.Fatalf("library rejected jwx output %s: %v", out, err)
	}
	if set.GetKeyID() != kid {
		t.Errorf("kid = %v, want %v", set.GetKeyID(), kid)
	}
}
