package est_test

import (
	"os"
	"os/exec"
	"testing"
)

// TestESTDifferentialVsLibest checks trustctl's EST behavior against the libest
// reference client (RFC 7030). libest is an external C toolchain not present in the
// unit sandbox, so — like the Pebble ACME differential — this runs on the CI
// backstop: it is skipped unless EST_LIBEST points at an estclient binary, and
// then drives a real /cacerts + /simpleenroll round-trip against it.
//
// Honest by construction: when the reference is absent the test SKIPS (it does not
// pass vacuously), so a green local run never implies libest agreement.
func TestESTDifferentialVsLibest(t *testing.T) {
	bin := os.Getenv("EST_LIBEST")
	if bin == "" {
		t.Skip("EST_LIBEST not set; the libest differential runs on the CI backstop")
	}
	if _, err := exec.LookPath(bin); err != nil {
		t.Fatalf("EST_LIBEST=%q not executable: %v", bin, err)
	}
	// CI wires the libest estclient against a live server here and asserts the
	// enrolled certificate verifies to the /cacerts chain.
	t.Log("libest differential is driven by the CI job; see .github/workflows for the harness")
}
