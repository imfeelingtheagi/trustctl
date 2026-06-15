package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fileContains reports whether the file at rel (relative to docs/) contains sub.
func fileContains(t *testing.T, rel, sub string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return strings.Contains(string(b), sub)
}

// anyTestFileHas reports whether any *_test.go file directly under dir contains sub.
func anyTestFileHas(t *testing.T, dir, sub string) bool {
	t.Helper()
	entries, err := os.ReadDir(filepath.FromSlash(dir))
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.FromSlash(dir + "/" + e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), sub) {
			return true
		}
	}
	return false
}

// TestESTReferenceDifferentialIsHonestAndCodeBound is the reality-bound disclosure
// for TEST-002: the EST reference-differential claim in limitations.md must match the
// code, in both directions.
//
//   - The "EST runs a differential against OpenSSL on every make test" claim is true
//     only while a REAL, non-skipped OpenSSL differential exists in the est package —
//     the prior stub merely t.Log-ed. So the test asserts TestESTDifferentialVsOpenSSL
//     (and its openssl pkcs7/verify drive) is present; if it is ever removed, the
//     claim would become an over-claim and this fails loudly.
//   - The "no SPIFFE Workload-API differential yet" disclosure is honest only while
//     none exists. If a future change adds one (a go-spiffe/SPIRE differential), the
//     stale "no SPIFFE differential" disclosure must be retired, and this flips to
//     demand that. Likewise the EXC link must be present while these are outstanding.
func TestESTReferenceDifferentialIsHonestAndCodeBound(t *testing.T) {
	// (1) Code anchor: the EST package has a real OpenSSL differential (not a stub).
	// It must drive openssl's own pkcs7 parser AND chain verify — independent code.
	const estDir = "../internal/protocols/est"
	if !anyTestFileHas(t, estDir, "TestESTDifferentialVsOpenSSL") {
		t.Fatal("the EST OpenSSL differential (TestESTDifferentialVsOpenSSL) is gone; limitations.md claims EST has a real external-reference differential — restore it or correct the disclosure (TEST-002)")
	}
	for _, marker := range []string{`"pkcs7"`, `"verify"`} {
		if !anyTestFileHas(t, estDir, marker) {
			t.Errorf("the EST differential should drive openssl %s (an independent RFC 7030 implementation); the claim rests on it (TEST-002)", marker)
		}
	}

	// (2) limitations.md states the honest EST/ACME differential posture.
	lim := strings.ToLower(read(t, "limitations.md"))
	for _, marker := range []string{"openssl", "pebble", "differential"} {
		if !strings.Contains(lim, marker) {
			t.Errorf("limitations.md should describe the protocol reference differentials (missing %q) (TEST-002)", marker)
		}
	}

	// (3) Reality-bound SPIFFE differential disclosure. Detect whether a SPIFFE
	// reference differential now exists anywhere under internal/.
	spiffeDifferentialExists := repoHasSPIFFEDifferential(t)
	if spiffeDifferentialExists {
		// Now it exists: the "no SPIFFE differential" disclosure would be stale.
		if strings.Contains(lim, "no spiffe workload-api differential") {
			t.Error("a SPIFFE Workload-API differential appears to exist now, but limitations.md still says there is none — update the disclosure (TEST-002)")
		}
		return
	}
	// Not yet: the honest disclosure and the wire-in epic link must be present.
	if !strings.Contains(lim, "no spiffe workload-api differential") {
		t.Error("limitations.md must disclose that there is no SPIFFE Workload-API reference differential yet (TEST-002)")
	}
	if !strings.Contains(lim, "libest") {
		t.Error("limitations.md must disclose the libest estclient differential as opt-in/not-wired (TEST-002)")
	}
	if !fileContains(t, "limitations.md", "EXC-WIRE-02") {
		t.Error("limitations.md must link the wire-in epic EXC-WIRE-02 for the outstanding reference differentials (TEST-002)")
	}
}

// repoHasSPIFFEDifferential reports whether any test under internal/ wires a SPIFFE
// Workload-API differential against an independent implementation (go-spiffe/SPIRE).
// A bare mention of the spiffe package is not enough — we look for a differential/
// reference-client signal in a SPIFFE test file.
func repoHasSPIFFEDifferential(t *testing.T) bool {
	t.Helper()
	var found bool
	root := filepath.FromSlash("../internal")
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		s := strings.ToLower(string(b))
		isSpiffe := strings.Contains(path, "spiffe") || strings.Contains(s, "spiffe")
		hasRef := strings.Contains(s, "go-spiffe") || strings.Contains(s, "spire") ||
			strings.Contains(s, "spiffedifferential") || strings.Contains(s, "workload api differential")
		if isSpiffe && hasRef {
			found = true
		}
		return nil
	})
	return found
}
