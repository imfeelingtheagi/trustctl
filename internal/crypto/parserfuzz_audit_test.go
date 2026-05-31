package crypto_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fuzzFuncRE matches a Go fuzz target declaration.
var fuzzFuncRE = regexp.MustCompile(`(?m)^func Fuzz\w+\(`)

// TestEveryUntrustedParserIsFuzzed makes CLAUDE.md §6 ("fuzz every parser that
// touches untrusted input") executable: it enumerates the packages that parse
// attacker-controlled bytes and fails if any lacks at least one Go fuzz target.
// It was RED before R4.3 (ctlog, certinfo, sshkeys, and the CSR parser here had
// none) and is GREEN after. A new untrusted parser added without a fuzz target
// trips this guard.
//
// Paths are relative to this package directory (internal/crypto), which is the
// test's working directory.
func TestEveryUntrustedParserIsFuzzed(t *testing.T) {
	parsers := map[string]string{
		".":                 "PKCS#10 CSR (VerifyCertificateRequest)",
		"certinfo":          "X.509 certificate (Inspect)",
		"ctlog":             "CT-log RFC 6962 (ParseSTH / ParseEntries)",
		"sshkeys":           "SSH keys (authorized_keys / known_hosts / .pub)",
		"jose":              "JOSE / ACME JWS",
		"../protocols/acme": "ACME new-order / finalize",
		"../protocols/ari":  "ARI CertID",
		"../signing":        "signer SignRequest (protobuf)",
	}
	for dir, what := range parsers {
		if !dirHasFuzzTarget(t, dir) {
			t.Errorf("untrusted parser %s (%s) has no Go fuzz target — CLAUDE.md §6 requires every parser that touches untrusted input to be fuzzed", dir, what)
		}
	}
}

func dirHasFuzzTarget(t *testing.T, dir string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read parser dir %q: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if fuzzFuncRE.Match(b) {
			return true
		}
	}
	return false
}
