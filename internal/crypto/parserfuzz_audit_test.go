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

// fuzzFuncNameRE matches a Go fuzz target declaration and captures its name, so
// the guard can require specific decoders to stay fuzzed (not just "some target
// in this dir").
var fuzzFuncNameRE = regexp.MustCompile(`(?m)^func (Fuzz\w+)\(`)

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
		".":                   "PKCS#10 CSR (VerifyCertificateRequest)",
		"certinfo":            "X.509 certificate (Inspect)",
		"ctlog":               "CT-log RFC 6962 (ParseSTH / ParseEntries)",
		"sshkeys":             "SSH keys (authorized_keys / known_hosts / .pub)",
		"jose":                "JOSE / ACME JWS",
		"../protocols/acme":   "ACME new-order / finalize",
		"../protocols/ari":    "ARI CertID",
		"../protocols/est":    "EST enroll body (base64 PKCS#10)",
		"../signing":          "signer SignRequest (protobuf)",
		"../secretscan":       "scanner-report ingest (untrusted JSON)",
		"../kmip":             "KMIP TTLV wire frame parser",
		"../attest/awsiid":    "AWS IID attester Attest (untrusted CMS pre-verification)",
		"../attest/azureimds": "Azure IMDS attester Attest (untrusted CMS pre-verification)",
	}
	for dir, what := range parsers {
		if !dirHasFuzzTarget(t, dir) {
			t.Errorf("untrusted parser %s (%s) has no Go fuzz target — CLAUDE.md §6 requires every parser that touches untrusted input to be fuzzed", dir, what)
		}
	}

	// The "some fuzz target lives in this dir" check above is too coarse for the
	// CMS/PKCS7 decoder family: a single SCEP-request target satisfied it while
	// the sibling decoders that share the same (panic-prone) smallstep/pkcs7
	// BER decoder — and that parse UNTRUSTED bytes before any verification —
	// were left unfuzzed (FUZZ-001/002). Require those CMS boundary targets by
	// NAME so dropping one trips this guard, not just deleting the whole file.
	requireFuzzFuncByName(t, ".", map[string]string{
		"FuzzParseSCEPRequest":   "SCEP pkiMessage CMS (scep.go ParseSCEPRequest)",
		"FuzzParseSCEPResponse":  "SCEP CertRep CMS (scep.go ParseSCEPResponse) — shares the FUZZ-001 decoder",
		"FuzzVerifyCMSSignature": "cloud IID CMS (verify.go VerifyCMSSignature) — parses untrusted bytes pre-verification",
		// CMP (RFC 4210) PKIMessage parsing is another untrusted-ASN.1 boundary
		// (cmp.go ParseCMPRequest) that shares the CMS/PKCS7 decoder family. Pin it by
		// name so the SCEP/CMP/EST denominator the guard claims to police is complete
		// and dropping the CMP harness trips this guard (FUZZ-004).
		"FuzzParseCMPRequest":        "CMP PKIMessage (cmp.go ParseCMPRequest) — untrusted ASN.1 enrollment envelope",
		"FuzzParseOCSPRequestSerial": "served RFC 6960 OCSP request DER (revocation.go ParseOCSPRequestSerial)",
	})

	// The cloud instance-identity attesters parse the same untrusted CMS family at
	// their pre-verification entry point (Attest). VerifyCMSSignature is fuzzed at
	// the boundary above; require the end-to-end attester harnesses too so the JSON
	// document decode + selector extraction that runs on a verified-but-attacker-
	// shaped document is covered, and so dropping one attester's harness trips this
	// guard (FUZZ-002).
	requireFuzzFuncByName(t, "../attest/awsiid", map[string]string{
		"FuzzAWSIIDAttest": "AWS IID attester Attest (awsiid.go) — untrusted CMS document pre-verification",
	})
	requireFuzzFuncByName(t, "../attest/azureimds", map[string]string{
		"FuzzAzureIMDSAttest": "Azure IMDS attester Attest (azureimds.go) — untrusted CMS document pre-verification",
	})
	requireFuzzFuncByName(t, "../kmip", map[string]string{
		"FuzzParseTTLV": "KMIP TTLV wire frame decoder (kmip ttlv.go) — enterprise key-management client bytes",
	})
}

// requireFuzzFuncByName fails if any of the named Fuzz targets is missing from
// the *_test.go files in dir. It pins the exact untrusted decoders that must
// stay fuzzed (CLAUDE.md §6), closing the false-"all parsers fuzzed" assurance a
// directory-level check gives when one decoder in a multi-decoder package loses
// its harness.
func requireFuzzFuncByName(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read parser dir %q: %v", dir, err)
	}
	found := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range fuzzFuncNameRE.FindAllStringSubmatch(string(b), -1) {
			found[m[1]] = true
		}
	}
	for name, what := range want {
		if !found[name] {
			t.Errorf("required fuzz target %s (%s) is missing — CLAUDE.md §6 / FUZZ-001/002 require it; do not remove it", name, what)
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
