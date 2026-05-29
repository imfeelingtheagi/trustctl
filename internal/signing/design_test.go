package signing_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These tests encode the S1.3 acceptance criteria for a design spike: the design
// doc is committed under docs/design/ and covers the required topics, the
// dependency budget is explicit, and the protocol is specified precisely enough
// to implement (the committed .proto stub).

func sourceDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(file) // .../internal/signing
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(sourceDir(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func TestDesignDocCoversRequiredSections(t *testing.T) {
	doc := readRepoFile(t, "../../docs/design/signing-service.md")
	for _, want := range []string{
		"Status:",                   // reviewed/accepted status
		"AN-4",                      // the architectural non-negotiable
		"AN-8",                      // memory safety
		"Threat model",              // threat model section
		"Process boundary",          // separate, sacred process
		"Protocol",                  // protocol section
		"gRPC",                      // transport
		"Unix domain socket",        // UDS
		"Memory-safety obligations", // AN-8 obligations
		"mlock",                     // locked memory
		"MADV_DONTDUMP",             // dump exclusion
		"Dependency budget",         // explicit dependency budget
		"Fuzzing plan",              // fuzzing plan
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("design doc is missing required content: %q", want)
		}
	}
}

func TestDependencyBudgetIsExplicit(t *testing.T) {
	doc := readRepoFile(t, "../../docs/design/signing-service.md")
	for _, want := range []string{
		"google.golang.org/grpc",     // allowed transport
		"google.golang.org/protobuf", // allowed messages
		"golang.org/x/sys",           // allowed syscalls
		"net/http",                   // named as forbidden (no HTTP server)
		"database/sql",               // named as forbidden (no SQL driver)
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("dependency budget is missing %q", want)
		}
	}
	if !strings.Contains(strings.ToLower(doc), "forbidden") {
		t.Error("dependency budget must explicitly list forbidden dependencies")
	}
}

func TestProtocolStubIsImplementable(t *testing.T) {
	proto := readRepoFile(t, "proto/signer.proto")
	for _, want := range []string{
		"service SignerService",
		"rpc GenerateKey",
		"rpc GetPublicKey",
		"rpc Sign",
		"rpc DestroyKey",
		"rpc Health",
		"message SignRequest",
		"message SignResponse",
	} {
		if !strings.Contains(proto, want) {
			t.Errorf("protocol stub is missing %q", want)
		}
	}
}
