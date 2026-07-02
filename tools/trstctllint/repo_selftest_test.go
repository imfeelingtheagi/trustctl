package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRepoWideMulticheckerRunsAndFailsPlantedViolations(t *testing.T) {
	root := repoRoot(t)
	bin := filepath.Join(t.TempDir(), "trstctllint")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	runCmd(t, root, "go", "build", "-o", bin, "./tools/trstctllint")

	clean := exec.Command(bin, "./...")
	clean.Dir = root
	clean.Env = commandEnv(t)
	if out, err := clean.CombinedOutput(); err != nil {
		t.Fatalf("repo-wide trstctllint ./... failed on clean tree: %v\n%s", err, out)
	}

	fixture := t.TempDir()
	writeFile(t, filepath.Join(fixture, "go.mod"), "module trstctl.com/trstctl\n\ngo 1.22\n")
	writeFile(t, filepath.Join(fixture, "badcrypto", "bad.go"), `package badcrypto

import _ "crypto/x509"
`)
	writeFile(t, filepath.Join(fixture, "internal", "api", "secrets.go"), `package api

type issueRequest struct {
	Credential string
}

func leak(credential []byte) string {
	return string(credential)
}
`)
	writeFile(t, filepath.Join(fixture, "internal", "crypto", "agility.go"), `package crypto

import _ "trstctl.com/trstctl/internal/policy"

var providerRegistry = map[string]any{}
`)
	writeFile(t, filepath.Join(fixture, "internal", "policy", "policy.go"), `package policy
`)
	writeFile(t, filepath.Join(fixture, "internal", "badnetexec", "bad.go"), `package badnetexec

import (
	"net/http"
	"os/exec"
)

var client = http.DefaultClient

func reload() error {
	return exec.Command("sh", "-c", "reload").Run()
}
`)

	planted := exec.Command(bin, "./...")
	planted.Dir = fixture
	planted.Env = commandEnv(t)
	out, err := planted.CombinedOutput()
	if err == nil {
		t.Fatalf("trstctllint accepted planted violations; output:\n%s", out)
	}
	got := string(out)
	for _, want := range []string{
		`import "crypto/x509" is not allowed outside internal/crypto`,
		"secret-bearing API/auth field must not use string",
		"secret-bearing API/auth code must not convert secret bytes to string",
		`import "trstctl.com/trstctl/internal/policy" is not allowed in the crypto/signer boundary`,
		`runtime-mutable crypto provider/engine registry "providerRegistry" is not allowed`,
		"http.DefaultClient is not allowed in new outbound surfaces",
		"direct shell interpreter execution is not allowed",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("planted violation output missing %q:\n%s", want, got)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func commandEnv(t *testing.T) []string {
	t.Helper()
	env := os.Environ()
	if os.Getenv("GOCACHE") == "" {
		env = append(env, "GOCACHE="+filepath.Join(t.TempDir(), "gocache"))
	}
	return env
}

func runCmd(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = commandEnv(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
