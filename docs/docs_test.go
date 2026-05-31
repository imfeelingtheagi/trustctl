package docs

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// requiredPages are the documentation pages S7.6 must deliver, as paths relative
// to the docs directory.
var requiredPages = []string{
	"index.md",
	"getting-started.md",
	"install.md",
	"uninstall.md",
	"configuration.md",
	"compliance.md",
	"observability.md",
	"operations.md",
	"disaster-recovery.md",
	"troubleshooting.md",
	"cli.md",
	"telemetry.md",
	"guides/plugin-authoring.md",
	"guides/connector-authoring.md",
}

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// allMarkdown returns every Markdown file under the docs directory.
func allMarkdown(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRequiredDocsExist: every required page exists and is a real page (has a
// heading and more than a stub of content).
func TestRequiredDocsExist(t *testing.T) {
	for _, p := range requiredPages {
		body := read(t, p)
		if len(strings.TrimSpace(body)) < 200 {
			t.Errorf("%s is too short to be a real documentation page (%d bytes)", p, len(body))
		}
		if !strings.Contains(body, "#") {
			t.Errorf("%s has no Markdown heading", p)
		}
	}
}

var mdLink = regexp.MustCompile(`\[[^\]]*\]\(([^)]+)\)`)

// TestNoBrokenInternalLinks: every relative Markdown link resolves to a file
// that exists. External (http/https/mailto) and pure-anchor links are skipped.
func TestNoBrokenInternalLinks(t *testing.T) {
	for _, f := range allMarkdown(t) {
		body := read(t, f)
		dir := filepath.Dir(f)
		for _, m := range mdLink.FindAllStringSubmatch(body, -1) {
			target := strings.TrimSpace(m[1])
			switch {
			case target == "",
				strings.HasPrefix(target, "http://"),
				strings.HasPrefix(target, "https://"),
				strings.HasPrefix(target, "mailto:"),
				strings.HasPrefix(target, "#"):
				continue
			}
			path := target
			if i := strings.IndexAny(path, "#?"); i >= 0 {
				path = path[:i]
			}
			if path == "" {
				continue
			}
			resolved := filepath.Join(dir, filepath.FromSlash(path))
			if _, err := os.Stat(resolved); err != nil {
				t.Errorf("%s: broken internal link %q (looked for %q)", f, target, resolved)
			}
		}
	}
}

// supportedPlatforms are the platforms certctl ships for; install and uninstall
// must be documented for each.
var supportedPlatforms = []string{"Linux", "macOS", "Windows", "Docker", "Kubernetes"}

// TestInstallAndUninstallCoverAllPlatforms encodes "install/uninstall are
// documented for all supported platforms".
func TestInstallAndUninstallCoverAllPlatforms(t *testing.T) {
	for _, page := range []string{"install.md", "uninstall.md"} {
		body := read(t, page)
		for _, plat := range supportedPlatforms {
			if !strings.Contains(body, plat) {
				t.Errorf("%s does not document the %s platform", page, plat)
			}
		}
	}
}

// TestGettingStartedMatchesProduct encodes "a new user reaches a first cert in a
// few minutes following the docs, and the page is honest about timing": the
// getting-started page cites the real one-command eval, walks the real first-run
// wizard (S7.3) toward a first certificate, and backs its timing claim with the
// measured issuance figure (R1.4) rather than an unverified marketing number.
func TestGettingStartedMatchesProduct(t *testing.T) {
	body := read(t, "getting-started.md")
	lower := strings.ToLower(body)

	if !strings.Contains(lower, "minute") {
		t.Error("getting-started should set an honest first-cert time expectation in minutes")
	}
	if !strings.Contains(lower, "measured") || !strings.Contains(lower, "millisecond") {
		t.Error("getting-started should cite the measured issuance time (R1.4), not an unverified number")
	}
	if !strings.Contains(body, "docker compose") || !strings.Contains(body, "deploy/docker/docker-compose.yml") {
		t.Error("getting-started should cite the real Compose eval command")
	}
	if _, err := os.Stat(filepath.FromSlash("../deploy/docker/docker-compose.yml")); err != nil {
		t.Fatalf("the Compose file getting-started cites must exist: %v", err)
	}
	for _, step := range []string{"connect a ca", "install an agent", "first cert"} {
		if !strings.Contains(lower, step) {
			t.Errorf("getting-started should walk the wizard step %q", step)
		}
	}
}

// TestObservabilityDocIsReal cross-checks the observability page against the
// code: it documents the real endpoints and a metric the control plane actually
// emits, and the shipped Prometheus rules / dashboard exist.
func TestObservabilityDocIsReal(t *testing.T) {
	body := read(t, "observability.md")
	for _, want := range []string{"/metrics", "/readyz", "traceparent", "certctl_http_requests_total"} {
		if !strings.Contains(body, want) {
			t.Errorf("observability.md should document %q", want)
		}
	}
	// The documented metric is the one the middleware emits.
	mw := read(t, "../internal/observ/middleware.go")
	if !strings.Contains(mw, "certctl_http_requests_total") {
		t.Error("observability.md cites certctl_http_requests_total but the middleware does not emit it")
	}
	// The control plane mounts the documented endpoints.
	srv := read(t, "../internal/server/server.go")
	if !strings.Contains(srv, "/metrics") || !strings.Contains(srv, "/readyz") {
		t.Error("observability.md documents /metrics and /readyz but the server does not mount them")
	}
	// The baseline operator assets exist.
	for _, f := range []string{"../deploy/observability/alerts.yml", "../deploy/observability/dashboard.json"} {
		if _, err := os.Stat(filepath.FromSlash(f)); err != nil {
			t.Errorf("missing operator asset %s: %v", f, err)
		}
	}
}

// TestOperationsDocIsReal cross-checks the resilience page against the code: it
// documents the live-path controls (bulkheads, rate limiting with 429, graceful
// drain, fail-closed signing) and a setting the loader actually reads, and the
// server actually wires the bulkhead.
func TestOperationsDocIsReal(t *testing.T) {
	lower := strings.ToLower(read(t, "operations.md"))
	for _, want := range []string{"bulkhead", "rate limit", "429", "retry-after", "drain", "fail"} {
		if !strings.Contains(lower, want) {
			t.Errorf("operations.md should cover %q", want)
		}
	}
	if !strings.Contains(read(t, "operations.md"), "CERTCTL_RATE_LIMIT_REQUESTS") {
		t.Error("operations.md should document the rate-limit budget setting")
	}
	if code := read(t, "../internal/config/config.go"); !strings.Contains(code, "CERTCTL_RATE_LIMIT_REQUESTS") {
		t.Error("CERTCTL_RATE_LIMIT_REQUESTS is documented but the loader does not read it")
	}
	if srv := read(t, "../internal/server/server.go"); !strings.Contains(srv, "bulkhead") {
		t.Error("operations.md documents bulkheads but the server does not wire one")
	}
}

// TestDisasterRecoveryDocIsReal cross-checks the DR page against the code: it
// documents the real backup/restore commands and recovery objectives, and the
// binary actually implements the flags it cites.
func TestDisasterRecoveryDocIsReal(t *testing.T) {
	body := read(t, "disaster-recovery.md")
	for _, want := range []string{"--backup", "--restore", "RPO", "RTO", "event log", "rebuild"} {
		if !strings.Contains(body, want) {
			t.Errorf("disaster-recovery.md should cover %q", want)
		}
	}
	// The documented flags exist in the binary.
	main := read(t, "../cmd/certctl/main.go")
	for _, flag := range []string{`"backup"`, `"restore"`} {
		if !strings.Contains(main, flag) {
			t.Errorf("disaster-recovery.md documents a flag the binary does not define: %s", flag)
		}
	}
	// The restore path rebuilds from the event log (the AN-2 guarantee the doc rests on).
	if !strings.Contains(read(t, "../internal/server/backup.go"), "Rebuild") {
		t.Error("restore should rebuild the read model from the restored log")
	}
}

var mdRef = regexp.MustCompile(`[\w./-]+\.md`)

// TestMkdocsNavResolves: every page the MkDocs nav references exists under the
// docs directory.
func TestMkdocsNavResolves(t *testing.T) {
	cfg := read(t, "../mkdocs.yml")
	refs := mdRef.FindAllString(cfg, -1)
	if len(refs) < len(requiredPages) {
		t.Fatalf("mkdocs.yml lists %d pages, fewer than the %d required", len(refs), len(requiredPages))
	}
	seen := map[string]bool{}
	for _, r := range refs {
		if seen[r] {
			continue
		}
		seen[r] = true
		if _, err := os.Stat(filepath.FromSlash(r)); err != nil {
			t.Errorf("mkdocs.yml nav references %q, which does not exist under docs/", r)
		}
	}
}

// TestConnectorGuideTracksSDK: the connector authoring guide names the real SDK
// surface, and those symbols still exist in the SDK.
func TestConnectorGuideTracksSDK(t *testing.T) {
	body := read(t, "guides/connector-authoring.md")
	for _, sym := range []string{"Connector", "Deploy", "Capabilities", "Sandbox"} {
		if !strings.Contains(body, sym) {
			t.Errorf("connector guide should reference the SDK symbol %q", sym)
		}
	}
	sdk := read(t, "../internal/connector/connector.go")
	for _, sym := range []string{"Connector", "Sandbox"} {
		if !strings.Contains(sdk, sym) {
			t.Errorf("internal/connector no longer defines %q; the guide is stale", sym)
		}
	}
}

// TestPluginGuideTracksHost: the plugin authoring guide covers the capability
// model of the real WASM plugin host.
func TestPluginGuideTracksHost(t *testing.T) {
	lower := strings.ToLower(read(t, "guides/plugin-authoring.md"))
	for _, term := range []string{"capabilit", "grant", "wazero", "conformance"} {
		if !strings.Contains(lower, term) {
			t.Errorf("plugin guide should cover %q", term)
		}
	}
}

// TestConfigurationDocCitesRealEnvVars: the configuration reference documents
// environment variables that the config loader actually reads.
func TestConfigurationDocCitesRealEnvVars(t *testing.T) {
	body := read(t, "configuration.md")
	code := read(t, "../internal/config/config.go")
	for _, env := range []string{"CERTCTL_POSTGRES_MODE", "CERTCTL_NATS_URL", "CERTCTL_TELEMETRY_ENABLED", "CERTCTL_SERVER_ADDR", "CERTCTL_AUDIT_SIGNING_KEY_FILE", "CERTCTL_AUDIT_RETENTION", "CERTCTL_RATE_LIMIT_REQUESTS"} {
		if !strings.Contains(body, env) {
			t.Errorf("configuration.md should document %s", env)
		}
		if !strings.Contains(code, env) {
			t.Errorf("%s is documented but internal/config does not read it; the doc is stale", env)
		}
	}
}

// TestComplianceDocIsHonest encodes the R2.1 acceptance "state explicitly which
// framework controls this enables vs. what the operator must still do (no
// overclaiming)": the compliance page must frame controls as enabled (not
// certified), assign the operator their responsibilities, document the
// tamper-evidence model, and cite the real audit signing-key setting.
func TestComplianceDocIsHonest(t *testing.T) {
	body := read(t, "compliance.md")
	lower := strings.ToLower(body)

	for _, marker := range []string{"operator", "enables", "tamper", "retention"} {
		if !strings.Contains(lower, marker) {
			t.Errorf("compliance.md should address %q", marker)
		}
	}
	// No-overclaiming: an explicit disclaimer that deploying certctl is not itself
	// compliance/certification.
	if !strings.Contains(lower, "not a claim") && !strings.Contains(lower, "certification is yours") {
		t.Error("compliance.md must explicitly disclaim that certctl alone makes you compliant/certified")
	}
	// Reality cross-check: it points at a setting the config loader actually reads.
	if !strings.Contains(body, "CERTCTL_AUDIT_SIGNING_KEY_FILE") {
		t.Error("compliance.md should reference the persistent audit signing-key setting")
	}
	code := read(t, "../internal/config/config.go")
	if !strings.Contains(code, "CERTCTL_AUDIT_SIGNING_KEY_FILE") {
		t.Error("CERTCTL_AUDIT_SIGNING_KEY_FILE is referenced in docs but the config loader does not read it")
	}
}

// TestCLIDocCitesRealCommands: the CLI reference documents command groups that
// the CLI actually serves.
func TestCLIDocCitesRealCommands(t *testing.T) {
	body := read(t, "cli.md")
	cmd := read(t, "../internal/cli/command.go")
	for _, group := range []string{"owners", "issuers", "identities", "certificates", "risk", "agents"} {
		if !strings.Contains(body, group) {
			t.Errorf("cli.md should document the %q command group", group)
		}
		if !strings.Contains(cmd, group) {
			t.Errorf("%q is documented but is not a real CLI command group", group)
		}
	}
}
