package server

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

var sec07SlackBotToken = strings.Join([]string{
	"xoxb",
	"123456789012",
	"123456789012",
	"abcdefghijklmnopqrstuvwx",
}, "-")

// TestServedGitleaksScanDetectsPlantedSecret is the SEC-07 acceptance proof:
// the running control plane invokes the real pinned Gitleaks binary through the
// served /api/v1/secrets/scans route, detects a planted secret with the default
// 140+ rule set active, records the finding through discovery events, and never
// echoes the secret value into responses or the event log.
func TestServedGitleaksScanDetectsPlantedSecret(t *testing.T) {
	bin := requireGitleaksBinary(t)
	t.Setenv("TRSTCTL_GITLEAKS_BIN", bin)

	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("SLACK_TOKEN="+sec07SlackBotToken+"\n"), 0o644); err != nil {
		t.Fatalf("write planted secret fixture: %v", err)
	}

	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:write", "discovery:read", "graph:read")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans", tok, "sec-07-gitleaks-scan", map[string]any{
		"path": repo,
	})
	if status != http.StatusCreated {
		t.Fatalf("start gitleaks scan: status %d body %s", status, body)
	}
	assertNoPlantedSecret(t, "scan response", body)

	var scan struct {
		RunID         string `json:"run_id"`
		Scanner       string `json:"scanner"`
		RulesActive   int    `json:"rules_active"`
		FindingsCount int    `json:"findings_count"`
		Findings      []struct {
			RuleID        string `json:"rule_id"`
			File          string `json:"file"`
			Line          int    `json:"line"`
			CredentialRef string `json:"credential_ref"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &scan); err != nil {
		t.Fatalf("decode scan response: %v (%s)", err, body)
	}
	if scan.Scanner != "gitleaks" || scan.RunID == "" {
		t.Fatalf("scan response = %+v, want gitleaks scanner and a run id", scan)
	}
	if scan.RulesActive < 140 {
		t.Fatalf("rules_active = %d, want the pinned default rule set with 140+ rules", scan.RulesActive)
	}
	if scan.FindingsCount < 1 || len(scan.Findings) < 1 {
		t.Fatalf("scan response has no findings: %+v", scan)
	}
	if scan.Findings[0].RuleID != "slack-bot-token" || !strings.HasSuffix(scan.Findings[0].File, "app.env") || scan.Findings[0].Line != 1 {
		t.Fatalf("first finding = %+v, want slack-bot-token in app.env line 1", scan.Findings[0])
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+scan.RunID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list scan discovery findings: status %d body %s", status, body)
	}
	assertNoPlantedSecret(t, "discovery response", body)
	if !strings.Contains(string(body), "slack-bot-token@app.env") || !strings.Contains(string(body), `"kind":"leaked_secret"`) {
		t.Fatalf("discovery response does not expose the scan finding metadata: %s", body)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/graph", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get graph after scan: status %d body %s", status, body)
	}
	assertNoPlantedSecret(t, "graph response", body)
	if !strings.Contains(string(body), "slack-bot-token@app.env") || !strings.Contains(string(body), `"credential_kind":"leaked_secret"`) {
		t.Fatalf("graph response does not include the leaked-secret credential node: %s", body)
	}

	if !h.hasEvent(t, "discovery.finding.recorded") || !h.hasEvent(t, "discovery.run.completed") {
		t.Fatal("served gitleaks scan did not record discovery events")
	}
	if h.logContains(t, sec07SlackBotToken) {
		t.Fatal("the event log contains the planted secret value")
	}
}

func requireGitleaksBinary(t *testing.T) string {
	t.Helper()
	candidates := []string{os.Getenv("TRSTCTL_GITLEAKS_BIN"), "/private/tmp/trstctl-tools/gitleaks"}
	if path, err := exec.LookPath("gitleaks"); err == nil {
		candidates = append(candidates, path)
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate
		}
	}
	t.Skip("SEC-07 acceptance requires the pinned Gitleaks binary; install github.com/zricethezav/gitleaks/v8@v8.27.2 or set TRSTCTL_GITLEAKS_BIN")
	return ""
}

func assertNoPlantedSecret(t *testing.T, label string, body []byte) {
	t.Helper()
	if strings.Contains(string(body), sec07SlackBotToken) {
		t.Fatalf("%s leaked the planted secret value: %s", label, body)
	}
}
