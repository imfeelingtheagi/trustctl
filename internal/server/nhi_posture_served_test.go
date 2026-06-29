package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// TestServedNHIOverPrivilegeCAPPOST01EndToEnd proves CAP-POST-01 is served:
// the public API analyzes managed and discovered NHIs, detects granted-vs-used
// over-privilege, and returns usage-driven least-privilege recommendations.
func TestServedNHIOverPrivilegeCAPPOST01EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "nhi:read")
	ctx := context.Background()

	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerTeam, Name: "Platform Team", Email: "platform@example.test"})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}

	seedIdentity := func(id, name string, attrs map[string]any) {
		t.Helper()
		raw, err := json.Marshal(attrs)
		if err != nil {
			t.Fatalf("marshal attrs for %s: %v", id, err)
		}
		if err := h.store.UpsertIdentity(ctx, store.Identity{
			ID: id, TenantID: h.tenant, Kind: store.KindAPIKey, Name: name,
			OwnerID: owner.ID, Status: "deployed", Attributes: raw,
		}); err != nil {
			t.Fatalf("seed identity %s: %v", id, err)
		}
	}

	seedIdentity("22222222-2222-2222-2222-22222222a001", "payments-admin-token", map[string]any{
		"granted_scopes": []string{"repo:read", "repo:write", "admin:org", "secrets:write"},
		"used_scopes":    []string{"repo:read"},
		"last_used_at":   "2026-05-01T00:00:00Z",
	})
	seedIdentity("22222222-2222-2222-2222-22222222a002", "read-only-token", map[string]any{
		"granted_scopes": []string{"repo:read"},
		"used_scopes":    []string{"repo:read"},
		"last_used_at":   "2026-05-02T00:00:00Z",
	})
	seedDiscoveryPostureFinding(t, h.store, h.tenant, map[string]any{
		"credential_kind":      "oauth_app",
		"principal":            "legacy-github-app",
		"granted_permissions":  []string{"repo", "admin:org", "workflow"},
		"observed_permissions": []string{"repo"},
		"last_used_at":         "2026-04-01T00:00:00Z",
	})

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/overprivilege", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("NHI over-privilege posture: status %d body %s", status, body)
	}
	var got struct {
		Capability string   `json:"capability"`
		Coverage   []string `json:"coverage"`
		Summary    struct {
			TotalAnalyzed       int `json:"total_analyzed"`
			Overprivileged      int `json:"overprivileged"`
			LeastPrivilegePlans int `json:"least_privilege_plans"`
			UnusedGrants        int `json:"unused_grants"`
		} `json:"summary"`
		Findings []struct {
			InventoryID       string   `json:"inventory_id"`
			DisplayName       string   `json:"display_name"`
			Kind              string   `json:"kind"`
			Source            string   `json:"source"`
			Severity          string   `json:"severity"`
			FindingTypes      []string `json:"finding_types"`
			GrantedScopes     []string `json:"granted_scopes"`
			UsedScopes        []string `json:"used_scopes"`
			UnusedScopes      []string `json:"unused_scopes"`
			RecommendedScopes []string `json:"recommended_scopes"`
			Recommendation    string   `json:"recommendation"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode posture response: %v (%s)", err, body)
	}
	if got.Capability != "CAP-POST-01" {
		t.Fatalf("capability = %q, want CAP-POST-01", got.Capability)
	}
	for _, want := range []string{"managed_identities", "discovery_findings", "usage_driven_scope_delta", "least_privilege_recommendations"} {
		if !containsString(got.Coverage, want) {
			t.Fatalf("coverage %v missing %q", got.Coverage, want)
		}
	}
	if got.Summary.TotalAnalyzed != 3 || got.Summary.Overprivileged != 2 || got.Summary.LeastPrivilegePlans != 2 || got.Summary.UnusedGrants != 5 {
		t.Fatalf("summary = %+v, want 3 analyzed / 2 overprivileged / 2 plans / 5 unused", got.Summary)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("findings count = %d body %s, want 2", len(got.Findings), body)
	}
	byName := map[string]struct {
		unused []string
		used   []string
		source string
	}{}
	for _, f := range got.Findings {
		byName[f.DisplayName] = struct {
			unused []string
			used   []string
			source string
		}{unused: f.UnusedScopes, used: f.RecommendedScopes, source: f.Source}
		if f.Severity == "" || !containsString(f.FindingTypes, "unused_grants") || f.Recommendation == "" {
			t.Fatalf("finding lacks severity/type/recommendation: %+v", f)
		}
	}
	payments, ok := byName["payments-admin-token"]
	if !ok || !containsString(payments.unused, "admin:org") || !containsString(payments.unused, "secrets:write") || !containsString(payments.used, "repo:read") {
		t.Fatalf("managed identity recommendation = %+v, want unused admin/secrets and repo:read plan", payments)
	}
	discovered, ok := byName["legacy-github-app"]
	if !ok || discovered.source != "discovery_finding" || !containsString(discovered.unused, "admin:org") || !containsString(discovered.used, "repo") {
		t.Fatalf("discovered NHI recommendation = %+v, want discovery finding with admin:org removal and repo plan", discovered)
	}
}

func seedDiscoveryPostureFinding(t *testing.T, s *store.Store, tenantID string, metadata map[string]any) {
	t.Helper()
	ctx := context.Background()
	sourceID := "22222222-2222-2222-2222-22222222b001"
	runID := "22222222-2222-2222-2222-22222222b002"
	findingID := "22222222-2222-2222-2222-22222222b003"
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshal discovery metadata: %v", err)
	}
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: tenantID, Kind: "nhi", Name: "nhi-posture",
			Config: []byte(`{}`), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: runID, TenantID: tenantID, SourceID: sourceID, Status: "queued", CreatedAt: time.Now().UTC(),
		}); err != nil {
			return err
		}
		return s.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
			ID: findingID, TenantID: tenantID, RunID: runID, SourceID: sourceID,
			Kind: "non_human_identity", Ref: "github-app://legacy", Provenance: "oauth-saas",
			Fingerprint: "fp-legacy-github-app", RiskScore: 84, Metadata: raw,
			DiscoveredAt: time.Now().UTC(),
		})
	}); err != nil {
		t.Fatalf("seed discovery finding: %v", err)
	}
}
