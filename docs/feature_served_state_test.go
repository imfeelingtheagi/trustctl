package docs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type featureMapLedger struct {
	Items []featureMapServedState `json:"items"`
}

type featureMapServedState struct {
	FeatureID              string `json:"feature_id"`
	Feature                string `json:"feature"`
	ServedState            string `json:"served_state"`
	BackendStatus          string `json:"backend_status"`
	CurrentFrontendMapping string `json:"current_frontend_mapping"`
}

func featureServedStateLedger(t *testing.T) featureMapLedger {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash("../web/src/lib/feature-map-backlog.json"))
	if err != nil {
		t.Fatalf("read feature-map backlog: %v", err)
	}
	var ledger featureMapLedger
	if err := json.Unmarshal(b, &ledger); err != nil {
		t.Fatalf("parse feature-map backlog: %v", err)
	}
	if len(ledger.Items) == 0 {
		t.Fatal("feature-map backlog has no items")
	}
	return ledger
}

func TestFeatureCatalogHasExplicitServedState(t *testing.T) {
	valid := map[string]bool{
		"served":      true,
		"conditional": true,
		"partial":     true,
		"library":     true,
		"roadmap":     true,
	}
	byID := map[string]featureMapServedState{}
	counts := map[string]int{}
	for _, item := range featureServedStateLedger(t).Items {
		if item.FeatureID == "" {
			t.Fatalf("feature-map backlog item %q has no feature_id", item.Feature)
		}
		if byID[item.FeatureID].FeatureID != "" {
			t.Fatalf("feature-map backlog duplicates %s", item.FeatureID)
		}
		if !valid[item.ServedState] {
			t.Errorf("%s has invalid served_state %q", item.FeatureID, item.ServedState)
		}
		byID[item.FeatureID] = item
		counts[item.ServedState]++
	}

	for _, ft := range featureCatalog(t) {
		item := byID[ft.id]
		if item.FeatureID == "" {
			t.Errorf("features.tsv row %s (%s) has no feature-map served_state row", ft.id, ft.title)
			continue
		}
		if item.Feature == "" || item.BackendStatus == "" {
			t.Errorf("%s served_state row must carry feature and backend status evidence", ft.id)
		}
	}
	if len(byID) != len(featureCatalog(t)) {
		t.Fatalf("feature-map served_state denominator = %d, features.tsv denominator = %d", len(byID), len(featureCatalog(t)))
	}

	for _, state := range []string{"served", "conditional", "partial", "library", "roadmap"} {
		if counts[state] == 0 {
			t.Errorf("served_state ledger should include at least one %q row so enum handling is exercised", state)
		}
	}

	for _, item := range byID {
		if item.ServedState != "library" && item.ServedState != "roadmap" {
			continue
		}
		if !strings.Contains(strings.ToLower(item.CurrentFrontendMapping), "roadmap-disclosure") {
			t.Errorf("%s is %s but current GUI mapping is not an explicit roadmap disclosure: %q", item.FeatureID, item.ServedState, item.CurrentFrontendMapping)
		}
	}
}

func TestFeatureIndexDoesNotOverclaimAllCatalogRowsAsServed(t *testing.T) {
	body := read(t, "features.md")
	lower := strings.ToLower(body)
	for _, stale := range []string{
		"trstctl ships **78 capabilities**",
		"ships 78 capabilities",
		"all 78 capabilities are served",
		"78 ga capabilities",
	} {
		if strings.Contains(lower, strings.ToLower(stale)) {
			t.Errorf("features.md over-claims the feature catalog with %q", stale)
		}
	}
	for _, want := range []string{
		"tracks **78 capabilities**",
		"served-state metadata",
		"`served_state`",
		"`library`",
		"`roadmap`",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("features.md must explain the served-state catalog contract (missing %q)", want)
		}
	}
}
