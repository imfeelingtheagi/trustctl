package featureparity

import (
	"strings"
	"testing"
)

const (
	gaServedScopeIn  = "in_ga"
	gaServedScopeOut = "out_of_ga"
)

var residualServedStates = map[string]bool{
	"conditional": true,
	"partial":     true,
	"library":     true,
	"roadmap":     true,
}

// TestFeatureServedGACoverageCOVER001 locks the COVER-001 acceptance:
// the GA served denominator must be 100% served. Rows that remain conditional
// or partial must be explicitly out of GA scope, with a human-readable reason,
// so the catalog does not count residual capability as fully GA-served.
func TestFeatureServedGACoverageCOVER001(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	gaRows := 0
	gaServedRows := 0
	for _, item := range catalog.Items {
		scope := strings.TrimSpace(item.GAServedScope)
		if scope == "" {
			scope = gaServedScopeIn
		}

		switch {
		case item.ServedState == "served":
			if scope == gaServedScopeOut {
				t.Errorf("%s (%s) is served but excluded from the GA served denominator", item.FeatureID, item.Feature)
				continue
			}
			if scope != gaServedScopeIn {
				t.Errorf("%s (%s) has invalid ga_served_scope %q", item.FeatureID, item.Feature, item.GAServedScope)
				continue
			}
			gaRows++
			gaServedRows++
		case residualServedStates[item.ServedState]:
			if scope != gaServedScopeOut {
				t.Errorf("%s (%s) served_state=%s must set ga_served_scope=%q or be promoted to served", item.FeatureID, item.Feature, item.ServedState, gaServedScopeOut)
			}
			reason := strings.TrimSpace(item.GAScopeReason)
			if len(strings.Fields(reason)) < 6 {
				t.Errorf("%s (%s) must explain why the residual row is out of GA scope, got %q", item.FeatureID, item.Feature, reason)
			}
			if !strings.Contains(strings.ToLower(reason), "residual") {
				t.Errorf("%s (%s) ga_scope_reason must name the residual GA gap, got %q", item.FeatureID, item.Feature, reason)
			}
		default:
			t.Errorf("%s (%s) has invalid served_state %q", item.FeatureID, item.Feature, item.ServedState)
		}
	}

	if gaRows == 0 {
		t.Fatal("GA served denominator is empty")
	}
	if gaServedRows != gaRows {
		t.Fatalf("GA served coverage = %d/%d, want 100%%", gaServedRows, gaRows)
	}
}
