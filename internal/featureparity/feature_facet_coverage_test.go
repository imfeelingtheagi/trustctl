package featureparity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var featureFacetNames = []string{
	"served",
	"ui",
	"cli",
	"api",
	"test",
	"docs",
	"rbac",
	"audit",
	"telemetry",
	"a11y",
	"i18n",
}

var gaServedStates = map[string]bool{
	"served":      true,
	"conditional": true,
	"partial":     true,
}

var gaEvidenceRequired = map[string]bool{
	"served": true,
	"ui":     true,
	"test":   true,
	"docs":   true,
	"a11y":   true,
	"i18n":   true,
}

// TestFeatureFacetCoverage is the generated acceptance contract for COVER-006:
// every catalog row must have explicit evidence or an explicit N/A for each
// feature facet, and GA-ish rows must carry concrete evidence for the facets that
// are always applicable to a shipped operator surface.
func TestFeatureFacetCoverage(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("find repo root: %v", err)
	}

	for _, item := range catalog.Items {
		cells := item.FacetEvidence.Cells()
		isGA := gaServedStates[item.ServedState]
		for _, facet := range featureFacetNames {
			cell := cells[facet]
			hasEvidence := len(nonBlank(cell.Evidence)) > 0
			hasNA := strings.TrimSpace(cell.NA) != ""
			if !hasEvidence && !hasNA {
				t.Errorf("%s (%s) facet %q has no evidence and no explicit N/A", item.FeatureID, item.Feature, facet)
				continue
			}
			if hasEvidence && hasNA {
				t.Errorf("%s (%s) facet %q declares both evidence and N/A", item.FeatureID, item.Feature, facet)
			}
			if isGA && gaEvidenceRequired[facet] && !hasEvidence {
				t.Errorf("%s (%s) GA facet %q must have evidence, got N/A %q", item.FeatureID, item.Feature, facet, cell.NA)
			}
			if hasNA && !strings.HasPrefix(strings.TrimSpace(cell.NA), "N/A:") {
				t.Errorf("%s (%s) facet %q N/A reason must start with N/A:, got %q", item.FeatureID, item.Feature, facet, cell.NA)
			}
			for _, ref := range cell.Refs {
				if strings.TrimSpace(ref) == "" {
					t.Errorf("%s (%s) facet %q has a blank ref", item.FeatureID, item.Feature, facet)
					continue
				}
				if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(ref))); err != nil {
					t.Errorf("%s (%s) facet %q references missing file %q: %v", item.FeatureID, item.Feature, facet, ref, err)
				}
			}
		}
		checkFacetAlignment(t, item)
	}
}

func checkFacetAlignment(t *testing.T, item Item) {
	t.Helper()
	cells := item.FacetEvidence.Cells()
	if gaServedStates[item.ServedState] && strings.TrimSpace(cells["served"].NA) != "" {
		t.Errorf("%s (%s) is %s but served facet is N/A", item.FeatureID, item.Feature, item.ServedState)
	}
	if !gaServedStates[item.ServedState] && len(nonBlank(cells["served"].Evidence)) > 0 {
		t.Errorf("%s (%s) is %s but served facet claims evidence", item.FeatureID, item.Feature, item.ServedState)
	}
	if len(item.APISurface) > 0 && len(nonBlank(cells["api"].Evidence)) == 0 {
		t.Errorf("%s (%s) has api_surface entries but API facet has no evidence", item.FeatureID, item.Feature)
	}
	if len(item.APISurface) == 0 && strings.TrimSpace(item.APINA) != "" && strings.TrimSpace(cells["api"].NA) == "" {
		t.Errorf("%s (%s) has api_na but API facet has no N/A reason", item.FeatureID, item.Feature)
	}
	if len(item.CLISurface) > 0 && len(nonBlank(cells["cli"].Evidence)) == 0 {
		t.Errorf("%s (%s) has cli_surface entries but CLI facet has no evidence", item.FeatureID, item.Feature)
	}
	if len(item.CLISurface) == 0 && strings.TrimSpace(item.CLINA) != "" && strings.TrimSpace(cells["cli"].NA) == "" {
		t.Errorf("%s (%s) has cli_na but CLI facet has no N/A reason", item.FeatureID, item.Feature)
	}
	if len(item.SourceDocs) > 0 {
		docRefs := map[string]bool{}
		for _, ref := range cells["docs"].Refs {
			docRefs[ref] = true
		}
		for _, doc := range item.SourceDocs {
			if !docRefs[doc] {
				t.Errorf("%s (%s) docs facet must cite source_docs ref %q", item.FeatureID, item.Feature, doc)
			}
		}
	}
}

func nonBlank(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}
