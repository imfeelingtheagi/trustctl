package docs

import (
	"strings"
	"testing"
)

func TestProductDecisionRegisterCapturesReport007Recommendations(t *testing.T) {
	page := read(t, "product-decision-register.md")
	index := read(t, "index.md")

	if !strings.Contains(index, "product-decision-register.md") {
		t.Fatal("docs index must link the REPORT-007 product decision register")
	}

	required := []string{
		"REPORT-007",
		"Needs human decision",
		"not product truth until approved",
		"NARRATIVE-001",
		"self-hosted non-human identity management / Machine IAM control plane",
		"NARRATIVE-002",
		"no per-certificate and no ephemeral-identity billing",
		"NARRATIVE-003",
		"live eval receipts",
		"OWASP NHI mapping",
		"NARRATIVE-004",
		"served-now, conditional, partial, and roadmap",
		"PACKAGING-001",
		"billable unit",
		"PACKAGING-002",
		"Community, Enterprise, Provider, and Managed",
		"PACKAGING-003",
		"certificate counters as operational telemetry",
		"PACKAGING-004",
		"first-party SaaS, MSP/Provider, or self-hosted Provider",
	}
	for _, want := range required {
		if !strings.Contains(page, want) {
			t.Errorf("product-decision-register.md missing REPORT-007 marker %q", want)
		}
	}

	forbidden := []string{
		"approved decision",
		"final decision",
		"pricing is",
		"no per-certificate billing is policy",
		"managed offering is first-party saas",
	}
	lower := strings.ToLower(page)
	for _, phrase := range forbidden {
		if strings.Contains(lower, phrase) {
			t.Errorf("product-decision-register.md turns a recommendation into product truth: %q", phrase)
		}
	}
}
