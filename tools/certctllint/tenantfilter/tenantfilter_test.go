package tenantfilter_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"certctl.io/certctl/tools/certctllint/tenantfilter"
)

// TestTenantFilter exercises AN-1: SQL data-manipulation queries in repository
// packages must filter on tenant_id. Repository packages are recognized by
// living under internal/store, or by carrying the //certctl:repository marker.
// Outside such packages the rule is inactive, so SQL-looking prose is ignored.
func TestTenantFilter(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), tenantfilter.Analyzer,
		"certctl.io/certctl/internal/store", // repository by path
		"repoelsewhere",                     // repository by marker directive
		"notstore",                          // not a repository: ignored
	)
}
