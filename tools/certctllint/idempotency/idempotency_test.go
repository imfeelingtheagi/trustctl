package idempotency_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"certctl.io/certctl/tools/certctllint/idempotency"
)

// TestIdempotency exercises AN-5: a handler marked //certctl:mutation must
// accept and honor an idempotency key in its body. Unmarked functions are
// ignored (the rule tightens to auto-detect mutating handlers as the API lands).
func TestIdempotency(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), idempotency.Analyzer, "api")
}
