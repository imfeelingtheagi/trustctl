package idempotency_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trustctl.io/trustctl/tools/trustctllint/idempotency"
)

// TestIdempotency exercises AN-5: a handler marked //trustctl:mutation must
// thread an idempotency key into a real dedupe sink (orchestrator.Idempotency.Do
// or a key-accepting forwarding call such as API.mutate). Merely naming the key,
// passing it to a logger, or declaring an unused idempotency parameter does not
// satisfy the rule (ARCH-002). Unmarked functions are ignored. The fixture lives
// under the real module path so it can import the orchestrator stub for
// type-resolved sink detection.
func TestIdempotency(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), idempotency.Analyzer,
		"trustctl.io/trustctl/internal/api")
}
