package eventsource_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trustctl.io/trustctl/tools/trustctllint/eventsource"
)

// TestEventSource exercises AN-2 enforcement: a served mutating handler (marked
// //trustctl:mutation) must not write the relational read model directly through
// a store mutator — it must emit an event and let the projection build the read
// model. A planted direct-to-table write fails the build.
func TestEventSource(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), eventsource.Analyzer, "trustctl.io/trustctl/internal/api")
}
