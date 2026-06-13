package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"trustctl.io/trustctl/tools/trustctllint/cryptoboundary"
	"trustctl.io/trustctl/tools/trustctllint/eventsource"
	"trustctl.io/trustctl/tools/trustctllint/idempotency"
	"trustctl.io/trustctl/tools/trustctllint/keymaterial"
	"trustctl.io/trustctl/tools/trustctllint/tenantfilter"
)

func main() {
	multichecker.Main(
		cryptoboundary.Analyzer, // AN-3
		tenantfilter.Analyzer,   // AN-1
		keymaterial.Analyzer,    // AN-8
		idempotency.Analyzer,    // AN-5
		eventsource.Analyzer,    // AN-2
	)
}
