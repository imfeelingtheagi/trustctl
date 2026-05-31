package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"certctl.io/certctl/tools/certctllint/cryptoboundary"
	"certctl.io/certctl/tools/certctllint/eventsource"
	"certctl.io/certctl/tools/certctllint/idempotency"
	"certctl.io/certctl/tools/certctllint/keymaterial"
	"certctl.io/certctl/tools/certctllint/tenantfilter"
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
