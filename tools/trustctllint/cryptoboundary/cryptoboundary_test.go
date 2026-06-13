package cryptoboundary_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trustctl.io/trustctl/tools/trustctllint/cryptoboundary"
)

// TestCryptoBoundary exercises AN-3: crypto/* may be imported only inside
// internal/crypto (and its subpackages). The fixtures live under testdata/src
// at paths that mirror the real module layout so the boundary check is tested
// against realistic package paths.
func TestCryptoBoundary(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), cryptoboundary.Analyzer,
		"trustctl.io/trustctl/internal/crypto",          // the boundary: allowed
		"trustctl.io/trustctl/internal/crypto/software", // subpackage of the boundary: allowed
		"trustctl.io/trustctl/internal/store",           // violation: imports crypto/*
		"cleanpkg",                                      // clean: no crypto import at all
	)
}
