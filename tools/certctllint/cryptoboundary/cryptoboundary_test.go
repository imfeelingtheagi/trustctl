package cryptoboundary_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"certctl.io/certctl/tools/certctllint/cryptoboundary"
)

// TestCryptoBoundary exercises AN-3: crypto/* may be imported only inside
// internal/crypto (and its subpackages). The fixtures live under testdata/src
// at paths that mirror the real module layout so the boundary check is tested
// against realistic package paths.
func TestCryptoBoundary(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), cryptoboundary.Analyzer,
		"certctl.io/certctl/internal/crypto",          // the boundary: allowed
		"certctl.io/certctl/internal/crypto/software", // subpackage of the boundary: allowed
		"certctl.io/certctl/internal/store",           // violation: imports crypto/*
		"cleanpkg",                                    // clean: no crypto import at all
	)
}
