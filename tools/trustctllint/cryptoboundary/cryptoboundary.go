// Package cryptoboundary implements the AN-3 architecture rule: the standard
// library's crypto and crypto/* packages may be imported only from within
// internal/crypto (and its subpackages), which is the one sanctioned
// cryptography boundary. Every other package must route crypto operations
// through that boundary's interfaces.
package cryptoboundary

import (
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const (
	modulePath  = "trustctl.io/trustctl"
	boundaryPkg = modulePath + "/internal/crypto"
)

// Analyzer enforces AN-3.
var Analyzer = &analysis.Analyzer{
	Name: "cryptoboundary",
	Doc:  "AN-3: crypto/* may be imported only inside internal/crypto and its subpackages.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	if withinBoundary(pass.Pkg.Path()) {
		return nil, nil
	}
	for _, file := range pass.Files {
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if isCryptoImport(path) {
				pass.Reportf(imp.Pos(),
					"import %q is not allowed outside internal/crypto (AN-3); route crypto through the internal/crypto boundary",
					path)
			}
		}
	}
	return nil, nil
}

// withinBoundary reports whether pkgPath is the crypto boundary or a subpackage
// of it (for example a backend implementation under internal/crypto).
func withinBoundary(pkgPath string) bool {
	return pkgPath == boundaryPkg || strings.HasPrefix(pkgPath, boundaryPkg+"/")
}

// isCryptoImport reports whether an import path is the stdlib crypto package or
// one of its subpackages (crypto, crypto/x509, crypto/ecdsa, ...).
func isCryptoImport(path string) bool {
	return path == "crypto" || strings.HasPrefix(path, "crypto/")
}
