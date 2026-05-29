// Package keymaterial implements the AN-8 architecture rule: in packages that
// handle secret key material, key bytes must live in []byte (which can be
// mlock'd, marked non-dumpable, and explicitly zeroed), never in string (which
// Go's garbage collector may copy freely and which cannot be wiped).
//
// This is the narrow form for S0.2: a package opts in by carrying the
// //certctl:keymaterial marker, after which any string-typed struct field,
// parameter, or result is flagged. The marker is applied to the real
// key-handling packages as they land (internal/crypto, the signer, the secret
// buffer primitives), tightening enforcement over time.
package keymaterial

import (
	"go/ast"

	"golang.org/x/tools/go/analysis"

	"certctl.io/certctl/tools/certctllint/internal/directive"
)

const keyMaterialMarker = "certctl:keymaterial"

// Analyzer enforces AN-8.
var Analyzer = &analysis.Analyzer{
	Name: "keymaterial",
	Doc:  "AN-8: packages marked //certctl:keymaterial must not use string for key material; use []byte.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	if !directive.Present(pass.Files, keyMaterialMarker) {
		return nil, nil
	}
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			field, ok := n.(*ast.Field)
			if !ok {
				return true
			}
			if id, ok := field.Type.(*ast.Ident); ok && id.Name == "string" {
				pass.Reportf(field.Type.Pos(),
					"key-handling package must not use string for key material; use []byte (AN-8)")
			}
			return true
		})
	}
	return nil, nil
}
