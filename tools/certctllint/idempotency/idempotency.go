// Package idempotency implements the AN-5 architecture rule: a mutating API
// handler must accept and honor an idempotency key, so a retried request cannot
// execute the same mutation twice.
//
// This is the narrow form for S0.2: a handler opts in by carrying the
// //certctl:mutation marker on its doc comment, after which its body must
// reference an idempotency key (the "Idempotency-Key" header, or any identifier
// containing "idempotency"). The rule will tighten to auto-detect mutating
// handlers from their route/method as the API and orchestrator land.
package idempotency

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"

	"certctl.io/certctl/tools/certctllint/internal/directive"
)

const mutationMarker = "certctl:mutation"

// Analyzer enforces AN-5.
var Analyzer = &analysis.Analyzer{
	Name: "idempotency",
	Doc:  "AN-5: handlers marked //certctl:mutation must accept and honor an idempotency key.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if !directive.OnFunc(fn, mutationMarker) {
				continue
			}
			if !honorsIdempotency(fn.Body) {
				pass.Reportf(fn.Pos(),
					"mutating handler must accept and honor an idempotency key (AN-5)")
			}
		}
	}
	return nil, nil
}

// honorsIdempotency reports whether a function body references an idempotency
// key, either via a string literal (such as the "Idempotency-Key" header) or an
// identifier whose name mentions idempotency.
func honorsIdempotency(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			if strings.Contains(strings.ToLower(x.Name), "idempotency") {
				found = true
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				if s, err := strconv.Unquote(x.Value); err == nil &&
					strings.Contains(strings.ToLower(s), "idempotency") {
					found = true
				}
			}
		}
		return !found // stop walking once found
	})
	return found
}
