// Package eventsource implements the AN-2 architecture rule: a served mutating
// handler must not write the relational read model directly. State changes are
// emitted as events to the append-only log (the source of truth); the read
// model is a projection of that log. A handler that calls a store read-model
// mutator (CreateOwner, UpsertCertificate, …) bypasses the log, so the audit
// trail and a rebuild-from-log cannot reproduce the change.
//
// A handler opts into the served-mutation surface with the //certctl:mutation
// marker (the same marker AN-5 uses — these are the same handlers). Inside such
// a handler, a call to a Create/Update/Delete/Upsert/Set method on the store is
// a violation: the handler must instead emit a domain event and let the
// projection build the read model. Reads (Get*/List*/Exists*) are unaffected.
//
// The rule is deliberately scoped to the served mutation surface (the handlers
// the audit flagged for direct-to-table writes). The projector — the one
// sanctioned writer of the read model — is not a mutation handler, so it is not
// constrained here.
package eventsource

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"

	"certctl.io/certctl/tools/certctllint/internal/directive"
)

const (
	mutationMarker = "certctl:mutation"
	storePkgPath   = "certctl.io/certctl/internal/store"
	storeTypeName  = "Store"
)

// mutatorPrefixes name the store methods that write the relational read model.
// Read methods (Get/List/Exists/Lookup) and event helpers are not listed, so
// they remain available to handlers.
var mutatorPrefixes = []string{"Create", "Update", "Delete", "Upsert", "Set"}

// Analyzer enforces AN-2.
var Analyzer = &analysis.Analyzer{
	Name: "eventsource",
	Doc:  "AN-2: a //certctl:mutation handler must not write the read model directly; it must emit an event.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !directive.OnFunc(fn, mutationMarker) {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !isMutatorName(sel.Sel.Name) {
					return true
				}
				if isStoreReceiver(pass, sel.X) {
					pass.Reportf(call.Pos(),
						"served mutation must not write the read model directly via store.%s; emit an event and project it (AN-2)",
						sel.Sel.Name)
				}
				return true
			})
		}
	}
	return nil, nil
}

// isStoreReceiver reports whether expr has type *store.Store (the read-model
// repository). Resolution is by type, so it cannot be evaded by aliasing the
// receiver's name.
func isStoreReceiver(pass *analysis.Pass, expr ast.Expr) bool {
	tv, ok := pass.TypesInfo.Types[expr]
	if !ok {
		return false
	}
	ptr, ok := tv.Type.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := ptr.Elem().(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == storeTypeName &&
		obj.Pkg() != nil && obj.Pkg().Path() == storePkgPath
}

// isMutatorName reports whether a method name writes the read model: it begins
// with a mutator verb and the remainder is empty or starts a new word (an
// uppercase letter), so "Settings" would not match "Set".
func isMutatorName(name string) bool {
	for _, p := range mutatorPrefixes {
		if !strings.HasPrefix(name, p) {
			continue
		}
		rest := name[len(p):]
		if rest == "" || (rest[0] >= 'A' && rest[0] <= 'Z') {
			return true
		}
	}
	return false
}
