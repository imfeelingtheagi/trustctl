// Package tenantfilter implements the AN-1 architecture rule: data-manipulation
// SQL queries in repository packages must filter on tenant_id, so multi-tenant
// isolation cannot be bypassed by a forgotten WHERE clause.
//
// This is the narrow, "working" form for S0.2: it inspects SQL string literals
// in repository packages. Repository packages are those under internal/store or
// any package carrying the //certctl:repository marker. The rule will tighten
// (for example, to understand a query builder) as the store layer lands.
package tenantfilter

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"

	"certctl.io/certctl/tools/certctllint/internal/directive"
)

const (
	modulePath       = "certctl.io/certctl"
	repositoryPkg    = modulePath + "/internal/store"
	repositoryMarker = "certctl:repository"
)

// Analyzer enforces AN-1.
var Analyzer = &analysis.Analyzer{
	Name: "tenantfilter",
	Doc:  "AN-1: SQL data-manipulation queries in repository packages must filter on tenant_id.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	if !isRepositoryPackage(pass) {
		return nil, nil
	}
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			sql, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if isDML(sql) && !mentionsTenantID(sql) && !referencesSystemTable(sql) {
				pass.Reportf(lit.Pos(),
					"repository query does not filter on tenant_id (AN-1)")
			}
			return true
		})
	}
	return nil, nil
}

// isRepositoryPackage reports whether the package is part of the repository
// layer, either by location (internal/store) or by the //certctl:repository
// marker.
func isRepositoryPackage(pass *analysis.Pass) bool {
	p := pass.Pkg.Path()
	if p == repositoryPkg || strings.HasPrefix(p, repositoryPkg+"/") {
		return true
	}
	return directive.Present(pass.Files, repositoryMarker)
}

// isDML reports whether a string is a SQL data-manipulation statement, i.e. its
// first whitespace-delimited token is SELECT, INSERT, UPDATE, or DELETE. DDL
// such as CREATE/ALTER is intentionally out of scope.
func isDML(s string) bool {
	fields := strings.Fields(strings.ToLower(s))
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "select", "insert", "update", "delete":
		return true
	default:
		return false
	}
}

func mentionsTenantID(s string) bool {
	return strings.Contains(strings.ToLower(s), "tenant_id")
}

// systemTables are non-tenant, infrastructure tables that legitimately carry no
// tenant_id (e.g. the migration ledger). This is the sanctioned escape hatch —
// a fix to the rule itself, not a per-line ignore — and is extended only here,
// with a test fixture.
var systemTables = []string{"schema_migrations"}

// referencesSystemTable reports whether a query targets a known system table.
func referencesSystemTable(s string) bool {
	lower := strings.ToLower(s)
	for _, tbl := range systemTables {
		if strings.Contains(lower, tbl) {
			return true
		}
	}
	return false
}
