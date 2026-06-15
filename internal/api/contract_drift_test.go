package api_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// feInterfaceField captures one field name from a TypeScript interface body line
// like `  status?: string;` or `  id: string;` — the leading identifier before
// the optional `?` and the `:`.
var feInterfaceField = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\??\s*:`)

// readFEInterface extracts the field names of a named TypeScript interface from
// the frontend API client (web/src/lib/api.ts). It returns nil if the interface
// is not found.
func readFEInterface(t *testing.T, name string) []string {
	t.Helper()
	path := filepath.FromSlash("../../web/src/lib/api.ts")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read FE client %s: %v", path, err)
	}
	src := string(b)
	start := strings.Index(src, "interface "+name)
	if start < 0 {
		return nil
	}
	open := strings.Index(src[start:], "{")
	if open < 0 {
		return nil
	}
	open += start
	close := strings.Index(src[open:], "}")
	if close < 0 {
		t.Fatalf("FE interface %s has no closing brace", name)
	}
	body := src[open+1 : open+close]
	var fields []string
	for _, m := range feInterfaceField.FindAllStringSubmatch(body, -1) {
		fields = append(fields, m[1])
	}
	return fields
}

// schemaProps returns the property names of a component schema from the served
// OpenAPI document (doc is the parsed /api/v1/openapi.json).
func schemaProps(t *testing.T, doc map[string]any, schema string) map[string]bool {
	t.Helper()
	comps, _ := doc["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	s, ok := schemas[schema].(map[string]any)
	if !ok {
		t.Fatalf("served OpenAPI spec has no %q component schema", schema)
	}
	props, _ := s["properties"].(map[string]any)
	out := map[string]bool{}
	for k := range props {
		out[k] = true
	}
	return out
}

// TestCertificateContractFEMatchesBE is the SURFACE-005 contract-drift guard: the
// frontend Certificate type (web/src/lib/api.ts) must not reference a field the
// SERVED OpenAPI Certificate schema does not define. The finding's live instance
// was certificate.status — the FE rendered/filtered on c.status while the backend
// response had no status field. Both sides now carry it; this test FAILS if the
// FE type drifts ahead of (or away from) the served contract again, which — with
// no generated client — is otherwise the default failure mode.
//
// It is intentionally directional (FE ⊆ BE): a FE field with no served source is
// a guaranteed runtime "always empty / never matches" bug, whereas a BE field the
// FE chooses not to surface is benign. Full bidirectional codegen from the spec is
// the structural fix, tracked as EXC-WIRE-04.
func TestCertificateContractFEMatchesBE(t *testing.T) {
	feFields := readFEInterface(t, "Certificate")
	if len(feFields) == 0 {
		t.Fatal("could not find the FE Certificate interface in web/src/lib/api.ts")
	}

	doc := fetchSpec(t)
	beProps := schemaProps(t, doc, "Certificate")

	for _, f := range feFields {
		if !beProps[f] {
			t.Errorf("SURFACE-005 contract drift: FE Certificate.%s has no field in the served OpenAPI Certificate schema — the FE would render/filter on a field the API never sends (regenerate the FE client from /api/v1/openapi.json, EXC-WIRE-04, or align the field)", f)
		}
	}

	// Reality anchor: the field whose drift the audit caught must be present on
	// BOTH sides, so this test is grounded in the actual regression it guards.
	if !beProps["status"] {
		t.Error("the served Certificate schema no longer defines `status`; SURFACE-005's fixed drift has regressed on the BE side")
	}
	hasStatus := false
	for _, f := range feFields {
		if f == "status" {
			hasStatus = true
		}
	}
	if !hasStatus {
		t.Error("the FE Certificate type no longer references `status`; SURFACE-005's anchor field is gone — revisit this drift test")
	}
}
