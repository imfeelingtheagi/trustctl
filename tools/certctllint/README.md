# certctllint — the architecture linter

`certctllint` is a custom [`go/analysis`](https://pkg.go.dev/golang.org/x/tools/go/analysis)
multichecker that enforces certctl's architectural non-negotiables in CI. A pull
request cannot merge while any rule is violated.

## Rules

| Analyzer | Enforces | Summary |
|----------|----------|---------|
| `cryptoboundary` | **AN-3** | `crypto` / `crypto/*` may be imported only inside `internal/crypto` (and its subpackages). Every other package routes crypto through that boundary. |
| `tenantfilter` | **AN-1** | SQL data-manipulation queries (`SELECT`/`INSERT`/`UPDATE`/`DELETE`) in repository packages must reference `tenant_id`. |
| `keymaterial` | **AN-8** | In packages handling key material, fields/params/results must not be `string` (use `[]byte`). |
| `idempotency` | **AN-5** | Mutating handlers must accept and honor an idempotency key. |

`cryptoboundary` and `tenantfilter` are the two highest-value rules and run
fully. `keymaterial` and `idempotency` are intentionally narrow for now and
opt-in via marker directives (below); they tighten as the key-handling, API, and
orchestrator subsystems land.

## Marker directives (opt-in, not suppression)

Some rules apply only where a package or function opts in. Markers make a rule
**stricter**; they never silence it.

- `//certctl:repository` — marks a repository package outside `internal/store` so
  `tenantfilter` applies to it.
- `//certctl:keymaterial` — marks a package as key-handling so `keymaterial`
  applies to it.
- `//certctl:mutation` — marks a handler function so `idempotency` applies to it.

## Running it

```bash
go run ./tools/certctllint ./...          # whole module (what `make lint` runs)
go run ./tools/certctllint -tenantfilter=false ./...   # disable one rule for a run
go vet -vettool=$BIN ./...                # also usable as a vet tool
```

Each analyzer is independently testable with `go test ./tools/certctllint/...`,
which uses `analysistest` fixtures under each analyzer's `testdata/`.

## Escape hatch

There is **deliberately no blanket-ignore mechanism** — no `//nolint`, no
per-line suppression, no allowlist file. If a rule produces a false positive,
the only sanctioned fix is to **correct the rule itself in this package, with a
test fixture that captures the case** (add a clean fixture that must pass, or a
violating one that must fail). This keeps the non-negotiables un-violable and
keeps the rules honest: every refinement is encoded as a test.
