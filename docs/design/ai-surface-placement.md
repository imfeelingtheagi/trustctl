# AI Surface Placement

## Decision: keep core

`internal/rca`, `internal/aimodel`, `internal/api/aisurface.go`,
`internal/api/aisurface_handlers.go`, and `internal/mcpserver` stay in core for
now. No S-E6 code moves under `ee/`.

The reason is architectural, not commercial: these packages are the safety
boundary for grounded query, prompt redaction, MCP tool scoping, and tenant/RBAC
proof. Gating them now would split a single served safety surface across core and
Enterprise while the API handlers, query engine, docs reality tests, MCP parity
tests, and air-gap/model-egress checks still evolve together.

## Importer Evidence

Core-tag direct imports:

```text
$ GOCACHE=/private/tmp/trstctl-gocache go list -f '{{.ImportPath}} imports {{join .Imports ", "}}' -tags trstctl_core ./internal/rca ./internal/aimodel ./internal/mcpserver
trstctl.com/trstctl/internal/rca imports context, strings, trstctl.com/trstctl/internal/aimodel, trstctl.com/trstctl/internal/auditsink
trstctl.com/trstctl/internal/aimodel imports bytes, context, encoding/json, errors, fmt, io, net/http, regexp, strings, time
trstctl.com/trstctl/internal/mcpserver imports context, errors, fmt, sort, strings, sync, time, trstctl.com/trstctl/internal/auditsink, trstctl.com/trstctl/internal/rca, unicode
```

Core-tag dependency sweep:

```text
$ GOCACHE=/private/tmp/trstctl-gocache go list -deps -tags trstctl_core ./internal/rca ./internal/aimodel ./internal/mcpserver
...
trstctl.com/trstctl/internal/aimodel
trstctl.com/trstctl/internal/auditsink
trstctl.com/trstctl/internal/rca
trstctl.com/trstctl/internal/mcpserver
```

Forbidden import scan:

```text
$ rg "trstctl.com/trstctl/ee" internal/rca internal/aimodel internal/mcpserver internal/api/aisurface*.go -n
# no matches
```

## Why Not Gate Now

The served AI surface is already fail-closed by configuration:
`server.Deps.EnableAISurface` must be true before `api.WithAISurface` mounts
`/api/v1/ai/*` and `/api/v1/mcp/tools*`. The optional model adapter is also off
by default, and cloud egress requires explicit operator consent plus the egress
guard.

Moving the packages to `ee/` would not reduce the security blast radius. It would
instead create a commercial seam through these core controls:

- tenant-scoped query and RBAC checks in `internal/api/aisurface.go`;
- secret and PII redaction in `internal/aimodel`;
- grounded RCA citation handling in `internal/rca`;
- read-only-by-default MCP tooling in `internal/mcpserver`;
- MCP-vs-REST parity tests that cover served route exposure.

## Revisit Criteria

Revisit gating only if a future card introduces a distinct paid AI capability
that can sit behind a narrow seam without moving the core safety mechanism. Good
examples would be a managed model gateway, enterprise-only model policy store, or
provider-facing AI usage accounting. The default implementation and the safety
contracts above remain core.
