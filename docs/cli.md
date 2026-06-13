# CLI

`trustctl-cli` is a command-line interface at parity with the REST API, built for
scripts and CI: machine-readable JSON output and a CI-friendly API token. The
command set is generated from the API route table, so it stays in lockstep with
the server.

The running control plane also publishes its full **OpenAPI 3.1** specification at
`/api/v1/openapi.json` — fetch it to generate clients or import the API into your
tooling.

## Global flags

Every command accepts these, each with a `TRUSTCTL_*` environment fallback:

| Flag | Env | Meaning |
| --- | --- | --- |
| `--server` | `TRUSTCTL_SERVER` | Base URL of the control plane. |
| `--token` | `TRUSTCTL_TOKEN` | API token, sent as `Authorization: Bearer`. |
| `--tenant` | `TRUSTCTL_TENANT` | Tenant id (`X-Tenant-ID`) for header/dev auth. |
| `--idempotency-key` | `TRUSTCTL_IDEMPOTENCY_KEY` | Stable key for safe retries; generated per call if unset. |

A trustctl API token carries its own tenant and scopes, so with `--token` you
usually need nothing else. Mutations always send an `Idempotency-Key` so a
retried command can never execute twice.

## Output and exit codes

Responses are pretty-printed JSON on stdout. Exit code is **0** on success, **1**
on a request/response error (the status is written to stderr), and **2** on a
usage error — scriptable end to end.

## Commands

One command per core API operation:

| Group | Commands |
| --- | --- |
| `owners` | `create` · `list` · `get` · `update` · `delete` |
| `issuers` | `create` · `list` · `get` |
| `identities` | `create` · `list` · `get` · `transition` |
| `certificates` | `ingest` · `list` · `get` |
| `profiles` | `create` · `list` · `get-version` |
| `audit` | `events` · `export` |
| `graph` | `nodes` · `reachable` · `blast-radius` · `query` |
| `risk` | `credentials` |
| `agents` | `list` · `enroll-token` |

Plus `version`.

## Examples

```bash
export TRUSTCTL_SERVER=https://localhost:8443
export TRUSTCTL_TOKEN=trustctl_pat_...

# Create an owner from a JSON body on stdin.
echo '{"kind":"workload","name":"payments"}' | trustctl-cli owners create -f -

# List the certificate inventory.
trustctl-cli certificates list --limit 50

# Rank credentials by risk — what to rotate first.
trustctl-cli risk credentials --sort score

# Mint a one-time agent bootstrap token, then list registered agents.
trustctl-cli agents enroll-token
trustctl-cli agents list

# Run a graph query.
trustctl-cli graph query "MATCH (c:Certificate)-[:SIGNED_BY]->(i:Issuer) RETURN c,i"
```

Path parameters are positional; list filters (`--limit`, `--cursor`, `--sort`,
…) are flags; request bodies come from `-f <file>` or `-f -` (stdin).
