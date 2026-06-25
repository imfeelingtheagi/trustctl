# CLI

`trstctl-cli` is a command-line interface at parity with the REST API, built for
scripts and CI: machine-readable JSON output and a CI-friendly API token. The
command set is generated from the API route table, so it stays in lockstep with
the server.

The running control plane also publishes its full **OpenAPI 3.1** specification at
`/api/v1/openapi.json` — fetch it to generate clients or import the API into your
tooling.

Prefer a typed library? trstctl ships supported **client SDKs for Go and
TypeScript** (with auth, `Idempotency-Key`, cursor iterators, problem+json
errors, and retries) pinned to that same served contract. See
[Client SDKs](features/client-sdks.md).

## Global flags

Every command accepts these, each with a `TRSTCTL_*` environment fallback:

| Flag | Env | Meaning |
| --- | --- | --- |
| `--server` | `TRSTCTL_SERVER` | Base URL of the control plane. |
| `--token` | `TRSTCTL_TOKEN` | API token, sent as `Authorization: Bearer`. |
| `--tenant` | `TRSTCTL_TENANT` | Tenant id (`X-Tenant-ID`) for header/dev auth. |
| `--idempotency-key` | `TRSTCTL_IDEMPOTENCY_KEY` | Stable key for safe retries; generated per call if unset. |

A trstctl API token carries its own tenant and scopes, so with `--token` you
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
| `ca ceremonies` | `start` · `get` · `approve` |
| `ca authorities` | `list` · `create-root` · `create-intermediate` · `issue` |
| `external-cas` | `list` · `issue` |
| `identities` | `create` · `list` · `get` · `transition` · `approve` |
| `certificates` | `ingest` · `list` · `get` |
| `workloads` | `attested-issuance` |
| `broker agent-identities` | `issue` |
| `ephemeral` | `issue` · `approve` |
| `profiles` | `create` · `list` · `get-version` |
| `audit` | `events` · `export` |
| `privacy` | `erasures erase` · `erasures list` · `retention run` · `retention list` · `export` · `catalog` |
| `graph` | `nodes` · `reachable` · `blast-radius` · `query` |
| `risk` | `credentials` |
| `cbom` | `scan` · `assets` |
| `pqc migrations` | `start` · `rollback` |
| `agents` | `list` · `enroll-token` |
| `secrets store` | `put` · `list` · `import` · `get` · `history` · `recover` · `update` · `delete` |
| `secrets leases` | `issue` · `get` · `renew` · `revoke` |
| `secrets rotations` | `run` |
| `secrets syncs` | `run` |
| `secrets shares` | `create` · `redeem` |
| `secrets` | `login` · `pki` |

Plus `version`.

## Bootstrapping the first API token

`trstctl-cli` authenticates with an API token, but a freshly deployed control
plane has none and fails closed (every route `401`s). Mint the first one with the
**server** binary's first-run bootstrap verb, run on the control-plane host — it
writes straight to the datastore (no existing credential, no network trust
required) and prints a tenant-scoped token once:

```bash
trstctl token create --tenant <uuid> [--subject <name>] [--scopes a,b,c] [--tenant-name <label>]
```

- `--tenant` (required) is the UUID the token is scoped to; the tenant is
  registered through the event log if it does not exist yet.
- The default scope set is full operator control **excluding** certificate
  issuance (`certs:issue`) — bootstrapping a credential never grants self-issue.
- The raw `trst_…` token is printed once to stdout (only its hash is stored); save
  it immediately. Then export it as `TRSTCTL_TOKEN` for `trstctl-cli`.

## Examples

```bash
export TRSTCTL_SERVER=https://localhost:8443
export TRSTCTL_TOKEN=trst_...

# Create an owner from a JSON body on stdin.
echo '{"kind":"workload","name":"payments"}' | trstctl-cli owners create -f -

# List the certificate inventory.
trstctl-cli certificates list --limit 50

# Start a root CA ceremony, collect two approvals, then create the root.
cat > root-ceremony.json <<'JSON'
{"operation":"root","threshold":2,"spec":{"common_name":"Example Root CA","validity":"87600h","is_ca":true,"max_path_len":1}}
JSON
trstctl-cli ca ceremonies start -f root-ceremony.json
# Run each approval with a distinct custodian token.
trstctl-cli ca ceremonies approve <ceremony-id>
trstctl-cli ca ceremonies approve <ceremony-id>

cat > root-create.json <<'JSON'
{"ceremony_id":"<ceremony-id>","spec":{"common_name":"Example Root CA","validity":"87600h","is_ca":true,"max_path_len":1}}
JSON
trstctl-cli ca authorities create-root -f root-create.json

# List configured upstream CAs and issue through one of them.
trstctl-cli external-cas list
cat > upstream-issue.json <<'JSON'
{"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n","dns_names":["payments.example.com"],"ttl_seconds":86400}
JSON
trstctl-cli external-cas issue digicert -f upstream-issue.json

# Rank credentials by risk — what to rotate first.
trstctl-cli risk credentials --sort score

# Scan TLS endpoints/config files into the cryptographic bill of materials.
cat > cbom-scan.json <<'JSON'
{"tls_endpoints":["payments.internal.example:443"],"host_configs":["/etc/nginx/sites-enabled/payments.conf"]}
JSON
trstctl-cli cbom scan -f cbom-scan.json
trstctl-cli cbom assets

# Queue PQC re-issuance for a CBOM certificate-key asset, then rehearse rollback.
cat > pqc-migration.json <<'JSON'
{"asset_ids":["<cbom-asset-id>"],"target_algorithm":"ML-DSA-65","protocol":"acme","rollback_on_failure":true}
JSON
trstctl-cli pqc migrations start -f pqc-migration.json

cat > pqc-rollback.json <<'JSON'
{"asset_ids":["<cbom-asset-id>"],"reason":"canary rollback drill"}
JSON
trstctl-cli pqc migrations rollback <run-id> -f pqc-rollback.json

# Mint a one-time agent bootstrap token, then list registered agents.
trstctl-cli agents enroll-token
trstctl-cli agents list

# Issue a policy-gated short-lived credential for an AI/MCP agent.
cat > broker-agent.json <<'JSON'
{"agent_id":"agent-7","method":"k8s_sat","payload_base64":"<proof-base64>","public_key_pem":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n","scopes":["mcp:graph.read","tool:inventory.read"],"ttl_seconds":600}
JSON
trstctl-cli --idempotency-key agent-7-issue-1 broker agent-identities issue -f broker-agent.json

# Open an attestation-gated JIT credential request, approve it, then mint it.
cat > ephemeral-jit.json <<'JSON'
{"request_id":"jit-agent-7","method":"k8s_sat","payload_base64":"<proof-base64>","public_key_pem":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n","ttl_seconds":120}
JSON
trstctl-cli --idempotency-key jit-agent-7-request-1 ephemeral issue -f ephemeral-jit.json
printf '{"action":"issue"}' | trstctl-cli --idempotency-key jit-agent-7-approve-1 ephemeral approve jit-agent-7 -f -
trstctl-cli --idempotency-key jit-agent-7-issue-1 ephemeral issue -f ephemeral-jit.json

# Issue, renew, read, and revoke a dynamic secret lease from a configured provider.
cat > dynamic-lease.json <<'JSON'
{"provider":"postgresql","role":"readonly","ttl_seconds":900}
JSON
trstctl-cli --idempotency-key lease-issue-1 secrets leases issue -f dynamic-lease.json
trstctl-cli secrets leases get <lease-id>
printf '{"extend_seconds":900}' | trstctl-cli --idempotency-key lease-renew-1 secrets leases renew <lease-id> -f -
trstctl-cli --idempotency-key lease-revoke-1 secrets leases revoke <lease-id>

# Run rollback-safe static credential rotation through a configured backend rotator.
cat > static-rotation.json <<'JSON'
{"provider":"postgresql","key":"db/reporting","old_ref":"sec05_old"}
JSON
trstctl-cli --idempotency-key static-rotation-1 secrets rotations run -f static-rotation.json

# Push a stored secret to a configured external sync target. The response contains
# metadata only; the secret value is never echoed back.
cat > secret-sync.json <<'JSON'
{"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD"}
JSON
trstctl-cli --idempotency-key secret-sync-1 secrets syncs run -f secret-sync.json

# On an enrolled host, report local public certificate files over the agent channel.
trstctl-agent --enroll-url https://localhost:8443 \
  --bootstrap-token-file ./trstctl-bootstrap-token \
  --server localhost:9443 \
  --name edge-agent-1 \
  --ca-bundle ./trstctl-ca.pem \
  --inventory-cert-roots /etc/ssl,/etc/pki/tls/certs \
  --inventory-os-trust-roots /etc/ssl/certs \
  --inventory-java-trust-stores "$JAVA_HOME/lib/security/cacerts" \
  --inventory-private-key-roots /etc/ssl/private,/etc/ssh
trstctl-cli discovery findings list

# Run a graph query.
trstctl-cli graph query "MATCH (c:Certificate)-[:SIGNED_BY]->(i:Issuer) RETURN c,i"
```

`--inventory-private-key-roots` locates and classifies private-key files on the host
but reports only metadata: path, key format, algorithm, file-mode status, and a
public-key-derived fingerprint when one can be computed. The agent wipes file buffers
after inspection and never sends PEM/DER key bytes to the control plane.

Path parameters are positional; list filters (`--limit`, `--cursor`, `--sort`,
…) are flags; request bodies come from `-f <file>` or `-f -` (stdin).
