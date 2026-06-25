# Manage application secrets

## Goal

You will give your applications a safer way to hold the sensitive values they need —
database passwords, API tokens, encryption keys — by storing them encrypted, handing
out short-lived ones that expire on their own, and sharing one-off secrets through
links that self-destruct after a single view. The outcome is fewer long-lived secrets
copied into config files and CI, each one encrypted at rest and recorded in a
tamper-evident log. This is for a developer or platform engineer who wants their
services to stop hard-coding secrets. It is also honest about which pieces the running
binary serves today and which are library code you drive in Go.

## Before you start

- A running control plane and an API token from
  [Getting started](../getting-started.md) (`trstctl token create`).
- The CLI/API pointed at your server via `TRSTCTL_SERVER` and `TRSTCTL_TOKEN` — see
  [Getting started](../getting-started.md).
- The secrets surface is **off by default**. Enable it with `secrets.enable_api`, and
  set the master key-encryption key file (`TRSTCTL_SECRETS_KEK_FILE`, mode 0600) — the
  surface fails closed without it. See [Secrets](../features/secrets.md).

## What is served vs library-only

Be precise here (see [Current limitations](../limitations.md) and
[Secrets](../features/secrets.md)):

- **Served** on the running binary under `/api/v1/secrets/*`: the secret store
  (create, read, **rotate**, delete), dynamic secret leases, one-time secret sharing,
  the dynamic PKI secret (a short-lived certificate *and* its key), machine login,
  outbound **secret-sync** to configured external stores, and Gitleaks-backed
  code/CI secret scanning.
- **Library-only** (built and tested, no served endpoint yet): the **transit / KMIP**
  encryption-as-a-service surface. Ephemeral attestation-gated API keys and
  secret-store / API-key *discovery* are driven through their Go APIs today.

## Steps

1. Point your client at the control plane and confirm the secrets surface is enabled.

   ```yaml
   secrets:
     enable_api: true
   ```

   ```sh
   export TRSTCTL_SERVER=https://localhost:8443
   export TRSTCTL_TOKEN=trst_...
   export TRSTCTL_SECRETS_KEK_FILE=/etc/trstctl/secrets-kek
   ```

   -> the `/api/v1/secrets/*` routes answer for your tenant; with the key file absent
   they fail closed.

2. Store a secret. Each value is sealed under envelope encryption (a fresh per-secret
   data key wrapped by the master key), bound to your tenant and path, and held only in
   wipeable memory — never as a copyable string. Every write is an immutable
   `secret.version.written` event. See [Secrets](../features/secrets.md).

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/store/db/password \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"name":"db/password","value":"s3cr3t"}'
   ```

   -> the secret is stored as version 1; reading it back returns the latest live
   version.

3. Import a small tree and resolve references deliberately. Imports are all-or-nothing:
   every value is sealed as version 1, and if one path already exists the import is
   rejected. References use `${secret.path}` and expand only when the caller asks for
   `resolve=true`, so a normal read does not fan out across hidden dependencies.

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/store/import \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"prefix":"app","values":{"db/user":"payments","db/dsn":"postgres://${secret.app/db/user}@db.service.local/payments"}}'

   curl -fksS "https://localhost:8443/api/v1/secrets/store/app/db/dsn?resolve=true" \
     -H "Authorization: Bearer $TRSTCTL_TOKEN"
   ```

   -> the first response lists only imported metadata; the second response expands the
   referenced value for this tenant. A circular reference is a `409` problem response
   with a `cycle` field.

4. Rotate a long-lived secret to a new version. The served store creates a new version
   on write (old versions stay queryable), so a `PUT` rolls forward without losing
   history. For backend static credentials, the served rotation API stages a new
   credential, cuts the consumer pointer over, verifies the new login, retires the old
   reference, and rolls back automatically if cutover or verification fails. See
   [Secrets](../features/secrets.md).

   ```sh
   curl -fksS -X PUT https://localhost:8443/api/v1/secrets/store/db/password \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"value":"r0tat3d"}'
   ```

   -> a new native-store version is recorded.

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/rotations \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"provider":"postgresql","key":"db/reporting","old_ref":"sec05_old"}'
   ```

   -> a rollback-safe static credential rotation runs through the served API. The
   response contains only metadata such as `old_ref`, `new_ref`, `completed`,
   `rolled_back`, and `failed_phase`; it never returns the new credential value.

5. Read history or recover to a timestamp. Historical reads are explicit value reads,
   and point-in-time recovery republishes the version that was current at `at` as the
   next monotonic version.

   ```sh
   curl -fksS "https://localhost:8443/api/v1/secrets/store/history/db/password?version=1" \
     -H "Authorization: Bearer $TRSTCTL_TOKEN"

   curl -fksS -X POST https://localhost:8443/api/v1/secrets/store/recover/db/password \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"at":"2026-06-25T12:00:00Z"}'
   ```

   -> the recovered value becomes the latest version; metadata and audit records do not
   contain plaintext secret material.

6. Hand an application a short-lived backend credential it cannot hoard. Dynamic leases
   return the credential once, then later reads show only metadata. When the TTL expires,
   the served leaseworker queues backend revocation through the outbox, so a crash does
   not silently drop the revoke. Operators must wire the named provider backend before a
   tenant can issue from it. The built-in backend names are `postgresql`, `mysql`,
   `mongodb`, `aws-iam`, `gcp-iam`, `azure-entra`, `kubernetes`, and `redis`; each
   creates a scoped credential in the target system and revokes it when the lease
   closes.

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/leases \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"provider":"postgresql","role":"readonly","ttl_seconds":900}'

   curl -fksS https://localhost:8443/api/v1/secrets/leases/<lease-id> \
     -H "Authorization: Bearer $TRSTCTL_TOKEN"

   curl -fksS -X POST https://localhost:8443/api/v1/secrets/leases/<lease-id>/renew \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"extend_seconds":900}'

   curl -fksS -X POST https://localhost:8443/api/v1/secrets/leases/<lease-id>/revoke \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)"
   ```

   -> the issue response contains the credential; the get, renew, and revoke responses
   contain only lease id, provider, role, state, and timestamps.

7. Hand an application a short-lived certificate identity it cannot hoard. The dynamic
   PKI secret issues a usable TLS identity — a certificate **and** its private key —
   through the issuing authority in the separate signing service, recorded on the
   revocation pipeline so a revoked one stops validating. See [Secrets](../features/secrets.md).

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/pki \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{}'
   ```

   -> you get back a short-lived certificate and key your app can load directly, with no
   long-lived secret to steal. Ephemeral attestation-gated API keys are library-tier —
   see [Secrets](../features/secrets.md) and [Platform & API](../features/platform-and-api.md).

8. Share a one-off secret that destroys itself after a single read.

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/shares \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"value":"one-time-token"}'
   ```

   -> the share redeems exactly once at `POST /api/v1/secrets/shares/.../redeem`; a
   second redeem fails, and the bearer token is never written to the audit log.

9. Push a stored secret to a configured external target when a platform needs a copy.
   The served sync path writes a sealed outbox row first, then delivers through the
   configured pusher. GitHub Actions, AWS Secrets Manager, and Kubernetes have concrete
   pushers; Vercel/GitLab/Terraform/GCP/Azure style targets can use the JSON/manual
   pusher until deeper native APIs are configured.

   ```sh
   cat > secret-sync.json <<'JSON'
   {"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD"}
   JSON
   trstctl-cli --idempotency-key sync-db-password-1 secrets syncs run -f secret-sync.json
   ```

   -> the response returns only metadata and delivery flags; it never echoes the secret
   value.

10. Scan a repository or CI workspace for committed secrets. Install Gitleaks `v8.27.2`
    on the control-plane host and set `TRSTCTL_SECRETS_GITLEAKS_BIN` to that binary.
    The served scan uses the pinned default rule set (`213` rules), redacts the match,
    and records only rule/file/line/fingerprint metadata into discovery and graph.

   ```sh
   cat > secret-scan.json <<'JSON'
   {"path":"."}
   JSON
   trstctl-cli --idempotency-key ci-secret-scan-1 secrets scans run -f secret-scan.json

   curl -fksS "https://localhost:8443/api/v1/discovery/findings?run_id=<run-id>" \
     -H "Authorization: Bearer $TRSTCTL_TOKEN"
   ```

   -> the scan response shows the `run_id`, `rules_active`, and redacted findings.
   The secret value itself is not returned and is not written to the event log.

11. Know the edges before you rely on them. The transit/KMIP encryption surface remains
    **library-only** — there is no served endpoint yet, so you drive it through Go APIs.
    Finding secrets already scattered across your estate (secret-store and API-key
    discovery) records references only, never values — see
    [Discovery & inventory](../features/discovery-and-inventory.md) and
    [Current limitations](../limitations.md).

## Where next

- [migrate-from-existing-ca.md](migrate-from-existing-ca.md) — consolidate your
  certificates the same way.
- [onboard-a-team.md](onboard-a-team.md) — isolate each team's secrets in its own
  tenant.

**Journey:** J7
**Steps through:** F37, F38, F39, F35, F36, F63, F64, F65, F66, F67, F68, F60
