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
  (create, read, **rotate**, delete), one-time secret sharing, the dynamic PKI secret
  (a short-lived certificate *and* its key), and machine login.
- **Library-only** (built and tested, no served endpoint yet): outbound **secret-sync**
  to external stores, and the **transit / KMIP** encryption-as-a-service surface. The
  rotation engine, dynamic database secrets, ephemeral attestation-gated API keys, the
  gitleaks/trufflehog scanning bridge, and secret-store / API-key *discovery* are driven
  through their Go APIs today.

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
     -d '{"value":"s3cr3t"}'
   ```

   -> the secret is stored as version 1; reading it back returns the latest live
   version.

3. Rotate a long-lived secret to a new version. The served store creates a new version
   on write (old versions stay queryable), so a `PUT` rolls forward without losing
   history. See [Secrets](../features/secrets.md).

   ```sh
   curl -fksS -X PUT https://localhost:8443/api/v1/secrets/store/db/password \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"value":"r0tat3d"}'
   ```

   -> a new version is recorded. The four-phase rollback-safe rotation *engine* (stage,
   cut over, verify, retire, with automatic rollback) is library code today — drive it
   in Go; see [Secrets](../features/secrets.md).

4. Hand an application a short-lived credential it cannot hoard. The dynamic PKI secret
   issues a usable TLS identity — a certificate **and** its private key — through the
   issuing authority in the separate signing service, recorded on the revocation
   pipeline so a revoked one stops validating. See [Secrets](../features/secrets.md).

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/pki \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{}'
   ```

   -> you get back a short-lived certificate and key your app can load directly, with no
   long-lived secret to steal. Dynamic *database* secrets (PostgreSQL, MySQL, and the
   rest) and ephemeral attestation-gated API keys are library-tier — see
   [Secrets](../features/secrets.md) and [Platform & API](../features/platform-and-api.md).

5. Share a one-off secret that destroys itself after a single read.

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/shares \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"value":"one-time-token"}'
   ```

   -> the share redeems exactly once at `POST /api/v1/secrets/shares/.../redeem`; a
   second redeem fails, and the bearer token is never written to the audit log.

6. Know the edges before you rely on them. Outbound secret-sync (push + drift detection
   to Kubernetes, GitHub Actions, GitLab CI, and the rest) and the transit/KMIP
   encryption surface are **library-only** — there is no served endpoint yet, so you
   drive them through their Go APIs. Finding secrets already scattered across your
   estate (secret-store and API-key discovery) records references only, never values —
   see [Discovery & inventory](../features/discovery-and-inventory.md) and
   [Current limitations](../limitations.md).

   -> plan around this: the served pieces are the store, sharing, dynamic PKI, and
   machine login; sync and transit/KMIP are programmatic today.

## Where next

- [migrate-from-existing-ca.md](migrate-from-existing-ca.md) — consolidate your
  certificates the same way.
- [onboard-a-team.md](onboard-a-team.md) — isolate each team's secrets in its own
  tenant.

**Journey:** J7
**Steps through:** F37, F38, F39, F35, F36, F63, F64, F65, F66, F67, F68, F60
