# Onboard a team as a tenant

## Goal

You will give a team its own isolated slice of trstctl: a tenant whose data no other
team can read, browser sign-in through your existing identity provider, roles that
decide who can do what, a default-deny policy on the dangerous actions, and a
tamper-evident record of everything that happens. The outcome is a team that logs in
with its own accounts, holds exactly the permissions it should, and leaves an audit
trail you can hand to a security reviewer. This is for an operator setting up a new
group on a shared trstctl deployment.

## Before you start

- A running control plane and an admin API token from
  [Getting started](../getting-started.md) (`trstctl token create` mints the first
  one; it deliberately cannot self-issue certificates).
- The CLI pointed at your server via `TRSTCTL_SERVER` and `TRSTCTL_TOKEN` — see
  [Getting started](../getting-started.md).
- An OpenID Connect provider (Entra ID, Okta, Google, Keycloak, and the like) if you
  want browser sign-in. trstctl's interactive single sign-on is OIDC only — see
  [Platform & API](../features/platform-and-api.md).

## Steps

1. Pick a tenant id for the team and mint a tenant-scoped token. Isolation between
   tenants is enforced by the database itself, so one team can never read another's
   data — see [Platform & API](../features/platform-and-api.md).

   ```sh
   trstctl token create --tenant 22222222-2222-2222-2222-222222222222 --subject payments-team
   # -> prints a trst_... token once. Store it now.
   ```

   -> you have a credential confined to the new tenant; every CLI/API call with it acts
   only on that team's data.

2. Wire browser sign-in to your identity provider. Set the OIDC issuer, client id, and
   redirect URI, then enable the flow. The callback verifies the id_token's signature,
   issuer, audience, and nonce before minting an `HttpOnly` session cookie. See
   [Platform & API](../features/platform-and-api.md).

   ```yaml
   auth:
     oidc:
       enabled: true
   ```

   ```sh
   export TRSTCTL_AUTH_OIDC_ISSUER=https://login.example.com/
   export TRSTCTL_AUTH_OIDC_CLIENT_ID=trstctl-web
   export TRSTCTL_AUTH_OIDC_REDIRECT_URI=https://trstctl.example.com/auth/callback
   ```

   -> a user visiting the UI is redirected to your provider, signs in, and returns with
   a session that authorizes API calls under the same roles as a token. An enabled but
   incomplete OIDC block fails closed at startup.

3. Map each signed-in user to the right tenant so two users in different teams see only
   their own data. Use a configurable id_token claim or an explicit mapping; a user who
   maps to no tenant is rejected. See [Platform & API](../features/platform-and-api.md).

   ```yaml
   auth:
     oidc:
       tenant_claim: "tenant"
   ```

   -> each browser session is confined to its mapped tenant; cross-team leakage is
   denied at the database layer.

4. Decide who can do what with roles. trstctl ships `admin`, `operator`, `viewer`,
   `auditor`, and `ra-officer` (which can request but **not** self-issue certificates).
   The required permission is checked on every route and returns `403` on failure. See
   [Policy & governance](../features/policy-and-governance.md).

   -> a `viewer` can read inventory but not mint; an `ra-officer` can request a
   certificate but cannot issue it — the registration-authority separation, enforced,
   not assumed.

5. Turn on default-deny policy for the dangerous actions and require a second approver.
   With the policy gate enabled, every issue, deploy, and revoke is denied unless your
   Rego explicitly allows it, and a privileged action needs a *distinct* approver
   (self-approval is rejected). See [Policy & governance](../features/policy-and-governance.md).

   ```yaml
   ca:
     policy:
       enabled: true
       require_approval: true
   ```

   A minimal default-deny policy:

   ```text
   package trstctl.policy
   default allow = false
   allow { input.action == "revoke" }
   allow { input.action == "issue"; input.profile != "" }
   ```

   -> issuance now requires both a bound profile and a second person, and an approval is
   recorded via `POST /api/v1/identities/{id}/approvals`.

6. Confirm the trail. Every action is recorded as an immutable, hash-chained event, and
   you can export a signed evidence bundle for a reviewer. See
   [Policy & governance](../features/policy-and-governance.md).

   ```sh
   trstctl-cli audit events --type policy.decision --since 2026-01-01T00:00:00Z --limit 100
   trstctl-cli audit export --since 2026-01-01T00:00:00Z --until 2026-06-01T00:00:00Z
   ```

   -> you can show exactly who did what, when, and that the record was not altered
   (any tampering breaks the chain).

## Where next

- [migrate-from-existing-ca.md](migrate-from-existing-ca.md) — bring the team's
  existing certificates under trstctl.
- [manage-secrets.md](manage-secrets.md) — give the team's apps managed secrets.

**Journey:** J6
**Steps through:** F40, F8, F13, F28, F29, F9, F58
