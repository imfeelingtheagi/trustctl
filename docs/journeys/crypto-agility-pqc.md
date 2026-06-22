# Stay crypto-agile and migrate to post-quantum

## Goal

When you finish this journey you will understand where your weak and
quantum-vulnerable cryptography lives, why trstctl can swap algorithms in one place
instead of a rewrite, and how a post-quantum migration is planned and what it targets.
It is for a security or platform engineer getting ahead of the quantum transition. In
plain terms: you cannot migrate what you cannot see, so you first inventory the
algorithms in your estate, then lean on the fact that all of trstctl's cryptography
goes through one isolated path (so adding a post-quantum algorithm is a contained
change), then plan the re-issue of every quantum-vulnerable credential to a
post-quantum target.

## Before you start

- A running control plane and an API token, set up in
  [Getting started](../getting-started.md).
- The lifecycle, crypto-agility, and PQC-migration model is in
  [Lifecycle & PQC](../features/lifecycle-and-pqc.md); how the key-encryption key and
  secret material are protected is in [Secrets](../features/secrets.md).
- An honest expectation: the post-quantum primitives are in place and the migration
  tooling is library-complete, but a one-command operator trigger for the
  fleet-wide migration is not wired yet. This journey plans the move and surfaces the
  posture; see [Current limitations](../limitations.md) for served-vs-library detail.

## Steps

1. **Understand the crypto-agility model.** All cryptography in trstctl routes through
   a single isolated path; no other part of the system performs crypto directly, and a
   build check fails the build if anything tries. That is what makes adding or swapping
   an algorithm — including a post-quantum one — a one-place change rather than a
   redesign. The detail is in [Lifecycle & PQC](../features/lifecycle-and-pqc.md).

2. **Know which post-quantum algorithms are available.** Behind that single path,
   alongside classical RSA and ECDSA/Ed25519, these are ready to issue against:

   - **ML-DSA** (FIPS 204) — the lattice signature, e.g. `ML-DSA-65`.
   - **ML-KEM** (FIPS 203) — key encapsulation.
   - **SLH-DSA** (FIPS 205) — the hash-based signature, e.g. `SLH-DSA-SHA2-128f`,
     the conservative choice for long-lived roots (its signatures are large).
   - **A hybrid** `HybridEd25519Dilithium3` — classical Ed25519 paired with ML-DSA, so
     breaking either component alone does not forge a signature.

   You should pick the algorithm per certificate profile — large hash-based signatures
   suit roots, not high-volume leaves.

3. **Inventory the algorithms you run.** A cryptographic bill of materials (CBOM)
   classifies each observation by algorithm family and strength and flags the
   quantum-vulnerable ones. Its findings become crypto-asset nodes in the credential
   graph, so posture flows into blast-radius and compliance views. Explore the graph
   that the CBOM feeds:

   ```sh
   trstctl-cli graph nodes
   ```

   You should see your inventory as graph nodes. The CBOM scanner, its policy floor
   (RSA-2048, EC-256, TLS 1.2), and its served-vs-library status are in
   [Observability & risk](../features/observability-and-risk.md).

4. **Pin the algorithm a profile may use.** A certificate profile is a versioned,
   tenant-scoped rulebook for what may be issued — including the allowed key
   algorithms. To prepare a profile that issues post-quantum, declare its constraints
   and create it:

   ```sh
   trstctl-cli profiles create -f pqc-roots.json
   ```

   You should see the new profile version created. Editing a profile creates a new
   version while old versions stay queryable, so you always know which rules a past
   certificate was issued under. Profiles are covered in
   [Lifecycle & PQC](../features/lifecycle-and-pqc.md).

5. **Set the renewal window the migration will ride on.** Migration re-issues
   credentials, and lifecycle thresholds govern when renewal happens. Configure them:

   ```json
   {
     "lifecycle": {
       "renew_before": "720h",
       "alert_before": "168h"
     }
   }
   ```

   You should see `renew_before` (the window before expiry in which trstctl
   re-issues) and `alert_before` (when it warns) take effect. Until the standalone
   migration trigger is wired, re-issuance to a post-quantum target is driven through
   the issuance path directly.

6. **Keep what protects your secrets quantum-aware too.** Secret material — including
   the key-encryption key that seals everything at rest — lives only in wipeable
   memory and is zeroed after use, and it routes through the same single crypto path,
   so the same agility applies. Protect the KEK in production:

   ```sh
   export TRSTCTL_SECRETS_KEK_FILE=/secure/trstctl-kek.key
   ```

   You should keep the KEK in strong custody (back it with an HSM/KMS in production).
   The envelope-encryption and KEK model is in [Secrets](../features/secrets.md).

## Where next

- [Run trstctl in production](run-in-production.md)
- [Build on the API, CLI, and SDKs](build-on-the-api.md)

**Journey:** J12
**Steps through:** F16, F57, F66
