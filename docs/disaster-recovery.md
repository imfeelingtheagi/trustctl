# Backup, restore & disaster recovery

trustctl is **event-sourced** (AN-2): the event log is the source of truth, and the
relational read model is a pure projection of it. That makes recovery concrete —
restore the event log, rebuild the read model, and the control plane's state is
reconstructed. This page covers what to back up, how to restore, the recovery
objectives, and the DR runbook.

## The backup set

Back up **all** of the following. The convention is that **any new persistent
store joins this set** — if a feature adds a datastore, its backup is part of this
list. This is **enforced, not assumed**: a manifest test
(`internal/backup` `TestBackupManifestCoversEveryPersistentStore`) classifies every
table the migrations create as recovered by replaying the event log, recovered from
the PostgreSQL dump, or ephemeral, and fails the build if a new table is left
unclassified — so a store cannot silently fall out of the recovery plan.

| What | Why | How |
| --- | --- | --- |
| **Event log** (NATS JetStream) | The **source of truth** (AN-2). Restoring it reconstructs all event-sourced state (owners, issuers, identities, certificates, lifecycle, and the attributed audit trail). | `trustctl --backup=events.jsonl` (portable, versioned), or back up the JetStream `store_dir` / cluster. |
| **PostgreSQL** | The read model is rebuildable from the log, but **non-event state** lives here: API tokens, CT-monitoring config/checkpoints, and rate-limit buckets. | `pg_dump` (standard). The read model itself is restored by the rebuild, below. |
| **Audit export signing key** | So pre-restore signed evidence bundles still verify (R2.1). | Copy `TRUSTCTL_AUDIT_SIGNING_KEY_FILE` to secure storage. |
| **KEK** (key-encryption key) | The root of trust for everything sealed at rest: stored credentials (R3.1) **and** the signer's CA key (R3.2). Without it, sealed material cannot be opened. | Copy `TRUSTCTL_SECRETS_KEK_FILE` to secure storage, separately from the sealed data it protects. |
| **Signer CA key store** | The issuing CA's private key, **sealed at rest** (R3.2). Restoring it preserves the CA identity. | Back up the signer's key-store directory (`--keystore`); it holds only ciphertext. |
| **Issuing CA certificate** | So the control plane reuses the same CA cert across a restore (stable identity). | Copy `TRUSTCTL_CA_CERT_FILE`. |

The signer's CA key is now **persisted, sealed at rest** (R3.2) — it survives a
restart and is part of the backup set above. Restore it (the sealed key store) and
the KEK into a fresh signer to recover the CA identity; see Scenario B below. Keep
the **KEK separate** from the sealed data it protects.

## Backing up the event log

```bash
# Requires the external event store (TRUSTCTL_NATS_MODE=external).
trustctl --backup=/backups/trustctl-events-$(date +%F).jsonl
# -> "backed up <N> events to ..."
```

The backup is **newline-delimited JSON** — a self-describing, versioned header
followed by one record per event (id, type, tenant, time, data, and the recorded
actor). It is portable and inspectable, and it captures the complete envelope so
the recovered audit trail is intact.

## Restoring

Restore into a **fresh, empty** event store and a PostgreSQL instance, then rebuild:

```bash
# Requires external Postgres and NATS, and an EMPTY event store.
trustctl --restore=/backups/trustctl-events-2026-05-31.jsonl
# -> "restored <N> events from ... and rebuilt the read model"
```

`--restore` re-appends every event in order (preserving ids, timestamps, and
actors) and then **rebuilds the relational read model purely from the restored
log** (the AN-2 rebuild). It refuses a non-empty event store so a misdirected
restore can never duplicate the stream. For the non-event PostgreSQL state (API
tokens, CT config), restore the `pg_dump` separately.

A backup → restore → rebuild drill is exercised in CI
(`TestBackupRestoreDRDrillReproducesState`): it asserts the recovered inventory
**matches the source** — the same rebuild-from-log equivalence the architecture
guarantees.

## Recovery objectives (RPO / RTO)

These are **defaults to validate against your own infrastructure**, not promises —
they depend on how often you back up and how fast your datastores restore.

- **RPO (data loss window):** the age of your most recent backup. With continuous
  JetStream replication (external cluster) the RPO approaches **zero**; with
  periodic `trustctl --backup` it equals the **backup interval** (e.g. 24 h). Back
  up at the cadence your RPO target requires.
- **RTO (time to recover):** restore the datastores, run `trustctl --restore`, and
  start serving. The rebuild is a single pass over the log (tens of milliseconds
  for thousands of events; minutes for very large logs). Plan an RTO that covers
  provisioning + datastore restore + rebuild + a smoke test.

## High availability and the single-replica control plane

The default Helm chart runs **one** control-plane replica with a `Recreate` rollout
(`deploy/helm/trustctl/values.yaml` `replicaCount: 1`). This is a **deliberate
topology, not an oversight**, and it is a known availability trade-off (RESIL-002):

- **Why single-replica today.** The control plane co-locates the signing service as
  a locked-down sidecar reachable only over a shared in-memory Unix domain socket
  (AN-4), and the signer seals its CA key in a **per-pod** key store. Running a
  second replica would mean a second, independent signer with a different sealed key
  store — not the same CA. True horizontal scaling therefore needs the signer to run
  as its own pod reached over **mTLS gRPC** (the `signer.mode: isolated` topology),
  and **that cross-node transport is not built yet** (the `trustctl-signer` binary is
  UDS-only; see `docs/limitations.md` "Multi-replica HA"). Selecting
  `signer.mode=isolated` **fails the Helm render** with guidance rather than shipping
  a crash-looping signer pod (OPS-001).
- **What this means for availability.** Out of the box, a node failure or any config
  rollout takes issuance/validation **offline until the pod reschedules** (`Recreate`
  guarantees a brief downtime window on every deploy). The **datastores** (external
  PostgreSQL + replicated NATS) are where durability lives, so this is an
  *availability* gap, not a *data-loss* one — the event log (source of truth) and the
  read model survive a control-plane restart, and a rebuilt pod re-derives state from
  the log.
- **Recovery posture (leader-election note).** Until the isolated-signer transport
  lands, the supported HA story is **fast failover of a single active replica**, not
  active/active: run the pod under a Deployment so Kubernetes reschedules it on node
  loss, keep the datastores externally replicated, and keep `Recreate` so two
  control planes never run two independent signers against the same datastore at
  once. When the isolated topology ships, the plan is `replicaCount >= 2` with a
  shared isolated signer, `RollingUpdate maxUnavailable: 0`, a non-zero
  PodDisruptionBudget, and pod anti-affinity — with **leader election** gating the
  background workers (the outbox dispatcher, audit-retention, idempotency/outbox GC,
  and the projection tailer) so only one replica runs them while all replicas serve
  reads. Multi-replica projector safety is tracked under RESIL-004 / EXC-RESIL-01.

This gap is disclosed in the chart (`values.yaml` comments) and in
`docs/limitations.md`, which is what keeps the severity at Medium rather than High.

## DR runbook

### Scenario A — loss of the datastore (PostgreSQL and/or NATS)

1. Provision fresh PostgreSQL and NATS (empty).
2. Point trustctl at them (`TRUSTCTL_POSTGRES_*`, `TRUSTCTL_NATS_*`).
3. Run `trustctl --restore=<latest event-log backup>` — this restores the log and
   rebuilds the read model.
4. Restore the `pg_dump` for non-event state (API tokens, CT config) if needed.
5. Restore the audit signing key (`TRUSTCTL_AUDIT_SIGNING_KEY_FILE`).
6. Start the control plane; confirm `/readyz` is green and spot-check the inventory.

### Scenario B — loss of the signer host (recover the CA, no rotation)

The issuing CA key lives in the out-of-process signer (AN-4) and is now
**persisted, sealed at rest** (R3.2). A signer-host loss does **not** mean a new CA
— restore the sealed key store and the KEK and the **same CA is back**:

1. Provision a fresh signer host/container.
2. **Restore the signer's sealed key store** (`--keystore` directory) and the
   **KEK** (`TRUSTCTL_SECRETS_KEK_FILE`) from backup. Keep them from separate
   backups — the KEK opens the sealed keys.
3. Start `trustctl-signer --keystore <dir> --kek <kek>`; it reloads the sealed CA
   key. Restore `TRUSTCTL_CA_CERT_FILE` so the control plane reuses the same CA
   certificate. The CA identity is unchanged; already-issued certificates keep
   verifying and no re-issuance is needed.

If the CA key **and** its backup are both lost (true catastrophe), fall back to a
planned CA rotation: already-issued certificates remain valid until expiry, stand
up a new CA, re-issue, and distribute the new bundle — see the
[incident-response runbook](runbooks/incident-response.md) and the m-of-n
[key-ceremony runbook](runbooks/key-ceremony.md). HSM/KMS-backed custody and a
served break-glass flow remain future work.

See [Configuration → Datastores](configuration.md#datastores) and
[Configuration → Signer](configuration.md#signer-topology--ca-custody) for the
settings these procedures use.
