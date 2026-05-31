# Backup, restore & disaster recovery

certctl is **event-sourced** (AN-2): the event log is the source of truth, and the
relational read model is a pure projection of it. That makes recovery concrete —
restore the event log, rebuild the read model, and the control plane's state is
reconstructed. This page covers what to back up, how to restore, the recovery
objectives, and the DR runbook.

## The backup set

Back up **all** of the following. The convention is that **any new persistent
store joins this set** — if a feature adds a datastore, its backup is part of this
list.

| What | Why | How |
| --- | --- | --- |
| **Event log** (NATS JetStream) | The **source of truth** (AN-2). Restoring it reconstructs all event-sourced state (owners, issuers, identities, certificates, lifecycle, and the attributed audit trail). | `certctl --backup=events.jsonl` (portable, versioned), or back up the JetStream `store_dir` / cluster. |
| **PostgreSQL** | The read model is rebuildable from the log, but **non-event state** lives here: API tokens, CT-monitoring config/checkpoints, and rate-limit buckets. | `pg_dump` (standard). The read model itself is restored by the rebuild, below. |
| **Audit export signing key** | So pre-restore signed evidence bundles still verify (R2.1). | Copy `CERTCTL_AUDIT_SIGNING_KEY_FILE` to secure storage. |

The **signer / CA private keys** are deliberately **not** in a normal backup — they
live in the out-of-process signer (AN-4). Their custody and recovery is a separate,
deliberate procedure (see the DR runbook below).

## Backing up the event log

```bash
# Requires the external event store (CERTCTL_NATS_MODE=external).
certctl --backup=/backups/certctl-events-$(date +%F).jsonl
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
certctl --restore=/backups/certctl-events-2026-05-31.jsonl
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
  periodic `certctl --backup` it equals the **backup interval** (e.g. 24 h). Back
  up at the cadence your RPO target requires.
- **RTO (time to recover):** restore the datastores, run `certctl --restore`, and
  start serving. The rebuild is a single pass over the log (tens of milliseconds
  for thousands of events; minutes for very large logs). Plan an RTO that covers
  provisioning + datastore restore + rebuild + a smoke test.

## DR runbook

### Scenario A — loss of the datastore (PostgreSQL and/or NATS)

1. Provision fresh PostgreSQL and NATS (empty).
2. Point certctl at them (`CERTCTL_POSTGRES_*`, `CERTCTL_NATS_*`).
3. Run `certctl --restore=<latest event-log backup>` — this restores the log and
   rebuilds the read model.
4. Restore the `pg_dump` for non-event state (API tokens, CT config) if needed.
5. Restore the audit signing key (`CERTCTL_AUDIT_SIGNING_KEY_FILE`).
6. Start the control plane; confirm `/readyz` is green and spot-check the inventory.

### Scenario B — loss of the signer / CA private keys

The issuing CA key lives in the out-of-process signer (AN-4). **Today**, the signer
regenerates its CA key on restart, so a signer loss means a **new CA**:

1. Already-issued certificates **remain valid until they expire** — they do not
   depend on the live signer.
2. Bring up a new signer; certctl provisions a new issuing CA.
3. **Re-issue** active credentials under the new CA and distribute the new CA bundle
   to relying parties / agents.
4. Revoke and re-enroll as your policy requires.

Persistent CA-key custody (HSM / sealed storage) and an m-of-n key-ceremony /
break-glass procedure are tracked separately (R3.2); until then, treat CA-key loss
as a planned CA-rotation event using the steps above.

See [Configuration → Datastores](configuration.md#datastores) for the connection
settings these procedures use.
