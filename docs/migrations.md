# Database migrations & upgrades

certctl owns its PostgreSQL schema and applies migrations itself. This page is the
operator runbook for upgrades: how migrations run, why concurrent instances are
safe, the forward-only policy and its safeguard, and the step-by-step upgrade and
rollback procedures.

## How migrations work

The schema is a sequence of numbered SQL migrations (`0001_init.sql`,
`0002_…`, …) embedded in the binary. An applied-versions ledger,
`schema_migrations`, records which have run. On `Migrate`, certctl applies every
migration not yet in the ledger, **in order**, and each migration runs **in its
own transaction together with its ledger row** — so if a run is interrupted, the
schema and the ledger stay consistent and the next run resumes from exactly where
it stopped. Migrations are idempotent where they create cluster-global objects
(for example the RLS role), so a partial run is safe to retry.

## Concurrent instances are safe (advisory lock)

In a multi-replica deployment, several instances may boot at once and all try to
migrate. certctl serializes the **entire** migration run on a PostgreSQL
**session-level advisory lock** (`pg_advisory_lock`, a fixed key shared by all
instances of the deployment). The first instance to acquire it migrates; any other
instance **blocks** on the lock until the first finishes, then sees the migrations
already applied and does nothing. This closes the replica-boot race where two
instances could otherwise apply the same migration concurrently and collide.

You can see the lock while a migration is in flight:

```sql
SELECT * FROM pg_locks WHERE locktype = 'advisory';
```

The behavior is verified in CI: a test holds the lock from one session and asserts
`Migrate` waits for it rather than racing ahead, and a second test runs several
instances against one fresh database simultaneously and asserts the schema is
applied **exactly once** with no duplicate ledger rows.

## Forward-only policy and its safeguard

certctl migrations are **forward-only**: there are no down-migrations. This is a
deliberate choice, not a gap.

- The relational store is a **projection of the event log** (AN-2). The event log
  is the source of truth; the read model can be **rebuilt** from it at any time
  (see [Backup & disaster recovery](disaster-recovery.md)). Generic, automated
  rollback of arbitrary DDL is fragile theatre by comparison.
- Migrations are written to be **additive and non-destructive** (new tables and
  columns, not drops/renames of live data), so a forward roll is low-risk and an
  upgrade does not silently discard state.

The safeguard for forward-only is a **pre-migration backup gate**. Production
deployments can disable silent auto-migration and require migrations to be an
explicit, backed-up step:

```bash
# Disable automatic migration on boot (production).
export CERTCTL_MIGRATE_AUTO=false
```

With `CERTCTL_MIGRATE_AUTO=false`, a control plane that boots and finds pending
migrations **fails fast with guidance** instead of migrating — it will not change
the schema until an operator has taken a backup and applied the migration
deliberately. With the default `CERTCTL_MIGRATE_AUTO=true` (convenient for
single-node eval and first boot), pending migrations are applied automatically on
startup, still under the advisory lock.

## Upgrade runbook

1. **Read the release notes** for the new version and note any migration callouts.
2. **Inspect the plan** — see exactly what the upgrade will apply, changing
   nothing:

    ```bash
    certctl --migrate-status
    # -> "no pending migrations"  OR  "N pending migration(s): ..."
    ```

3. **Back up** before applying anything (the gate). Back up the event log and the
   PostgreSQL state per [Backup & disaster recovery](disaster-recovery.md):

    ```bash
    certctl --backup=/backups/certctl-events-$(date +%F).jsonl
    pg_dump "$CERTCTL_POSTGRES_DSN" > /backups/certctl-pg-$(date +%F).sql
    ```

4. **Apply the migrations** explicitly (safe to run from one instance; the advisory
   lock makes it safe even if others start):

    ```bash
    certctl --migrate
    # -> "applied N migration(s)"
    ```

5. **Start (or roll) the new version.** With auto-migration on, simply deploying
   the new binary applies anything still pending on first boot; replicas booting
   together are serialized by the lock.
6. **Verify** `/readyz` is green and spot-check the inventory.

## Rolling back

Because migrations are forward-only, rollback is **restore from the pre-migration
backup**, not a down-migration:

1. Stop the control plane.
2. Restore the PostgreSQL `pg_dump` taken in step 3 (and, if the event log was
   affected, restore it per the DR runbook and rebuild the read model).
3. Redeploy the **previous** binary version.
4. Confirm `/readyz` and the inventory.

This is why the backup gate exists: the backup taken before an upgrade **is** the
rollback path.

## Adding a migration (for contributors)

Add a new numbered file under `internal/store/migrations/` (next integer prefix);
never edit or renumber an already-shipped migration, since deployments track
applied versions by number. Keep migrations additive and non-destructive so the
forward-only policy stays low-risk. Any new persistent table is tenant-scoped with
row-level security (AN-1) and joins the backup set
([Backup & disaster recovery](disaster-recovery.md)).

See [Configuration → Datastores](configuration.md#datastores) for the Postgres
connection settings these commands use.
