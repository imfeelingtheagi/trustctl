package server

import (
	"context"
	"errors"
	"fmt"
	"os"

	"trustctl.io/trustctl/internal/backup"
	"trustctl.io/trustctl/internal/config"
	"trustctl.io/trustctl/internal/events"
	"trustctl.io/trustctl/internal/projections"
	"trustctl.io/trustctl/internal/store"
)

// RunBackup writes a portable backup of the event log (the AN-2 source of truth)
// to path and returns the number of events backed up. It requires an external
// event store — the datastore an operator actually backs up — and fails fast
// otherwise (a bundled/embedded store is per-process and not a backup target).
func RunBackup(ctx context.Context, cfg *config.Config, path string) (int, error) {
	if cfg.NATS.Mode != config.NATSExternal || cfg.NATS.URL == "" {
		return 0, errors.New("backup requires an external event store (set TRUSTCTL_NATS_MODE=external and TRUSTCTL_NATS_URL)")
	}
	log, err := events.Open(ctx, cfg.NATS)
	if err != nil {
		return 0, fmt.Errorf("open event log: %w", err)
	}
	defer func() { _ = log.Close() }()

	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("create backup file: %w", err)
	}
	defer func() { _ = f.Close() }()

	n, err := backup.WriteLog(ctx, log, f)
	if err != nil {
		return n, err
	}
	if err := f.Close(); err != nil { // flush to disk before reporting success
		return n, fmt.Errorf("close backup file: %w", err)
	}
	return n, nil
}

// RunRestore restores the event log from a backup at path and rebuilds the read
// model purely from it (AN-2 / R1.1) — reconstructing the control plane's state.
// It requires external Postgres and NATS (the recovered datastores), and the
// event store must be empty. It returns the number of events restored.
func RunRestore(ctx context.Context, cfg *config.Config, path string) (int, error) {
	if cfg.NATS.Mode != config.NATSExternal || cfg.NATS.URL == "" {
		return 0, errors.New("restore requires an external event store (set TRUSTCTL_NATS_MODE=external and TRUSTCTL_NATS_URL)")
	}
	if cfg.Postgres.Mode != config.PostgresExternal || cfg.Postgres.DSN == "" {
		return 0, errors.New("restore requires an external Postgres (set TRUSTCTL_POSTGRES_MODE=external and TRUSTCTL_POSTGRES_DSN)")
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open backup file: %w", err)
	}
	defer func() { _ = f.Close() }()

	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return 0, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return 0, fmt.Errorf("migrate: %w", err)
	}

	log, err := events.Open(ctx, cfg.NATS)
	if err != nil {
		return 0, fmt.Errorf("open event log: %w", err)
	}
	defer func() { _ = log.Close() }()

	n, err := backup.RestoreLog(ctx, log, f)
	if err != nil {
		return n, err
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		return n, fmt.Errorf("rebuild read model from restored log: %w", err)
	}
	return n, nil
}

// RunRebuild atomically re-derives the read model from the event log already
// present (RESIL-003) and returns the number of events replayed. Unlike RunRestore
// it does NOT require an empty event store: it is the recovery path when the read
// model has diverged or a prior restore was interrupted, re-projecting from the
// intact log without re-appending anything. The rebuild is atomic (truncate +
// replay in one transaction), so an interrupted rebuild rolls back to the prior read
// model rather than leaving a partial inventory. It requires external Postgres and
// NATS (the operational datastores), like restore.
func RunRebuild(ctx context.Context, cfg *config.Config) (int, error) {
	if cfg.NATS.Mode != config.NATSExternal || cfg.NATS.URL == "" {
		return 0, errors.New("rebuild requires an external event store (set TRUSTCTL_NATS_MODE=external and TRUSTCTL_NATS_URL)")
	}
	if cfg.Postgres.Mode != config.PostgresExternal || cfg.Postgres.DSN == "" {
		return 0, errors.New("rebuild requires an external Postgres (set TRUSTCTL_POSTGRES_MODE=external and TRUSTCTL_POSTGRES_DSN)")
	}
	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return 0, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return 0, fmt.Errorf("migrate: %w", err)
	}

	log, err := events.Open(ctx, cfg.NATS)
	if err != nil {
		return 0, fmt.Errorf("open event log: %w", err)
	}
	defer func() { _ = log.Close() }()

	// Count what we replay so the operator gets a concrete confirmation.
	n := 0
	if err := log.Replay(ctx, 0, func(events.Event) error { n++; return nil }); err != nil {
		return 0, fmt.Errorf("count event log: %w", err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		return 0, fmt.Errorf("rebuild read model: %w", err)
	}
	return n, nil
}
