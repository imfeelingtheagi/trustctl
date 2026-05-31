package server

import (
	"context"
	"errors"
	"fmt"
	"os"

	"certctl.io/certctl/internal/backup"
	"certctl.io/certctl/internal/config"
	"certctl.io/certctl/internal/events"
	"certctl.io/certctl/internal/projections"
	"certctl.io/certctl/internal/store"
)

// RunBackup writes a portable backup of the event log (the AN-2 source of truth)
// to path and returns the number of events backed up. It requires an external
// event store — the datastore an operator actually backs up — and fails fast
// otherwise (a bundled/embedded store is per-process and not a backup target).
func RunBackup(ctx context.Context, cfg *config.Config, path string) (int, error) {
	if cfg.NATS.Mode != config.NATSExternal || cfg.NATS.URL == "" {
		return 0, errors.New("backup requires an external event store (set CERTCTL_NATS_MODE=external and CERTCTL_NATS_URL)")
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
		return 0, errors.New("restore requires an external event store (set CERTCTL_NATS_MODE=external and CERTCTL_NATS_URL)")
	}
	if cfg.Postgres.Mode != config.PostgresExternal || cfg.Postgres.DSN == "" {
		return 0, errors.New("restore requires an external Postgres (set CERTCTL_POSTGRES_MODE=external and CERTCTL_POSTGRES_DSN)")
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
