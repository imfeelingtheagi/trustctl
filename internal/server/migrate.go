package server

import (
	"context"
	"errors"
	"fmt"

	"trustctl.io/trustctl/internal/config"
	"trustctl.io/trustctl/internal/store"
)

// requireExternalPostgres rejects the bundled single-node datastore for explicit
// migration operations: migrations act on the external database an operator
// manages, so a bundled-mode invocation is a misconfiguration and is refused
// before opening anything.
func requireExternalPostgres(cfg *config.Config) error {
	if cfg.Postgres.Mode != config.PostgresExternal || cfg.Postgres.DSN == "" {
		return errors.New("migration requires an external Postgres (set TRUSTCTL_POSTGRES_MODE=external and TRUSTCTL_POSTGRES_DSN)")
	}
	return nil
}

// MigrateStatus returns the pending migrations (the dry-run plan) without
// applying anything. It backs `trustctl --migrate-status`, the pre-migration
// check an operator runs before taking a backup and upgrading.
func MigrateStatus(ctx context.Context, cfg *config.Config) ([]string, error) {
	if err := requireExternalPostgres(cfg); err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	return st.PendingMigrations(ctx)
}

// RunMigrate applies pending migrations explicitly (under the advisory lock that
// serializes concurrent instances) and returns the number applied. It backs
// `trustctl --migrate`, the deliberate, post-backup migration step used when
// automatic migration is disabled (TRUSTCTL_MIGRATE_AUTO=false).
func RunMigrate(ctx context.Context, cfg *config.Config) (int, error) {
	if err := requireExternalPostgres(cfg); err != nil {
		return 0, err
	}
	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return 0, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	pending, err := st.PendingMigrations(ctx)
	if err != nil {
		return 0, fmt.Errorf("inspect migrations: %w", err)
	}
	if err := st.Migrate(ctx); err != nil {
		return 0, fmt.Errorf("migrate: %w", err)
	}
	return len(pending), nil
}
