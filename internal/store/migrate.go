package store

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migrate applies any pending migrations in order, tracked in the
// schema_migrations ledger (a system, non-tenant table). It runs as the
// connecting (privileged) role.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx,
		"CREATE TABLE IF NOT EXISTS schema_migrations (version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"); err != nil {
		return fmt.Errorf("store: create migrations ledger: %w", err)
	}
	applied, err := s.appliedVersions(ctx)
	if err != nil {
		return err
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		version, err := versionOf(name)
		if err != nil {
			return fmt.Errorf("store: bad migration name %q: %w", name, err)
		}
		if applied[version] {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if err := s.applyMigration(ctx, version, string(body)); err != nil {
			return fmt.Errorf("store: apply migration %s: %w", name, err)
		}
	}
	return nil
}

func (s *Store) appliedVersions(ctx context.Context) (map[int64]bool, error) {
	rows, err := s.pool.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := make(map[int64]bool)
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func (s *Store) applyMigration(ctx context.Context, version int64, body string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, body); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// versionOf parses the leading integer of a migration filename ("0001_init.sql"
// -> 1).
func versionOf(name string) (int64, error) {
	base := name
	if i := strings.IndexByte(base, '_'); i > 0 {
		base = base[:i]
	}
	return strconv.ParseInt(base, 10, 64)
}
