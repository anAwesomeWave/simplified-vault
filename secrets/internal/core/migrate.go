package core

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_initial.sql
var initialSchema string

// Migrate serializes startup migrations across service instances.
func Migrate(ctx context.Context, db *pgxpool.Pool) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(748129315)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"); err != nil {
		return err
	}
	var applied bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=1)").Scan(&applied); err != nil {
		return err
	}
	if !applied {
		if _, err = tx.Exec(ctx, initialSchema); err != nil {
			return fmt.Errorf("migration 1: %w", err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES (1)"); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
