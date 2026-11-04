package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrate применяет встроенные миграции в порядке имён файлов. Каждая
// миграция должна быть идемпотентной; advisory lock на уровне транзакции
// не даёт одновременным запускам мешать друг другу.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin migration: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // после commit ничего не делает

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('auth-migrations'))"); err != nil {
		return fmt.Errorf("postgres: migration lock: %w", err)
	}
	for _, name := range names {
		sql, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("postgres: apply %s: %w", name, err)
		}
	}
	return tx.Commit(ctx)
}
