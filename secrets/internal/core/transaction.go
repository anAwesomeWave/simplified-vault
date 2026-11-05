package core

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Rollback must also be bounded when a database connection stops responding.
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
