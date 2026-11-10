// Package postgres - подключение к auth_db и миграции её схемы.
// Работа с данными (SQL-запросы) - в internal/auth/repository.
package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config описывает подключение к базе данных.
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string
}

// NewPostgresPool открывает пул и ждёт до wait, пока база начнёт принимать
// соединения (postgres обычно стартует медленнее сервиса)
func NewPostgresPool(ctx context.Context, cfg Config, wait time.Duration, log *slog.Logger) (*pgxpool.Pool, error) {
	pcfg, err := pgxpool.ParseConfig(fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Database, cfg.SSLMode))
	if err != nil {
		return nil, fmt.Errorf("postgres: parse config: %w", err)
	}
	// Задаём отдельно, чтобы спецсимволы в пароле не нужно было экранировать.
	pcfg.ConnConfig.Password = cfg.Password
	pcfg.MaxConns = 10
	pcfg.ConnConfig.ConnectTimeout = 5 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: create pool: %w", err)
	}

	deadline := time.Now().Add(wait)
	for {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = pool.Ping(pingCtx)
		cancel()
		if err == nil {
			return pool, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			pool.Close()
			return nil, fmt.Errorf("postgres: ping: %w", err)
		}
		log.Warn("database is not ready, retrying", "err", err)
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
		}
	}
}
