// Команда auth запускает сервис auth: регистрация, вход и выпуск JWT.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/config"
	"github.com/anAwesomeWave/simplified-vault/auth/internal/db/postgres"
	"github.com/anAwesomeWave/simplified-vault/auth/internal/server"
)

const (
	// dbWaitTimeout - сколько ждём готовности postgres при старте
	dbWaitTimeout = 60 * time.Second
	// shutdownTimeout - сколько ждём завершения текущих запросов при остановке
	shutdownTimeout = 15 * time.Second
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// `auth healthcheck` используется в Docker HEALTHCHECK: итоговый образ
	// distroless, curl в нём нет
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(cfg.HTTPAddr))
	}

	log := newLogger(cfg.LogLevel)
	if err := run(&cfg, log); err != nil {
		log.Error("auth stopped", slog.String("error", err.Error()))
		os.Exit(1)
	}
	log.Info("service terminated")
}

func run(cfg *config.Config, log *slog.Logger) error {
	termCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dbPassword, err := config.ReadSecretFile(cfg.DBPasswordFile)
	if err != nil {
		return err
	}
	pool, err := postgres.NewPostgresPool(termCtx, postgres.Config{
		Host:     cfg.DBHost,
		Port:     cfg.DBPort,
		User:     cfg.DBUser,
		Password: dbPassword,
		Database: cfg.DBName,
		SSLMode:  cfg.DBSSLMode,
	}, dbWaitTimeout, log)
	if err != nil {
		return fmt.Errorf("failed to create postgres pool: %w", err)
	}
	defer pool.Close()

	if err := postgres.Migrate(termCtx, pool); err != nil {
		return fmt.Errorf("failed to migrate: %w", err)
	}

	errCh := make(chan error, 1)
	srv := server.NewServer(cfg, pool, log)
	if err := srv.Run(errCh); err != nil {
		return fmt.Errorf("failed to run server: %w", err)
	}

	select {
	case err := <-errCh:
		return err
	case <-termCtx.Done():
		log.Warn("service starts termination")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return srv.Stop(shutdownCtx)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func healthcheck(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
