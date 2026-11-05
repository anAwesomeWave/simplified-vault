package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"simple-vault/secrets/internal/app"
	"simple-vault/secrets/internal/config"
	"simple-vault/secrets/internal/core"
	"simple-vault/secrets/internal/events"
	"simple-vault/secrets/internal/httpapi"
	"simple-vault/secrets/internal/secure"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(); err != nil {
			os.Exit(1)
		}
		return
	}
	if err := run(logger); err != nil {
		logger.Error("service stopped with an error", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	if len(os.Args) != 1 {
		return errors.New("usage: secrets [healthcheck]")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	startupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	db, err := pgxpool.New(startupCtx, cfg.PostgresURL)
	if err != nil {
		return errors.New("invalid PostgreSQL configuration")
	}
	defer db.Close()
	if err := db.Ping(startupCtx); err != nil {
		return errors.New("PostgreSQL connection failed")
	}
	if err := core.Migrate(startupCtx, db); err != nil {
		return errors.New("PostgreSQL migrations failed")
	}
	masterKey, err := os.ReadFile(cfg.MasterKeyFile)
	if err != nil {
		return errors.New("cannot read master key file")
	}
	cipher, err := secure.New(masterKey)
	clear(masterKey)
	if err != nil {
		return err
	}
	cache := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, DialTimeout: 2 * time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, MaxRetries: -1, ContextTimeoutEnabled: true})
	defer func() { _ = cache.Close() }()
	if err := cache.Ping(startupCtx).Err(); err != nil {
		logger.Warn("Redis unavailable; continuing with PostgreSQL")
	}
	service := core.New(db, cache, cipher, cfg.PublicBaseURL)
	handler := httpapi.New(service, logger, 10*time.Second)
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	listener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	publisher := events.New(cfg.RabbitMQURL, logger)
	return app.Serve(ctx, server, listener, 15*time.Second, logger,
		func(workerCtx context.Context) {
			if err := publisher.Run(workerCtx, db); err != nil {
				logger.Error("event publisher stopped")
			}
		},
		func(workerCtx context.Context) {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-workerCtx.Done():
					return
				case <-ticker.C:
					cleanupCtx, done := context.WithTimeout(workerCtx, 30*time.Second)
					if err := service.Cleanup(cleanupCtx); err != nil && workerCtx.Err() == nil {
						logger.Error("expired secrets cleanup failed")
					}
					done()
				}
			}
		})
}

func healthcheck() error {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8000"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://127.0.0.1:" + port + "/health/live")
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return errors.New("unhealthy")
	}
	return nil
}
