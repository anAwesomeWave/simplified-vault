// Команда notification запускает сервис уведомлений: читает события из
// RabbitMQ (exchange app.events, очередь notification.events) и отправляет письма по SMTP.
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

	"github.com/anAwesomeWave/simplified-vault/notification/internal/config"
	"github.com/anAwesomeWave/simplified-vault/notification/internal/server"
)

// shutdownTimeout - сколько ждём завершения обработки при остановке. Должен
// быть больше DRAIN_TIMEOUT и меньше stop_grace_period в compose
const shutdownTimeout = 15 * time.Second

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// `notification healthcheck` используется в Docker HEALTHCHECK: итоговый
	// образ distroless, curl в нём нет
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(cfg.HealthAddr))
	}

	log := newLogger(cfg.LogLevel)
	if err := run(&cfg, log); err != nil {
		log.Error("notification stopped", slog.String("error", err.Error()))
		os.Exit(1)
	}
	log.Info("service terminated")
}

func run(cfg *config.Config, log *slog.Logger) error {
	termCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rabbitPassword, err := config.ReadSecretFile(cfg.RabbitPasswordFile)
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)
	srv := server.NewServer(cfg, rabbitPassword, log)
	if err := srv.Run(errCh); err != nil {
		return fmt.Errorf("failed to run server: %w", err)
	}

	var runErr error
	select {
	case runErr = <-errCh:
	case <-termCtx.Done():
		log.Warn("service starts termination")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Stop(shutdownCtx); err != nil && runErr == nil {
		runErr = err
	}
	return runErr
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func healthcheck(addr string) int {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
