package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Serve drains HTTP before stopping workers, then returns so dependencies can close.
func Serve(ctx context.Context, server *http.Server, listener net.Listener, timeout time.Duration, logger *slog.Logger, workers ...func(context.Context)) error {
	workerCtx, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	finished := make(chan struct{}, len(workers))
	for _, worker := range workers {
		go func() { defer func() { finished <- struct{}{} }(); worker(workerCtx) }()
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	logger.Info("secrets server started", "address", listener.Addr().String())
	var result error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			result = fmt.Errorf("HTTP server failed: %w", err)
		}
	}
	logger.Info("draining HTTP requests")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		result = errors.Join(result, fmt.Errorf("HTTP drain: %w", err))
	}
	stopWorkers()
	// A forced HTTP close may consume the entire drain deadline. Give canceled
	// workers their own bounded interval to release database transactions.
	workerShutdownCtx, cancelWorkers := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWorkers()
	for range workers {
		select {
		case <-finished:
		case <-workerShutdownCtx.Done():
			return errors.Join(result, errors.New("background worker shutdown timed out"))
		}
	}
	logger.Info("secrets server stopped")
	return result
}
