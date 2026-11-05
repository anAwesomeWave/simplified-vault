package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Serve stops accepting connections on cancellation and drains active requests.
func Serve(ctx context.Context, server *http.Server, listener net.Listener, timeout time.Duration, logger *slog.Logger) error {
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	logger.Info("gateway started", "address", listener.Addr().String())
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-result:
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
	}
	logger.Info("draining gateway requests")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return errors.Join(serveErr, err)
	}
	logger.Info("gateway stopped")
	return serveErr
}
