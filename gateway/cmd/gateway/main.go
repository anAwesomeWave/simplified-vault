package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"simple-vault/gateway/internal/app"
	"simple-vault/gateway/internal/auth"
	"simple-vault/gateway/internal/config"
	"simple-vault/gateway/internal/gateway"
	"simple-vault/gateway/internal/ratelimit"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := healthcheck(); err != nil {
			os.Exit(1)
		}
		return
	}
	if err := run(logger); err != nil {
		logger.Error("gateway stopped with an error", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	if len(os.Args) != 1 {
		return errors.New("usage: gateway [healthcheck]")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	publicKey, err := os.ReadFile(cfg.PublicKeyFile)
	if err != nil {
		return errors.New("cannot read JWT public key file")
	}
	verifier, err := auth.New(publicKey)
	if err != nil {
		return err
	}
	var tlsConfig *tls.Config
	if cfg.TLSCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return errors.New("cannot load TLS certificate and private key")
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	}
	listener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return err
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	handler := gateway.New(cfg.AuthURL, cfg.SecretsURL, verifier, ratelimit.New(cfg.LoginLimit, time.Minute), logger)
	defer handler.CloseIdleConnections()
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Serve(ctx, server, listener, 15*time.Second, logger)
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
	// A local TCP check also works when the listener terminates TLS.
	connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 2*time.Second)
	if err != nil {
		return err
	}
	return connection.Close()
}
