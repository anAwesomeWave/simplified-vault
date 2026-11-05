package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	authHttp "github.com/anAwesomeWave/simplified-vault/auth/internal/auth/delivery/http"
	authRepository "github.com/anAwesomeWave/simplified-vault/auth/internal/auth/repository"
	authSecurity "github.com/anAwesomeWave/simplified-vault/auth/internal/auth/security"
	authUsecase "github.com/anAwesomeWave/simplified-vault/auth/internal/auth/usecase"
	"github.com/anAwesomeWave/simplified-vault/auth/internal/config"
)

// Server - единственное место, где слои собираются вместе:
// repository и security -> usecase -> delivery
type Server struct {
	cfg  *config.Config
	pool *pgxpool.Pool
	log  *slog.Logger
	srv  *http.Server
}

func NewServer(cfg *config.Config, pool *pgxpool.Pool, log *slog.Logger) *Server {
	return &Server{
		cfg:  cfg,
		pool: pool,
		log:  log,
	}
}

// Run собирает слои и запускает HTTP-сервер в фоне. Ошибка инициализации
// возвращается сразу, ошибка работающего сервера приходит в errCh
func (s *Server) Run(errCh chan<- error) error {
	// Init security
	key, err := authSecurity.LoadRSAPrivateKey(s.cfg.JWTPrivateKeyFile)
	if err != nil {
		return err
	}
	tokenIssuer, err := authSecurity.NewJWTIssuer(key, s.cfg.JWTIssuer, s.cfg.JWTAudience, config.TokenTTL)
	if err != nil {
		return err
	}
	passwordHasher, err := authSecurity.NewArgon2idHasher(authSecurity.DefaultArgon2idParams, runtime.NumCPU())
	if err != nil {
		return err
	}

	// Init repositories
	usersRepo := authRepository.NewUsersRepo(s.pool)

	// Init useCases
	authUC := authUsecase.NewAuthUC(usersRepo, passwordHasher, tokenIssuer)

	// Init handlers
	authHandler := authHttp.NewHandler(authUC, s.log)

	s.srv = &http.Server{
		Addr:              s.cfg.HTTPAddr,
		Handler:           authHttp.NewRouter(authHandler, s.log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}

	go func() {
		s.log.Info("auth listening", slog.String("addr", s.cfg.HTTPAddr))
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("listen and serve: %w", err)
		}
	}()

	return nil
}

// Stop перестаёт принимать соединения и дожидается текущих запросов до отмены ctx
func (s *Server) Stop(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}
