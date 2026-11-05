package repository

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/db/postgres"
	"github.com/anAwesomeWave/simplified-vault/auth/internal/models"
	serverErrors "github.com/anAwesomeWave/simplified-vault/auth/internal/server_errors"
)

// Интеграционный тест. Запускается, только если задан AUTH_TEST_DB_HOST, например:
//
//	docker run --rm -d -p 55432:5432 -e POSTGRES_PASSWORD=test postgres:17-alpine
//	AUTH_TEST_DB_HOST=127.0.0.1 AUTH_TEST_DB_PORT=55432 go test ./internal/auth/repository/...
func TestUsersRepo(t *testing.T) {
	host := os.Getenv("AUTH_TEST_DB_HOST")
	if host == "" {
		t.Skip("AUTH_TEST_DB_HOST not set")
	}
	port, _ := strconv.Atoi(envOr("AUTH_TEST_DB_PORT", "5432"))
	ctx := context.Background()

	pool, err := postgres.NewPostgresPool(ctx, postgres.Config{
		Host:     host,
		Port:     port,
		User:     envOr("AUTH_TEST_DB_USER", "postgres"),
		Password: envOr("AUTH_TEST_DB_PASSWORD", "test"),
		Database: envOr("AUTH_TEST_DB_NAME", "postgres"),
		SSLMode:  "disable",
	}, 30*time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// дважды: миграции должны быть идемпотентными
	for i := 0; i < 2; i++ {
		if err := postgres.Migrate(ctx, pool); err != nil {
			t.Fatalf("migrate #%d: %v", i+1, err)
		}
	}

	repo := NewUsersRepo(pool)
	email := models.Email("it-" + uuid.NewString() + "@example.com")
	user := &models.User{ID: uuid.New(), Email: email, PasswordHash: "$argon2id$x", CreatedAt: time.Now().UTC()}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM users WHERE email = $1", email.String()) })

	if err := repo.CreateUser(ctx, user); err != nil {
		t.Fatalf("create: %v", err)
	}
	dup := *user
	dup.ID = uuid.New()
	if err := repo.CreateUser(ctx, &dup); !errors.Is(err, serverErrors.ErrEmailTaken) {
		t.Fatalf("duplicate create err = %v, want ErrEmailTaken", err)
	}

	got, err := repo.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != user.ID || got.Email != user.Email || got.PasswordHash != user.PasswordHash {
		t.Fatalf("got %+v, want %+v", got, user)
	}
	if _, err := repo.GetUserByEmail(ctx, "missing-"+email); !errors.Is(err, serverErrors.ErrUserNotFound) {
		t.Fatalf("missing err = %v, want ErrUserNotFound", err)
	}
	if err := repo.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
