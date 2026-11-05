package config

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	amqp "github.com/rabbitmq/amqp091-go"
)

func setup(t *testing.T) {
	t.Helper()
	passwordPath := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordPath, []byte("p@ss:/?%+word\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POSTGRES_PASSWORD_FILE", passwordPath)
	t.Setenv("RABBITMQ_PASSWORD_FILE", passwordPath)
	for key, value := range map[string]string{
		"HTTP_ADDR": ":8000", "PUBLIC_BASE_URL": "https://localhost:8443/", "REDIS_ADDR": "redis:6379",
		"POSTGRES_HOST": "postgres-secrets", "POSTGRES_PORT": "5432", "POSTGRES_USER": "secrets", "POSTGRES_DB": "secrets_db", "POSTGRES_SSLMODE": "disable",
		"RABBITMQ_HOST": "rabbitmq", "RABBITMQ_PORT": "5672", "RABBITMQ_USER": "secrets", "RABBITMQ_VHOST": "/",
	} {
		t.Setenv(key, value)
	}
}

func TestFilePasswordsAndURLRoundTrip(t *testing.T) {
	setup(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	pg, err := url.Parse(cfg.PostgresURL)
	if err != nil {
		t.Fatal(err)
	}
	pgPassword, _ := pg.User.Password()
	rabbit, err := amqp.ParseURI(cfg.RabbitMQURL)
	if err != nil {
		t.Fatal(err)
	}
	if pgPassword != "p@ss:/?%+word" || rabbit.Password != pgPassword || rabbit.Vhost != "/" {
		t.Fatal("file credentials or AMQP vhost did not round-trip")
	}
	if cfg.PublicBaseURL != "https://localhost:8443" {
		t.Fatal("unexpected configuration defaults")
	}
	t.Setenv("RABBITMQ_VHOST", "team/a b")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	rabbit, err = amqp.ParseURI(cfg.RabbitMQURL)
	if err != nil || rabbit.Vhost != "team/a b" {
		t.Fatalf("escaped vhost: %q, %v", rabbit.Vhost, err)
	}
}

func TestInvalidConfigRejectedWithoutLeakingPassword(t *testing.T) {
	for _, item := range []struct{ key, value string }{
		{"PUBLIC_BASE_URL", "https://u:password@example.test"}, {"PUBLIC_BASE_URL", "//example.test"},
		{"PUBLIC_BASE_URL", "https://example.test?token=secret"}, {"HTTP_ADDR", "8000"},
		{"POSTGRES_PORT", "0"}, {"RABBITMQ_PORT", "65536"},
	} {
		t.Run(item.key+item.value, func(t *testing.T) {
			setup(t)
			t.Setenv(item.key, item.value)
			if _, err := Load(); err == nil {
				t.Fatal("expected invalid configuration to fail")
			}
		})
	}
	t.Run("missing-password", func(t *testing.T) {
		setup(t)
		t.Setenv("POSTGRES_PASSWORD_FILE", filepath.Join(t.TempDir(), "missing"))
		if _, err := Load(); err == nil || err.Error() != "cannot read PostgreSQL password file" {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
