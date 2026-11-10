// Package config загружает конфигурацию сервиса.
//
// Несекретные настройки берутся из переменных окружения. Секреты (пароль
// RabbitMQ) читаются из файлов — по умолчанию Docker secrets в /run/secrets/ —
// и никогда из переменных окружения.
package config

import (
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	LogLevel string
	// HealthAddr - адрес HTTP /healthz для Docker HEALTHCHECK. По умолчанию
	// только loopback: снаружи контейнера к notification соединений нет
	HealthAddr string

	RabbitHost         string
	RabbitPort         int
	RabbitUser         string
	RabbitVHost        string
	RabbitPasswordFile string

	Workers      int
	DrainTimeout time.Duration

	SMTPHost     string
	SMTPPort     int
	SMTPHelo     string
	SMTPStartTLS bool
	SMTPTimeout  time.Duration
	MailFrom     string

	// PublicBaseURL - внешний адрес gateway для ссылок в письмах
	PublicBaseURL string
}

func Load() (Config, error) {
	c := Config{
		LogLevel:           env("LOG_LEVEL", "info"),
		HealthAddr:         env("HEALTH_ADDR", "127.0.0.1:8000"),
		RabbitHost:         env("RABBITMQ_HOST", "rabbitmq"),
		RabbitUser:         env("RABBITMQ_USER", "vault"),
		RabbitVHost:        env("RABBITMQ_VHOST", "/"),
		RabbitPasswordFile: env("RABBITMQ_PASSWORD_FILE", "/run/secrets/rabbitmq_password"),
		SMTPHost:           env("SMTP_HOST", "mailpit"),
		SMTPHelo:           env("SMTP_HELO", "notification"),
		MailFrom:           env("MAIL_FROM", "Сервис передачи секретов <no-reply@vault.local>"),
		PublicBaseURL:      strings.TrimRight(env("PUBLIC_BASE_URL", "https://localhost"), "/"),
	}
	var err error
	if c.RabbitPort, err = portEnv("RABBITMQ_PORT", "5672"); err != nil {
		return Config{}, err
	}
	if c.SMTPPort, err = portEnv("SMTP_PORT", "1025"); err != nil {
		return Config{}, err
	}
	if c.Workers, err = strconv.Atoi(env("WORKERS", "4")); err != nil || c.Workers < 1 || c.Workers > 64 {
		return Config{}, fmt.Errorf("config: WORKERS must be between 1 and 64")
	}
	if c.SMTPStartTLS, err = strconv.ParseBool(env("SMTP_STARTTLS", "false")); err != nil {
		return Config{}, fmt.Errorf("config: invalid SMTP_STARTTLS")
	}
	if c.SMTPTimeout, err = time.ParseDuration(env("SMTP_TIMEOUT", "30s")); err != nil || c.SMTPTimeout <= 0 {
		return Config{}, fmt.Errorf("config: invalid SMTP_TIMEOUT")
	}
	if c.DrainTimeout, err = time.ParseDuration(env("DRAIN_TIMEOUT", "10s")); err != nil || c.DrainTimeout <= 0 {
		return Config{}, fmt.Errorf("config: invalid DRAIN_TIMEOUT")
	}
	if _, err := mail.ParseAddress(c.MailFrom); err != nil {
		return Config{}, fmt.Errorf("config: invalid MAIL_FROM: %w", err)
	}
	u, err := url.Parse(c.PublicBaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Config{}, fmt.Errorf("config: PUBLIC_BASE_URL must be an absolute http(s) URL without query")
	}
	return c, nil
}

// ReadSecretFile читает файл секрета и обрезает пробельные символы по краям
// (файлы, созданные через `echo`, заканчиваются переводом строки).
func ReadSecretFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("config: read secret %s: %w", path, err)
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return "", fmt.Errorf("config: secret %s is empty", path)
	}
	return s, nil
}

func portEnv(key, def string) (int, error) {
	port, err := strconv.Atoi(env(key, def))
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("config: invalid %s", key)
	}
	return port, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
