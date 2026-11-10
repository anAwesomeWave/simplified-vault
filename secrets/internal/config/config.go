package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	HTTPAddr      string
	PublicBaseURL string
	PostgresURL   string
	RedisAddr     string
	RabbitMQURL   string
	MasterKeyFile string
}

func Load() (Config, error) {
	c := Config{
		HTTPAddr: env("HTTP_ADDR", ":8000"), PublicBaseURL: env("PUBLIC_BASE_URL", "http://localhost:8000"),
		RedisAddr:     env("REDIS_ADDR", "redis:6379"),
		MasterKeyFile: env("MASTER_KEY_FILE", "/run/secrets/master_key"),
	}
	baseURL, err := url.Parse(c.PublicBaseURL)
	if err != nil || baseURL.Host == "" || (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return Config{}, errors.New("PUBLIC_BASE_URL must be an absolute HTTP(S) URL without credentials, query or fragment")
	}
	c.PublicBaseURL = strings.TrimRight(c.PublicBaseURL, "/")
	if _, _, err := net.SplitHostPort(c.HTTPAddr); err != nil {
		return Config{}, errors.New("HTTP_ADDR must be host:port")
	}
	if _, _, err := net.SplitHostPort(c.RedisAddr); err != nil {
		return Config{}, errors.New("REDIS_ADDR must be host:port")
	}
	pgPassword, err := readPassword(env("POSTGRES_PASSWORD_FILE", "/run/secrets/postgres_password"))
	if err != nil {
		return Config{}, errors.New("cannot read PostgreSQL password file")
	}
	pgPort, err := port("POSTGRES_PORT", "5432")
	if err != nil {
		return Config{}, err
	}
	// POSTGRES_HOST may list the primary and its standby separated by commas.
	// The driver tries them in order and keeps the node that accepts writes,
	// so a promoted standby is picked up without reconfiguring the service.
	var pgHosts []string
	for _, host := range strings.Split(env("POSTGRES_HOST", "postgres-secrets"), ",") {
		if host = strings.TrimSpace(host); host != "" {
			pgHosts = append(pgHosts, net.JoinHostPort(host, pgPort))
		}
	}
	if len(pgHosts) == 0 {
		return Config{}, errors.New("POSTGRES_HOST must not be empty")
	}
	pg := url.URL{Scheme: "postgres", User: url.UserPassword(env("POSTGRES_USER", "secrets"), pgPassword), Host: strings.Join(pgHosts, ","), Path: "/" + env("POSTGRES_DB", "secrets_db")}
	query := url.Values{}
	query.Set("sslmode", env("POSTGRES_SSLMODE", "disable"))
	query.Set("connect_timeout", "5")
	query.Set("target_session_attrs", "read-write")
	pg.RawQuery = query.Encode()
	c.PostgresURL = pg.String()
	rabbitPassword, err := readPassword(env("RABBITMQ_PASSWORD_FILE", "/run/secrets/rabbitmq_password"))
	if err != nil {
		return Config{}, errors.New("cannot read RabbitMQ password file")
	}
	rabbitPort, err := port("RABBITMQ_PORT", "5672")
	if err != nil {
		return Config{}, err
	}
	rabbit := url.URL{Scheme: "amqp", User: url.UserPassword(env("RABBITMQ_USER", "secrets"), rabbitPassword), Host: net.JoinHostPort(env("RABBITMQ_HOST", "rabbitmq"), rabbitPort), Path: "/" + env("RABBITMQ_VHOST", "/")}
	// AMQP encodes the virtual host as one URI path segment, including its slash.
	rabbit.RawPath = "/" + url.PathEscape(env("RABBITMQ_VHOST", "/"))
	c.RabbitMQURL = rabbit.String()
	return c, nil
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}
func port(name, fallback string) (string, error) {
	value := env(name, fallback)
	number, err := strconv.Atoi(value)
	if err != nil || number < 1 || number > 65535 {
		return "", fmt.Errorf("%s must be a port number", name)
	}
	return value, nil
}
func readPassword(path string) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	result := strings.TrimSuffix(strings.TrimSuffix(string(value), "\n"), "\r")
	if result == "" {
		return "", errors.New("empty password")
	}
	return result, nil
}
