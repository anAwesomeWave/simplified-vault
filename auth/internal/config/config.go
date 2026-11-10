// Package config загружает конфигурацию сервиса.
//
// Несекретные настройки берутся из переменных окружения. Секреты (пароль БД,
// приватный ключ JWT) читаются из файлов — по умолчанию Docker secrets в
// /run/secrets/ — и никогда из переменных окружения.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// TokenTTL зафиксирован спецификацией (ФТ-3): 15 минут.
const TokenTTL = 15 * time.Minute

type Config struct {
	HTTPAddr string
	LogLevel string

	DBHost         string
	DBPort         int
	DBUser         string
	DBName         string
	DBSSLMode      string
	DBPasswordFile string

	JWTPrivateKeyFile string
	JWTIssuer         string
	JWTAudience       string
}

func Load() (Config, error) {
	c := Config{
		HTTPAddr:          env("HTTP_ADDR", ":8000"),
		LogLevel:          env("LOG_LEVEL", "info"),
		DBHost:            env("DB_HOST", "postgres-auth"),
		DBUser:            env("DB_USER", "auth"),
		DBName:            env("DB_NAME", "auth_db"),
		DBSSLMode:         env("DB_SSLMODE", "disable"),
		DBPasswordFile:    env("DB_PASSWORD_FILE", "/run/secrets/postgres_auth_password"),
		JWTPrivateKeyFile: env("JWT_PRIVATE_KEY_FILE", "/run/secrets/jwt_private_key"),
		JWTIssuer:         env("JWT_ISSUER", "auth"),
		JWTAudience:       env("JWT_AUDIENCE", "secrets"),
	}
	port, err := strconv.Atoi(env("DB_PORT", "5432"))
	if err != nil || port <= 0 || port > 65535 {
		return Config{}, fmt.Errorf("config: invalid DB_PORT")
	}
	c.DBPort = port
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

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
