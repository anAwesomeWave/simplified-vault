// Package auth — слой контрактов фичи auth.
//
// Здесь только интерфейсы: delivery.go, usecase.go, repository.go и
// security.go. Реализации лежат в подпакетах delivery/http, usecase,
// repository и security и зависят друг от друга только через эти
// интерфейсы. Собираются они вместе в internal/server.
package auth

import (
	"context"

	"github.com/google/uuid"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/models"
)

type UseCase interface {
	// Register регистрирует пользователя и возвращает его id. Ошибки: ErrInvalidEmail,
	// ErrPasswordTooShort, ErrPasswordTooLong, ErrEmailTaken
	Register(ctx context.Context, request models.Credentials) (uuid.UUID, error)
	// Login проверяет учётные данные и выпускает access-токен. Некорректный email,
	// неизвестный email и неверный пароль одинаково дают ErrInvalidCredentials
	Login(ctx context.Context, request models.Credentials) (*models.AccessToken, error)
	// CheckHealth проверяет, что зависимости сервиса (БД) доступны
	CheckHealth(ctx context.Context) error
}
