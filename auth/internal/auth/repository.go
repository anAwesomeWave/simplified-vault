package auth

import (
	"context"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/models"
)

type Repository interface {
	// CreateUser сохраняет пользователя, ErrEmailTaken - email уже занят
	CreateUser(ctx context.Context, user *models.User) error
	// GetUserByEmail ищет пользователя по нормализованному email, ErrUserNotFound - его нет
	GetUserByEmail(ctx context.Context, email models.Email) (*models.User, error)
	// Ping проверяет доступность БД
	Ping(ctx context.Context) error
}
