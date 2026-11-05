package auth

import (
	"context"
	"time"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/models"
)

// PasswordHasher хэширует и проверяет пароли
type PasswordHasher interface {
	Hash(ctx context.Context, password string) (string, error)
	Verify(ctx context.Context, password, encoded string) (bool, error)
	// VerifyDummy тратит столько же времени, сколько Verify, и ничего не проверяет:
	// вход для несуществующего пользователя длится так же, как для существующего
	VerifyDummy(ctx context.Context, password string)
}

// TokenIssuer выпускает access-токены
type TokenIssuer interface {
	Issue(user *models.User) (string, error)
	TTL() time.Duration
}
