package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/auth"
	"github.com/anAwesomeWave/simplified-vault/auth/internal/models"
	serverErrors "github.com/anAwesomeWave/simplified-vault/auth/internal/server_errors"
)

type authUC struct {
	repo   auth.Repository
	hasher auth.PasswordHasher
	tokens auth.TokenIssuer
	now    func() time.Time
}

func NewAuthUC(repo auth.Repository, hasher auth.PasswordHasher, tokens auth.TokenIssuer) auth.UseCase {
	return &authUC{repo: repo, hasher: hasher, tokens: tokens, now: time.Now}
}

// Register проверяет email и пароль, хэширует пароль и сохраняет пользователя (ФТ-1, ФТ-2).
//
// Отдельной проверки «email уже есть» перед вставкой нет: уникальность гарантирует
// уникальный индекс в БД, так что две одновременные регистрации на один адрес
// не создадут двух пользователей
func (uc *authUC) Register(ctx context.Context, request models.Credentials) (uuid.UUID, error) {
	email, err := models.NewEmail(request.Email)
	if err != nil {
		return uuid.Nil, err
	}
	if err := models.ValidatePassword(request.Password); err != nil {
		return uuid.Nil, err
	}

	hash, err := uc.hasher.Hash(ctx, request.Password)
	if err != nil {
		return uuid.Nil, fmt.Errorf("register: hash password: %w", err)
	}

	user := models.NewUser(email, hash, uc.now())
	if err := uc.repo.CreateUser(ctx, user); err != nil {
		if errors.Is(err, serverErrors.ErrEmailTaken) {
			return uuid.Nil, serverErrors.ErrEmailTaken
		}
		return uuid.Nil, fmt.Errorf("register: create user: %w", err)
	}
	return user.ID, nil
}

// Login проверяет учётные данные и выпускает access-токен (ФТ-3).
//
// Если сверять пароль не с чем (email некорректный или не найден), вызывается
// VerifyDummy, чтобы время ответа не выдавало, зарегистрирован ли адрес
func (uc *authUC) Login(ctx context.Context, request models.Credentials) (*models.AccessToken, error) {
	email, err := models.NewEmail(request.Email)
	if err != nil || len(request.Password) > models.MaxPasswordBytes {
		uc.hasher.VerifyDummy(ctx, request.Password)
		return nil, serverErrors.ErrInvalidCredentials
	}

	user, err := uc.repo.GetUserByEmail(ctx, email)
	if errors.Is(err, serverErrors.ErrUserNotFound) {
		uc.hasher.VerifyDummy(ctx, request.Password)
		return nil, serverErrors.ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("login: get user: %w", err)
	}

	ok, err := uc.hasher.Verify(ctx, request.Password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("login: verify password: %w", err)
	}
	if !ok {
		return nil, serverErrors.ErrInvalidCredentials
	}

	token, err := uc.tokens.Issue(user)
	if err != nil {
		return nil, fmt.Errorf("login: issue token: %w", err)
	}
	return &models.AccessToken{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(uc.tokens.TTL() / time.Second),
	}, nil
}

func (uc *authUC) CheckHealth(ctx context.Context) error {
	return uc.repo.Ping(ctx)
}
