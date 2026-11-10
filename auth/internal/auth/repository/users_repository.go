package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/auth"
	"github.com/anAwesomeWave/simplified-vault/auth/internal/models"
	serverErrors "github.com/anAwesomeWave/simplified-vault/auth/internal/server_errors"
)

// uniqueViolation - код ошибки Postgres при нарушении уникального индекса
const uniqueViolation = "23505"

// usersRepo хранит пользователей в auth_db. Ошибки pgx наружу не выходят:
// они переводятся в ошибки из server_errors
type usersRepo struct {
	pool *pgxpool.Pool
}

func NewUsersRepo(pool *pgxpool.Pool) auth.Repository {
	return &usersRepo{pool: pool}
}

func (r *usersRepo) CreateUser(ctx context.Context, user *models.User) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, created_at) VALUES ($1, $2, $3, $4)`,
		user.ID, user.Email.String(), user.PasswordHash, user.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return serverErrors.ErrEmailTaken
	}
	return err
}

func (r *usersRepo) GetUserByEmail(ctx context.Context, email models.Email) (*models.User, error) {
	var (
		user     models.User
		rawEmail string
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, created_at FROM users WHERE email = $1`, email.String(),
	).Scan(&user.ID, &rawEmail, &user.PasswordHash, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, serverErrors.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	// в БД email уже нормализован (это гарантирует CHECK), повторная проверка не нужна
	user.Email = models.Email(rawEmail)
	return &user, nil
}

func (r *usersRepo) Ping(ctx context.Context) error {
	return r.pool.Ping(ctx)
}
