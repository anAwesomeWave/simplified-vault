package models

import (
	"time"

	"github.com/google/uuid"
)

// User - учётная запись пользователя
type User struct {
	ID           uuid.UUID
	Email        Email
	PasswordHash string // argon2id в формате PHC
	CreatedAt    time.Time
}

// NewUser создаёт нового пользователя со случайным id (UUID v4)
func NewUser(email Email, passwordHash string, now time.Time) *User {
	return &User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    now.UTC(),
	}
}
