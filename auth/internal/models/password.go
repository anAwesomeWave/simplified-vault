package models

import (
	"unicode/utf8"

	serverErrors "github.com/anAwesomeWave/simplified-vault/auth/internal/server_errors"
)

const (
	// MinPasswordLength - минимальная длина пароля в символах (ФТ-1)
	MinPasswordLength = 10
	// MaxPasswordBytes - ограничение размера пароля, чтобы огромные входные данные
	// не нагружали хэширование
	MaxPasswordBytes = 1024
)

// ValidatePassword проверяет пароль на соответствие политике. Длина считается
// в символах, а не в байтах: "пароль1234" - это 10 символов
func ValidatePassword(password string) error {
	if len(password) > MaxPasswordBytes {
		return serverErrors.ErrPasswordTooLong
	}
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < MinPasswordLength {
		return serverErrors.ErrPasswordTooShort
	}
	return nil
}
