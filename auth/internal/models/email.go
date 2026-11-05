package models

import (
	"net/mail"
	"strings"

	serverErrors "github.com/anAwesomeWave/simplified-vault/auth/internal/server_errors"
)

// MaxEmailLength - максимальная длина адреса по RFC 5321
const MaxEmailLength = 254

// Email - нормализованный адрес электронной почты.
//
// Создавать его нужно через NewEmail: тогда значение всегда валидно и записано
// в нижнем регистре, а уникальность email (ФТ-2) не зависит от регистра букв
type Email string

// NewEmail обрезает пробелы, приводит адрес к нижнему регистру и проверяет, что это
// голый addr-spec ("user@host.tld", без отображаемого имени), иначе ErrInvalidEmail
func NewEmail(raw string) (Email, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" || len(s) > MaxEmailLength {
		return "", serverErrors.ErrInvalidEmail
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s {
		return "", serverErrors.ErrInvalidEmail
	}
	if domainPart := s[strings.LastIndexByte(s, '@')+1:]; !strings.Contains(domainPart, ".") {
		return "", serverErrors.ErrInvalidEmail
	}
	return Email(s), nil
}

func (e Email) String() string { return string(e) }
