package models

import (
	"fmt"
	"net/mail"
	"strings"

	serverErrors "github.com/anAwesomeWave/simplified-vault/notification/internal/server_errors"
)

// MaxEmailLength - максимальная длина адреса по RFC 5321
const MaxEmailLength = 254

// Email - проверенный адрес получателя письма.
//
// Создавать его нужно через NewEmail: тогда значение - голый addr-spec
// ("user@host.tld") без пробелов, переводов строк и отображаемого имени,
// и его безопасно подставлять в SMTP-команды и заголовки письма
type Email string

// NewEmail обрезает пробелы, приводит адрес к нижнему регистру (как это делает auth)
// и проверяет его, иначе ErrInvalidEvent
func NewEmail(raw string) (Email, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" || len(s) > MaxEmailLength {
		return "", fmt.Errorf("%w: invalid email", serverErrors.ErrInvalidEvent)
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s {
		return "", fmt.Errorf("%w: invalid email", serverErrors.ErrInvalidEvent)
	}
	if domainPart := s[strings.LastIndexByte(s, '@')+1:]; !strings.Contains(domainPart, ".") {
		return "", fmt.Errorf("%w: invalid email", serverErrors.ErrInvalidEvent)
	}
	return Email(s), nil
}

func (e Email) String() string { return string(e) }
