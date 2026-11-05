package models

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	serverErrors "github.com/anAwesomeWave/simplified-vault/notification/internal/server_errors"
)

// EventType - тип события, он же ключ маршрутизации в exchange app.events
type EventType string

const (
	EventSecretCreated   EventType = "secret.created"
	EventAccessRequested EventType = "access.requested"
	EventAccessDecided   EventType = "access.decided"
	EventSecretViewed    EventType = "secret.viewed"
	EventAccessRevoked   EventType = "access.revoked"
)

// EventTypes - все события, которые слушает notification. По ним строятся
// привязки очереди notification.events к exchange app.events
var EventTypes = []EventType{
	EventSecretCreated,
	EventAccessRequested,
	EventAccessDecided,
	EventSecretViewed,
	EventAccessRevoked,
}

// Decision - решение автора по запросу доступа
type Decision string

const (
	DecisionApproved Decision = "approved"
	DecisionDenied   Decision = "denied"
)

const (
	// MaxEventSize - предел размера тела сообщения. Событие без текста секрета
	// весит сотни байт; запас нужен только для длинного списка user_emails
	MaxEventSize = 256 << 10
	// MaxTitleRunes - длиннее название секрета в письме обрезается
	MaxTitleRunes = 200
	// MaxRecipients - предел адресатов одного access.revoked
	MaxRecipients = 1000
)

// Event - проверенное и нормализованное событие из app.events.
//
// Поля текста секрета здесь нет и быть не должно: даже если оно случайно
// окажется в сообщении, при разборе оно отбрасывается и в письмо не попадёт (ФТ-17)
type Event struct {
	ID         uuid.UUID
	Type       EventType
	OccurredAt time.Time

	SecretID uuid.UUID
	// Title - название секрета без управляющих символов, не длиннее MaxTitleRunes
	Title string

	// secret.created
	OwnerID   uuid.UUID
	ExpiresAt time.Time

	// access.requested
	RequestID uuid.UUID

	// access.requested, access.decided
	RequesterEmail Email
	// access.requested, secret.viewed
	OwnerEmail Email
	// access.decided
	Decision Decision
	// secret.viewed
	ViewerEmail Email
	IP          netip.Addr
	// access.revoked: без повторов, в порядке появления
	UserEmails []Email
}

// rawEvent - формат сообщения в брокере. Общие поля есть в каждом событии,
// остальные зависят от типа
type rawEvent struct {
	EventID    uuid.UUID `json:"event_id"`
	Type       EventType `json:"type"`
	OccurredAt time.Time `json:"occurred_at"`

	SecretID       uuid.UUID `json:"secret_id"`
	Title          string    `json:"title"`
	OwnerID        uuid.UUID `json:"owner_id"`
	ExpiresAt      time.Time `json:"expires_at"`
	RequestID      uuid.UUID `json:"request_id"`
	RequesterEmail string    `json:"requester_email"`
	OwnerEmail     string    `json:"owner_email"`
	Decision       string    `json:"decision"`
	ViewerEmail    string    `json:"viewer_email"`
	IP             string    `json:"ip"`
	UserEmails     []string  `json:"user_emails"`
}

// ParseEvent разбирает и проверяет тело сообщения. Любая ошибка оборачивает
// ErrInvalidEvent или ErrUnknownEventType: повтор обработки её не исправит
func ParseEvent(body []byte) (*Event, error) {
	if len(body) > MaxEventSize {
		return nil, fmt.Errorf("%w: body is %d bytes, limit %d", serverErrors.ErrInvalidEvent, len(body), MaxEventSize)
	}
	var raw rawEvent
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%w: decode json: %v", serverErrors.ErrInvalidEvent, err)
	}

	if raw.EventID == uuid.Nil {
		return nil, missing("event_id")
	}
	if raw.OccurredAt.IsZero() {
		return nil, missing("occurred_at")
	}
	if raw.Type == "" {
		return nil, missing("type")
	}

	e := &Event{
		ID:         raw.EventID,
		Type:       raw.Type,
		OccurredAt: raw.OccurredAt.UTC(),
		SecretID:   raw.SecretID,
		Title:      SanitizeTitle(raw.Title),
	}
	if e.SecretID == uuid.Nil {
		// secret_id есть во всех событиях, и только по нему строятся ссылки в письмах
		return nil, missing("secret_id")
	}

	var err error
	switch raw.Type {
	case EventSecretCreated:
		if raw.OwnerID == uuid.Nil {
			return nil, missing("owner_id")
		}
		if raw.ExpiresAt.IsZero() {
			return nil, missing("expires_at")
		}
		e.OwnerID, e.ExpiresAt = raw.OwnerID, raw.ExpiresAt.UTC()

	case EventAccessRequested:
		if raw.RequestID == uuid.Nil {
			return nil, missing("request_id")
		}
		e.RequestID = raw.RequestID
		if e.RequesterEmail, err = emailField("requester_email", raw.RequesterEmail); err != nil {
			return nil, err
		}
		if e.OwnerEmail, err = emailField("owner_email", raw.OwnerEmail); err != nil {
			return nil, err
		}

	case EventAccessDecided:
		if e.Decision, err = parseDecision(raw.Decision); err != nil {
			return nil, err
		}
		if e.RequesterEmail, err = emailField("requester_email", raw.RequesterEmail); err != nil {
			return nil, err
		}

	case EventSecretViewed:
		if e.ViewerEmail, err = emailField("viewer_email", raw.ViewerEmail); err != nil {
			return nil, err
		}
		if e.OwnerEmail, err = emailField("owner_email", raw.OwnerEmail); err != nil {
			return nil, err
		}
		ip, perr := netip.ParseAddr(raw.IP)
		if perr != nil {
			return nil, fmt.Errorf("%w: invalid ip", serverErrors.ErrInvalidEvent)
		}
		e.IP = ip.Unmap()

	case EventAccessRevoked:
		// Пустой список допустим: секрет отозван, а одобренных пользователей не было
		if len(raw.UserEmails) > MaxRecipients {
			return nil, fmt.Errorf("%w: user_emails has %d entries, limit %d",
				serverErrors.ErrInvalidEvent, len(raw.UserEmails), MaxRecipients)
		}
		seen := make(map[Email]struct{}, len(raw.UserEmails))
		for _, s := range raw.UserEmails {
			addr, err := emailField("user_emails", s)
			if err != nil {
				return nil, err
			}
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			e.UserEmails = append(e.UserEmails, addr)
		}

	default:
		return nil, fmt.Errorf("%w: %q", serverErrors.ErrUnknownEventType, sanitizeForLog(string(raw.Type)))
	}
	return e, nil
}

// SanitizeTitle убирает из названия управляющие и невидимые символы (переводы
// строк, bidi-override и т.п.), схлопывает пробелы и обрезает до MaxTitleRunes.
// Название вводит пользователь, а попадает оно в тему и текст письма
func SanitizeTitle(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > MaxTitleRunes {
		s = string([]rune(s)[:MaxTitleRunes-1]) + "…"
	}
	return s
}

func parseDecision(s string) (Decision, error) {
	// Принимаем и форму из API (approve/deny), и форму статуса (approved/denied)
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "approved", "approve":
		return DecisionApproved, nil
	case "denied", "deny":
		return DecisionDenied, nil
	case "":
		return "", missing("decision")
	}
	return "", fmt.Errorf("%w: unknown decision", serverErrors.ErrInvalidEvent)
}

func emailField(name, raw string) (Email, error) {
	if strings.TrimSpace(raw) == "" {
		return "", missing(name)
	}
	e, err := NewEmail(raw)
	if err != nil {
		return "", fmt.Errorf("%w: invalid %s", serverErrors.ErrInvalidEvent, name)
	}
	return e, nil
}

func missing(field string) error {
	return fmt.Errorf("%w: missing %s", serverErrors.ErrInvalidEvent, field)
}

// sanitizeForLog обрезает недоверенную строку перед записью в лог
func sanitizeForLog(s string) string {
	s = SanitizeTitle(s)
	if len(s) > 64 {
		s = strings.ToValidUTF8(s[:64], "")
	}
	return s
}
