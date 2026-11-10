package notification

import (
	"context"

	"github.com/anAwesomeWave/simplified-vault/notification/internal/models"
)

// Mailer отправляет письма
type Mailer interface {
	// Send отправляет одно письмо. Ошибка, оборачивающая
	// server_errors.ErrPermanentDelivery, означает окончательный отказ сервера;
	// остальные ошибки временные, отправку можно повторить
	Send(ctx context.Context, msg *models.Message) error
}
