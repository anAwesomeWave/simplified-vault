package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/anAwesomeWave/simplified-vault/notification/internal/models"
	"github.com/anAwesomeWave/simplified-vault/notification/internal/notification"
	serverErrors "github.com/anAwesomeWave/simplified-vault/notification/internal/server_errors"
)

// RetryPolicy - повтор отправки при временных ошибках SMTP: пауза растёт
// от Initial вдвое до Max. Число попыток не ограничено: пока SMTP недоступен,
// письмо всё равно не отправить, а сообщение безопасно ждёт в durable-очереди.
// Прервать повторы может только отмена ctx (остановка сервиса)
type RetryPolicy struct {
	Initial time.Duration
	Max     time.Duration
}

var DefaultRetryPolicy = RetryPolicy{Initial: time.Second, Max: 30 * time.Second}

type notificationUC struct {
	mailer notification.Mailer
	links  links
	retry  RetryPolicy
	log    *slog.Logger
	sleep  func(ctx context.Context, d time.Duration) error
}

// NewNotificationUC собирает usecase. publicBaseURL - внешний адрес gateway,
// от него строятся ссылки в письмах (например, "https://vault.company.com")
func NewNotificationUC(mailer notification.Mailer, publicBaseURL string, retry RetryPolicy, log *slog.Logger) notification.UseCase {
	if retry.Initial <= 0 {
		retry.Initial = DefaultRetryPolicy.Initial
	}
	if retry.Max < retry.Initial {
		retry.Max = retry.Initial
	}
	return &notificationUC{
		mailer: mailer,
		links:  links{baseURL: strings.TrimRight(publicBaseURL, "/")},
		retry:  retry,
		log:    log,
		sleep:  sleepCtx,
	}
}

func (uc *notificationUC) Handle(ctx context.Context, body []byte) error {
	e, err := models.ParseEvent(body)
	if err != nil {
		return err
	}
	log := uc.log.With(
		slog.String("event_id", e.ID.String()),
		slog.String("type", string(e.Type)),
		slog.String("secret_id", e.SecretID.String()),
	)

	if e.Type == models.EventSecretCreated {
		// Писем по созданию секрета нет, только запись в лог
		log.Info("secret created",
			slog.String("owner_id", e.OwnerID.String()),
			slog.Time("expires_at", e.ExpiresAt))
		return nil
	}
	msgs := uc.compose(e)

	// Письма отправляются по очереди. При повторе внутри одного Handle уже
	// отправленные письма не переотправляются; при возврате сообщения в очередь
	// (остановка сервиса посреди access.revoked) часть писем может прийти дважды
	for i, msg := range msgs {
		msg.ID = e.ID.String() + "." + strconv.Itoa(i)
		if err := uc.sendWithRetry(ctx, log, msg); err != nil {
			return fmt.Errorf("send %s notification %d/%d: %w", e.Type, i+1, len(msgs), err)
		}
	}
	// Адреса и IP в лог не пишем: это персональные данные, а лог читает больше людей
	log.Info("notification sent", slog.Int("recipients", len(msgs)))
	return nil
}

// compose превращает событие в письма. Для secret.created писем нет
func (uc *notificationUC) compose(e *models.Event) []*models.Message {
	switch e.Type {
	case models.EventAccessRequested:
		return []*models.Message{accessRequestedMessage(e, uc.links)}
	case models.EventAccessDecided:
		return []*models.Message{accessDecidedMessage(e, uc.links)}
	case models.EventSecretViewed:
		return []*models.Message{secretViewedMessage(e, uc.links)}
	case models.EventAccessRevoked:
		return accessRevokedMessages(e)
	}
	return nil
}

func (uc *notificationUC) sendWithRetry(ctx context.Context, log *slog.Logger, msg *models.Message) error {
	delay := uc.retry.Initial
	for attempt := 1; ; attempt++ {
		err := uc.mailer.Send(ctx, msg)
		if err == nil {
			return nil
		}
		if errors.Is(err, serverErrors.ErrPermanentDelivery) {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return errors.Join(ctxErr, err)
		}
		log.Warn("mail delivery failed, will retry",
			slog.Int("attempt", attempt),
			slog.Duration("retry_in", delay),
			slog.String("error", err.Error()))
		if err := uc.sleep(ctx, delay); err != nil {
			return err
		}
		delay = min(delay*2, uc.retry.Max)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
