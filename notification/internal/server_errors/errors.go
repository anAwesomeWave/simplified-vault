package server_errors

import "errors"

var (
	// ErrInvalidEvent - событие нельзя обработать: не JSON, нет обязательных полей,
	// некорректный email и т.п. Повтор не поможет, сообщение уходит в DLQ
	ErrInvalidEvent = errors.New("invalid event")
	// ErrUnknownEventType - тип события notification не знает. Тоже окончательная ошибка
	ErrUnknownEventType = errors.New("unknown event type")
	// ErrPermanentDelivery - SMTP-сервер окончательно отверг письмо (ответ 5xx).
	// Повтор не поможет, сообщение уходит в DLQ
	ErrPermanentDelivery = errors.New("permanent mail delivery failure")
)

// IsPermanent сообщает, что ошибку обработки не исправить повтором
func IsPermanent(err error) bool {
	return errors.Is(err, ErrInvalidEvent) ||
		errors.Is(err, ErrUnknownEventType) ||
		errors.Is(err, ErrPermanentDelivery)
}
