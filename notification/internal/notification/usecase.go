// Package notification — слой контрактов фичи notification.
//
// Здесь только интерфейсы: delivery.go, usecase.go и mailer.go. Реализации
// лежат в подпакетах delivery/amqp, usecase и mailer/smtp и зависят друг от
// друга только через эти интерфейсы. Собираются они вместе в internal/server.
package notification

import "context"

type UseCase interface {
	// Handle разбирает событие из app.events и отправляет по нему письма.
	//
	//   - nil: событие обработано, все письма отправлены (или письмо не нужно),
	//     сообщение можно подтверждать;
	//   - ошибка, для которой server_errors.IsPermanent == true: событие
	//     некорректно или SMTP окончательно отверг письмо, повтор не поможет;
	//   - любая другая ошибка (в т.ч. отмена ctx): обработка прервана,
	//     сообщение нужно вернуть в очередь.
	Handle(ctx context.Context, body []byte) error
}
