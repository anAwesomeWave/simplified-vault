// Package rabbitmq - подключение к RabbitMQ и объявление топологии,
// которую использует notification. Чтение сообщений - в internal/notification/delivery/amqp.
package rabbitmq

import (
	"fmt"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/anAwesomeWave/simplified-vault/notification/internal/models"
)

const (
	// EventsExchange - topic exchange, в который secrets публикует все события.
	// Ключ маршрутизации совпадает с типом события
	EventsExchange = "app.events"
	// EventsQueue - durable-очередь notification
	EventsQueue = "notification.events"
	// DeadLetterExchange и DeadLetterQueue принимают сообщения, которые
	// обработать нельзя (битое событие, окончательный отказ SMTP). Они не
	// теряются и не крутятся в очереди бесконечно, их можно разобрать вручную
	DeadLetterExchange = "notification.dlx"
	DeadLetterQueue    = "notification.events.dead"
)

type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	VHost    string
	// ConnectionName видно в списке соединений RabbitMQ
	ConnectionName string
}

// Dial открывает соединение с брокером
func Dial(cfg Config) (*amqp.Connection, error) {
	uri := amqp.URI{
		Scheme:   "amqp",
		Host:     cfg.Host,
		Port:     cfg.Port,
		Username: cfg.User,
		Password: cfg.Password,
		Vhost:    cfg.VHost,
	}
	props := amqp.NewConnectionProperties()
	if cfg.ConnectionName != "" {
		props.SetClientConnectionName(cfg.ConnectionName)
	}
	conn, err := amqp.DialConfig(uri.String(), amqp.Config{
		Heartbeat:  10 * time.Second,
		Locale:     "en_US",
		Properties: props,
		Dial:       amqp.DefaultDial(5 * time.Second),
	})
	if err != nil {
		// В тексте ошибки amqp091 нет URI, пароль не утекает в лог
		return nil, fmt.Errorf("rabbitmq: dial %s:%d: %w", cfg.Host, cfg.Port, err)
	}
	return conn, nil
}

// DeclareTopology идемпотентно объявляет exchange, очереди и привязки.
//
// Exchange app.events объявляют и secrets, и notification, параметры должны
// совпадать: topic, durable. Очередь notification.events объявляет только
// notification: secrets публикует в exchange и про очередь не знает
func DeclareTopology(ch *amqp.Channel) error {
	if err := ch.ExchangeDeclare(EventsExchange, amqp.ExchangeTopic, true, false, false, false, nil); err != nil {
		return fmt.Errorf("rabbitmq: declare exchange %s: %w", EventsExchange, err)
	}
	if err := ch.ExchangeDeclare(DeadLetterExchange, amqp.ExchangeFanout, true, false, false, false, nil); err != nil {
		return fmt.Errorf("rabbitmq: declare exchange %s: %w", DeadLetterExchange, err)
	}
	// Обе очереди - quorum: копия хранится на каждом узле кластера RabbitMQ,
	// при отказе узла-лидера очередь продолжает работать на оставшемся большинстве.
	// Тип очереди нельзя изменить повторным объявлением: существующую
	// classic-очередь с тем же именем нужно удалить
	if _, err := ch.QueueDeclare(DeadLetterQueue, true, false, false, false, amqp.Table{
		"x-queue-type": amqp.QueueTypeQuorum,
	}); err != nil {
		return fmt.Errorf("rabbitmq: declare queue %s: %w", DeadLetterQueue, err)
	}
	if err := ch.QueueBind(DeadLetterQueue, "", DeadLetterExchange, false, nil); err != nil {
		return fmt.Errorf("rabbitmq: bind %s: %w", DeadLetterQueue, err)
	}
	if _, err := ch.QueueDeclare(EventsQueue, true, false, false, false, amqp.Table{
		"x-queue-type":           amqp.QueueTypeQuorum,
		"x-dead-letter-exchange": DeadLetterExchange,
	}); err != nil {
		return fmt.Errorf("rabbitmq: declare queue %s: %w", EventsQueue, err)
	}
	for _, t := range models.EventTypes {
		if err := ch.QueueBind(EventsQueue, string(t), EventsExchange, false, nil); err != nil {
			return fmt.Errorf("rabbitmq: bind %s to %s: %w", EventsQueue, t, err)
		}
	}
	return nil
}
