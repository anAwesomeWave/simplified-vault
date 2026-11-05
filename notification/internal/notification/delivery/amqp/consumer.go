// Package amqp читает события из очереди notification.events и передаёт
// их в notification.UseCase.
package amqp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"

	"github.com/anAwesomeWave/simplified-vault/notification/internal/broker/rabbitmq"
	"github.com/anAwesomeWave/simplified-vault/notification/internal/notification"
	serverErrors "github.com/anAwesomeWave/simplified-vault/notification/internal/server_errors"
)

const (
	reconnectInitial = time.Second
	reconnectMax     = 30 * time.Second
)

type Config struct {
	Broker rabbitmq.Config
	// Workers - сколько сообщений обрабатывается параллельно. Столько же
	// сообщений брокер выдаёт без подтверждения (prefetch)
	Workers int
	// DrainTimeout - сколько при остановке ждём обработки уже полученных
	// сообщений; потом обработка прерывается и сообщения возвращаются в очередь
	DrainTimeout time.Duration
}

type consumer struct {
	cfg   Config
	uc    notification.UseCase
	log   *slog.Logger
	ready atomic.Bool
}

func NewConsumer(cfg Config, uc notification.UseCase, log *slog.Logger) notification.Consumer {
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.DrainTimeout <= 0 {
		cfg.DrainTimeout = 10 * time.Second
	}
	return &consumer{cfg: cfg, uc: uc, log: log}
}

func (c *consumer) Ready() bool { return c.ready.Load() }

func (c *consumer) Run(ctx context.Context) error {
	delay := reconnectInitial
	for {
		started, err := c.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if started {
			// Соединение работало: следующую попытку начинаем без долгой паузы
			delay = reconnectInitial
		}
		c.log.Warn("rabbitmq session ended, reconnecting",
			slog.String("error", errString(err)), slog.Duration("retry_in", delay))
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil
		}
		delay = min(delay*2, reconnectMax)
	}
}

// session подключается, объявляет топологию и читает очередь, пока не
// отменят ctx или не оборвётся соединение. started - дошло ли до чтения очереди
func (c *consumer) session(ctx context.Context) (started bool, err error) {
	conn, err := rabbitmq.Dial(c.cfg.Broker)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		return false, fmt.Errorf("open channel: %w", err)
	}
	defer ch.Close()

	if err := rabbitmq.DeclareTopology(ch); err != nil {
		return false, err
	}
	if err := ch.Qos(c.cfg.Workers, 0, false); err != nil {
		return false, fmt.Errorf("set qos: %w", err)
	}
	const tag = "notification"
	deliveries, err := ch.Consume(rabbitmq.EventsQueue, tag, false, false, false, false, nil)
	if err != nil {
		return false, fmt.Errorf("consume %s: %w", rabbitmq.EventsQueue, err)
	}
	connClosed := conn.NotifyClose(make(chan *amqp091.Error, 1))

	c.ready.Store(true)
	defer c.ready.Store(false)
	c.log.Info("consuming events", slog.String("queue", rabbitmq.EventsQueue), slog.Int("workers", c.cfg.Workers))

	// Обработка не привязана к ctx напрямую: при остановке уже полученные
	// сообщения дообрабатываются, и только по DrainTimeout повторы прерываются
	procCtx, cancelProc := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelProc()

	var wg sync.WaitGroup
	for range c.cfg.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range deliveries {
				c.handle(procCtx, d)
			}
		}()
	}
	workersDone := make(chan struct{})
	go func() { wg.Wait(); close(workersDone) }()

	select {
	case <-ctx.Done():
		c.log.Info("stopping consumer")
		c.ready.Store(false)
		// После basic.cancel брокер больше ничего не присылает, а уже
		// полученные сообщения дочитываются из deliveries, и канал закрывается
		if err := ch.Cancel(tag, false); err != nil {
			// Закрытие канала тоже закрывает deliveries, а неподтверждённые
			// сообщения брокер вернёт в очередь
			c.log.Warn("cancel consumer", slog.String("error", err.Error()))
			cancelProc()
			_ = ch.Close()
		}
		select {
		case <-workersDone:
		case <-time.After(c.cfg.DrainTimeout):
			c.log.Warn("drain timeout, requeueing unfinished messages")
			cancelProc()
			<-workersDone
		}
		return true, nil

	case amqpErr := <-connClosed:
		// Неподтверждённые сообщения брокер вернёт в очередь сам
		cancelProc()
		<-workersDone
		return true, fmt.Errorf("connection closed: %v", amqpErr)

	case <-workersDone:
		// deliveries закрылся: закрыт канал или брокер отменил consumer
		// (например, удалили очередь)
		return true, errors.New("delivery channel closed")
	}
}

// handle обрабатывает одно сообщение и подтверждает его только после отправки писем
func (c *consumer) handle(ctx context.Context, d amqp091.Delivery) {
	log := c.log.With(slog.String("routing_key", d.RoutingKey), slog.Uint64("delivery_tag", d.DeliveryTag))

	err := c.safeHandle(ctx, d.Body)
	switch {
	case err == nil:
		if ackErr := d.Ack(false); ackErr != nil {
			// Письмо ушло, но брокер пришлёт сообщение ещё раз
			log.Warn("ack failed", slog.String("error", ackErr.Error()))
		}
	case serverErrors.IsPermanent(err):
		// Повтор не поможет: в dead-letter очередь, чтобы не крутить сообщение вечно
		log.Error("event rejected", slog.String("error", err.Error()))
		if nackErr := d.Nack(false, false); nackErr != nil {
			log.Warn("nack failed", slog.String("error", nackErr.Error()))
		}
	default:
		log.Warn("event processing interrupted, requeueing", slog.String("error", err.Error()))
		if nackErr := d.Nack(false, true); nackErr != nil {
			log.Warn("nack failed", slog.String("error", nackErr.Error()))
		}
	}
}

// safeHandle не даёт панике в обработке одного сообщения уронить сервис:
// такое сообщение считается необрабатываемым и уходит в DLQ
func (c *consumer) safeHandle(ctx context.Context, body []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: panic while handling event: %v", serverErrors.ErrInvalidEvent, r)
		}
	}()
	return c.uc.Handle(ctx, body)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
