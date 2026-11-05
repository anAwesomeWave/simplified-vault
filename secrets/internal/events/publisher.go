// Package events delivers the transactional outbox to RabbitMQ.
// Delivery is at least once: consumers must deduplicate using event_id.
package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	Exchange = "app.events"
	Queue    = "notification.events"

	operationTimeout = 5 * time.Second
	pollInterval     = 500 * time.Millisecond
	maxRetryDelay    = 30 * time.Second
)

var routingKeys = [...]string{
	"secret.created", "access.requested", "access.decided", "secret.viewed", "access.revoked",
}

type Publisher struct {
	amqpURL string
	logger  *slog.Logger
}

func New(amqpURL string, logger *slog.Logger) *Publisher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Publisher{amqpURL: amqpURL, logger: logger}
}

// Run owns the RabbitMQ connection and returns after ctx is canceled. Transient
// database and broker failures leave the event in the outbox and trigger a retry.
// The caller must wait for Run before closing the database pool.
func (p *Publisher) Run(ctx context.Context, db *pgxpool.Pool) error {
	retryDelay := time.Second
	for ctx.Err() == nil {
		session, err := p.connect(ctx)
		if err == nil {
			err = p.deliver(ctx, db, session)
			session.close()
			// A live session has already established successful connectivity.
			retryDelay = time.Second
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			// Never log connection strings, broker errors or event payloads: they
			// may contain credentials or recipient data.
			p.logger.Warn("event delivery unavailable; outbox retained", "retry_in", retryDelay)
		}
		if !wait(ctx, retryDelay) {
			return nil
		}
		retryDelay = min(retryDelay*2, maxRetryDelay)
	}
	return nil
}

type brokerSession struct {
	connection *amqp.Connection
	channel    *amqp.Channel
	transport  net.Conn
	returns    <-chan amqp.Return
	stop       func() bool
}

func (s *brokerSession) close() {
	if s.stop != nil {
		s.stop()
	}
	// Closing the socket also unblocks RPCs and publishing when the broker is
	// applying flow control. No unbounded AMQP close handshake is performed.
	_ = s.transport.Close()
}

func (p *Publisher) connect(parent context.Context) (*brokerSession, error) {
	ctx, cancel := context.WithTimeout(parent, operationTimeout)
	defer cancel()
	var transport net.Conn
	var stop func() bool
	conn, err := amqp.DialConfig(p.amqpURL, amqp.Config{
		Heartbeat: 5 * time.Second,
		Dial: func(network, addr string) (net.Conn, error) {
			var err error
			transport, err = (&net.Dialer{Timeout: operationTimeout}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			deadline, _ := ctx.Deadline()
			if err := transport.SetDeadline(deadline); err != nil {
				_ = transport.Close()
				return nil, err
			}
			// amqp091's synchronous topology RPCs do not accept a context.
			// Closing the underlying socket gives them the same deadline.
			stop = context.AfterFunc(ctx, func() { _ = transport.Close() })
			return transport, nil
		},
	})
	success := false
	defer func() {
		if stop != nil {
			stop()
		}
		if !success && transport != nil {
			_ = transport.Close()
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("connect broker: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		return nil, err
	}
	if err := ch.ExchangeDeclare(Exchange, "topic", true, false, false, false, nil); err != nil {
		return nil, err
	}
	if _, err := ch.QueueDeclare(Queue, true, false, false, false, nil); err != nil {
		return nil, err
	}
	for _, key := range routingKeys {
		if err := ch.QueueBind(Queue, key, Exchange, false, nil); err != nil {
			return nil, err
		}
	}
	if err := ch.Confirm(false); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// The handshake deadline must not become the lifetime of a healthy
	// connection. Heartbeats and per-publish deadlines govern it from here.
	if err := transport.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	// A mandatory return precedes the publisher confirmation. Keep the
	// notification buffered so RabbitMQ's reader cannot block on our caller.
	returns := ch.NotifyReturn(make(chan amqp.Return, 1))
	if !stop() {
		return nil, ctx.Err()
	}
	stop = nil
	success = true
	return &brokerSession{
		connection: conn, channel: ch, transport: transport, returns: returns,
		stop: context.AfterFunc(parent, func() { _ = transport.Close() }),
	}, nil
}

func (p *Publisher) deliver(ctx context.Context, db *pgxpool.Pool, session *brokerSession) error {
	for ctx.Err() == nil {
		delivered, err := p.deliverOne(ctx, db, session)
		if err != nil {
			return err
		}
		if !delivered && !wait(ctx, pollInterval) {
			return ctx.Err()
		}
		if session.connection.IsClosed() {
			return amqp.ErrClosed
		}
	}
	return ctx.Err()
}

func (p *Publisher) deliverOne(parent context.Context, db *pgxpool.Pool, session *brokerSession) (bool, error) {
	ctx, cancel := context.WithTimeout(parent, operationTimeout)
	defer cancel()
	tx, err := db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	var eventID, eventType string
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT event_id::text, type, payload
		FROM outbox ORDER BY created_at, event_id
		LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&eventID, &eventType, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// The AMQP publish context is ignored by amqp091-go. A socket deadline
	// and cancellation close bound flow-controlled writes and confirmation waits.
	deadline, _ := ctx.Deadline()
	if err := session.transport.SetWriteDeadline(deadline); err != nil {
		return false, err
	}
	defer func() { _ = session.transport.SetWriteDeadline(time.Time{}) }()
	stop := context.AfterFunc(ctx, func() { _ = session.transport.Close() })
	defer stop()
	confirmation, err := session.channel.PublishWithDeferredConfirmWithContext(ctx, Exchange, eventType, true, false, amqp.Publishing{
		ContentType: "application/json", DeliveryMode: amqp.Persistent,
		MessageId: eventID, Type: eventType, Body: payload,
	})
	if err != nil {
		return false, err
	}
	if confirmation == nil {
		return false, errors.New("publisher confirmation is unavailable")
	}
	ack, err := confirmation.WaitContext(ctx)
	if err != nil {
		return false, err
	}
	if !ack {
		return false, errors.New("broker rejected event")
	}
	select {
	case returned, ok := <-session.returns:
		if !ok {
			return false, amqp.ErrClosed
		}
		return false, fmt.Errorf("event unroutable: code %d", returned.ReplyCode)
	default:
	}
	if _, err := tx.Exec(ctx, `DELETE FROM outbox WHERE event_id = $1`, eventID); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		// If the broker accepted the event but the transaction did not commit,
		// it will be retried with the same event_id after reconnection.
		return false, err
	}
	return true, nil
}

func wait(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
