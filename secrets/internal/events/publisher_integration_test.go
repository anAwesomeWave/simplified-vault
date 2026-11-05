package events_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	amqp "github.com/rabbitmq/amqp091-go"

	"simple-vault/secrets/internal/core"
	"simple-vault/secrets/internal/domain"
	"simple-vault/secrets/internal/events"
	"simple-vault/secrets/internal/secure"
)

func TestIntegrationPublisherDeliversCommittedEvents(t *testing.T) {
	dsn, brokerURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_AMQP_URL")
	if dsn == "" || brokerURL == "" {
		t.Skip("set TEST_DATABASE_URL and TEST_AMQP_URL for PostgreSQL/RabbitMQ integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "events_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err := core.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	conn, err := amqp.DialConfig(brokerURL, amqp.Config{Dial: amqp.DefaultDial(5 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseDeadline(time.Now().Add(time.Second)) })
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ExchangeDeclare(events.Exchange, "topic", true, false, false, false, nil); err != nil {
		t.Fatal(err)
	}
	// Capture a private copy; never consume or purge notification.events.
	queue, err := ch.QueueDeclare("", false, true, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.QueueBind(queue.Name, "#", events.Exchange, false, nil); err != nil {
		t.Fatal(err)
	}
	deliveries, err := ch.Consume(queue.Name, "", true, true, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := secure.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := core.New(db, nil, cipher, "https://vault.example")
	owner := domain.User{ID: uuid.NewString(), Email: "events-owner@example.com"}
	plaintext := "private-text-" + uuid.NewString()
	created, err := service.Create(ctx, owner, domain.CreateInput{Title: "Publisher integration", Text: plaintext})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Open(ctx, owner, created.ID, "192.0.2.42"); err != nil {
		t.Fatal(err)
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- events.New(brokerURL, slog.New(slog.NewTextHandler(io.Discard, nil))).Run(workerCtx, db)
	}()
	t.Cleanup(func() {
		stopWorker()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("publisher did not stop")
		}
	})
	seen := make(map[string]bool)
	for len(seen) < 2 {
		select {
		case delivery, ok := <-deliveries:
			if !ok {
				t.Fatal("capture queue closed")
			}
			var payload map[string]any
			if err := json.Unmarshal(delivery.Body, &payload); err != nil {
				t.Fatal(err)
			}
			if payload["secret_id"] != created.ID {
				continue
			}
			kind, _ := payload["type"].(string)
			if kind != "secret.created" && kind != "secret.viewed" {
				t.Fatalf("unexpected event type %q", kind)
			}
			if delivery.Exchange != events.Exchange || delivery.RoutingKey != kind || delivery.Type != kind || delivery.ContentType != "application/json" || delivery.DeliveryMode != amqp.Persistent {
				t.Fatalf("incorrect event transport: type=%q route=%q persistent=%d", kind, delivery.RoutingKey, delivery.DeliveryMode)
			}
			id, ok := payload["event_id"].(string)
			if _, err := uuid.Parse(id); !ok || err != nil || delivery.MessageId != id {
				t.Fatal("missing or inconsistent event identity")
			}
			if _, ok := payload["occurred_at"].(string); !ok {
				t.Fatal("missing event timestamp")
			}
			if bytes.Contains(delivery.Body, []byte(plaintext)) || payload["text"] != nil || payload["ciphertext"] != nil || payload["nonce"] != nil {
				t.Fatal("secret data leaked to broker")
			}
			if kind == "secret.viewed" && (payload["viewer_email"] != owner.Email || payload["owner_email"] != owner.Email || payload["ip"] != "192.0.2.42") {
				t.Fatal("view event fields differ from contract")
			}
			seen[kind] = true
		case <-ctx.Done():
			t.Fatalf("events not delivered: %v", seen)
		}
	}
	for {
		var remaining int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM outbox").Scan(&remaining); err != nil {
			t.Fatal(err)
		}
		if remaining == 0 {
			break
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("confirmed events remain in outbox")
		}
	}
}
