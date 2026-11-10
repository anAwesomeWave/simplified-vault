package amqp

// Интеграционный тест на реальных RabbitMQ и Mailpit. Без переменных окружения
// пропускается; запуск - см. README (make it).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	amqp091 "github.com/rabbitmq/amqp091-go"

	"github.com/anAwesomeWave/simplified-vault/notification/internal/broker/rabbitmq"
	smtpMailer "github.com/anAwesomeWave/simplified-vault/notification/internal/notification/mailer/smtp"
	"github.com/anAwesomeWave/simplified-vault/notification/internal/notification/usecase"
)

type itEnv struct {
	broker     rabbitmq.Config
	brokerURL  string
	smtpHost   string
	smtpPort   int
	mailpitURL string
}

func loadITEnv(t *testing.T) itEnv {
	t.Helper()
	brokerURL := os.Getenv("NOTIFICATION_IT_RABBITMQ_URL")
	smtpAddr := os.Getenv("NOTIFICATION_IT_SMTP_ADDR")
	mailpitURL := os.Getenv("NOTIFICATION_IT_MAILPIT_URL")
	if brokerURL == "" || smtpAddr == "" || mailpitURL == "" {
		t.Skip("set NOTIFICATION_IT_RABBITMQ_URL, NOTIFICATION_IT_SMTP_ADDR and NOTIFICATION_IT_MAILPIT_URL to run")
	}
	uri, err := amqp091.ParseURI(brokerURL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(smtpAddr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	return itEnv{
		broker: rabbitmq.Config{
			Host: uri.Host, Port: uri.Port, User: uri.Username, Password: uri.Password,
			VHost: uri.Vhost, ConnectionName: "notification-it",
		},
		brokerURL:  brokerURL,
		smtpHost:   host,
		smtpPort:   port,
		mailpitURL: mailpitURL,
	}
}

// startConsumer запускает consumer с настоящими usecase и SMTP-отправителем.
// Возвращает функцию остановки, которая ждёт завершения Run
func startConsumer(t *testing.T, env itEnv, smtpPort int, drain time.Duration) (*consumer, func()) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mailer, err := smtpMailer.NewMailer(smtpMailer.Config{
		Host: env.smtpHost, Port: smtpPort, From: "Vault <no-reply@vault.local>", Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	uc := usecase.NewNotificationUC(mailer, "https://vault.test", usecase.RetryPolicy{Initial: 100 * time.Millisecond, Max: 200 * time.Millisecond}, log)
	c := NewConsumer(Config{Broker: env.broker, Workers: 2, DrainTimeout: drain}, uc, log).(*consumer)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	waitFor(t, "consumer ready", c.Ready)

	var stopped bool
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("consumer did not stop")
		}
	}
	t.Cleanup(stop)
	return c, stop
}

func TestConsumerIntegration(t *testing.T) {
	env := loadITEnv(t)

	conn, err := amqp091.Dial(env.brokerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	if err := rabbitmq.DeclareTopology(ch); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{rabbitmq.EventsQueue, rabbitmq.DeadLetterQueue} {
		if _, err := ch.QueuePurge(q, false); err != nil {
			t.Fatal(err)
		}
	}

	publish := func(routingKey string, body []byte) {
		t.Helper()
		err := ch.PublishWithContext(context.Background(), rabbitmq.EventsExchange, routingKey, false, false, amqp091.Publishing{
			ContentType: "application/json", DeliveryMode: amqp091.Persistent, Body: body,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	queueLen := func(q string) int {
		t.Helper()
		// Пассивное объявление только читает состояние очереди, аргументы не сверяются
		info, err := ch.QueueDeclarePassive(q, true, false, false, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		return info.Messages
	}

	owner := "owner-" + uuid.NewString()[:8] + "@company.com"
	secretID := uuid.NewString()

	_, stop := startConsumer(t, env, env.smtpPort, 5*time.Second)

	t.Run("access.requested sends mail to owner and acks", func(t *testing.T) {
		publish("access.requested", mustJSON(map[string]any{
			"event_id": uuid.NewString(), "type": "access.requested", "occurred_at": time.Now().UTC(),
			"secret_id": secretID, "title": "Доступ к админке CRM", "request_id": uuid.NewString(),
			"requester_email": "ivan@company.com", "owner_email": owner,
			"text": "must-never-be-mailed",
		}))
		msgs := waitForMail(t, env.mailpitURL, owner, 1)
		if msgs[0].Subject != "Запрос доступа к секрету «Доступ к админке CRM»" {
			t.Errorf("subject = %q", msgs[0].Subject)
		}
		if msgs[0].Snippet == "" {
			t.Error("empty body")
		}
		waitFor(t, "queue drained", func() bool { return queueLen(rabbitmq.EventsQueue) == 0 })
	})

	t.Run("invalid and unknown events go to DLQ", func(t *testing.T) {
		publish("access.requested", []byte(`{"type":"access.requested"}`))
		publish("secret.viewed", []byte(`not json`))
		waitFor(t, "2 messages in DLQ", func() bool { return queueLen(rabbitmq.DeadLetterQueue) == 2 })
		if n := queueLen(rabbitmq.EventsQueue); n != 0 {
			t.Errorf("events queue has %d messages", n)
		}
	})

	t.Run("secret.created is acked without mail", func(t *testing.T) {
		publish("secret.created", mustJSON(map[string]any{
			"event_id": uuid.NewString(), "type": "secret.created", "occurred_at": time.Now().UTC(),
			"secret_id": secretID, "owner_id": uuid.NewString(), "expires_at": time.Now().Add(time.Hour).UTC(),
		}))
		waitFor(t, "queue drained", func() bool { return queueLen(rabbitmq.EventsQueue) == 0 })
	})

	stop()

	t.Run("SMTP down: message is not acked and survives shutdown", func(t *testing.T) {
		// Порт, на котором никто не слушает
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		deadPort := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()

		user := "user-" + uuid.NewString()[:8] + "@company.com"
		_, stopDown := startConsumer(t, env, deadPort, 500*time.Millisecond)
		publish("access.revoked", mustJSON(map[string]any{
			"event_id": uuid.NewString(), "type": "access.revoked", "occurred_at": time.Now().UTC(),
			"secret_id": secretID, "title": "CRM", "user_emails": []string{user},
		}))
		time.Sleep(time.Second) // consumer взял сообщение и ретраит
		stopDown()
		waitFor(t, "message requeued", func() bool { return queueLen(rabbitmq.EventsQueue) == 1 })

		// SMTP снова доступен: письмо уходит, очередь пустеет
		_, stopUp := startConsumer(t, env, env.smtpPort, 5*time.Second)
		waitForMail(t, env.mailpitURL, user, 1)
		waitFor(t, "queue drained", func() bool { return queueLen(rabbitmq.EventsQueue) == 0 })
		stopUp()
	})
}

type mailpitMessage struct {
	Subject string `json:"Subject"`
	Snippet string `json:"Snippet"`
}

func waitForMail(t *testing.T, mailpitURL, to string, n int) []mailpitMessage {
	t.Helper()
	var out []mailpitMessage
	waitFor(t, "mail to "+to, func() bool {
		resp, err := http.Get(mailpitURL + "/api/v1/search?query=" + url.QueryEscape("to:"+to))
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var r struct {
			Messages []mailpitMessage `json:"messages"`
		}
		if json.NewDecoder(resp.Body).Decode(&r) != nil {
			return false
		}
		out = r.Messages
		return len(out) >= n
	})
	if len(out) != n {
		t.Fatalf("got %d mails to %s, want %d", len(out), to, n)
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprint(err))
	}
	return b
}
