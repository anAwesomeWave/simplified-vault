package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/anAwesomeWave/simplified-vault/notification/internal/broker/rabbitmq"
	"github.com/anAwesomeWave/simplified-vault/notification/internal/config"
	"github.com/anAwesomeWave/simplified-vault/notification/internal/notification"
	amqpDelivery "github.com/anAwesomeWave/simplified-vault/notification/internal/notification/delivery/amqp"
	smtpMailer "github.com/anAwesomeWave/simplified-vault/notification/internal/notification/mailer/smtp"
	notificationUsecase "github.com/anAwesomeWave/simplified-vault/notification/internal/notification/usecase"
)

// Server - единственное место, где слои собираются вместе:
// mailer -> usecase -> consumer
type Server struct {
	cfg            *config.Config
	rabbitPassword string
	log            *slog.Logger

	consumer     notification.Consumer
	stopConsumer context.CancelFunc
	consumerDone chan struct{}
	health       *http.Server
}

func NewServer(cfg *config.Config, rabbitPassword string, log *slog.Logger) *Server {
	return &Server{cfg: cfg, rabbitPassword: rabbitPassword, log: log}
}

// Run собирает слои и запускает consumer и /healthz в фоне. Ошибка
// инициализации возвращается сразу, ошибка работающих компонентов приходит в errCh
func (s *Server) Run(errCh chan<- error) error {
	// Init mailer
	mailer, err := smtpMailer.NewMailer(smtpMailer.Config{
		Host:     s.cfg.SMTPHost,
		Port:     s.cfg.SMTPPort,
		HeloName: s.cfg.SMTPHelo,
		From:     s.cfg.MailFrom,
		StartTLS: s.cfg.SMTPStartTLS,
		Timeout:  s.cfg.SMTPTimeout,
	})
	if err != nil {
		return err
	}

	// Init useCases
	uc := notificationUsecase.NewNotificationUC(mailer, s.cfg.PublicBaseURL, notificationUsecase.DefaultRetryPolicy, s.log)

	// Init consumer
	s.consumer = amqpDelivery.NewConsumer(amqpDelivery.Config{
		Broker: rabbitmq.Config{
			Host:           s.cfg.RabbitHost,
			Port:           s.cfg.RabbitPort,
			User:           s.cfg.RabbitUser,
			Password:       s.rabbitPassword,
			VHost:          s.cfg.RabbitVHost,
			ConnectionName: "notification",
		},
		Workers:      s.cfg.Workers,
		DrainTimeout: s.cfg.DrainTimeout,
	}, uc, s.log)

	var ctx context.Context
	ctx, s.stopConsumer = context.WithCancel(context.Background())
	s.consumerDone = make(chan struct{})
	go func() {
		defer close(s.consumerDone)
		if err := s.consumer.Run(ctx); err != nil {
			errCh <- fmt.Errorf("consumer: %w", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	s.health = &http.Server{
		Addr:              s.cfg.HealthAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	go func() {
		s.log.Info("health endpoint listening", slog.String("addr", s.cfg.HealthAddr))
		if err := s.health.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("health listen: %w", err)
		}
	}()
	return nil
}

// healthz отвечает 200, пока consumer подключён к брокеру и читает очередь
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	if !s.consumer.Ready() {
		http.Error(w, "not consuming", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ok"))
}

// Stop останавливает чтение очереди, дожидается обработки полученных сообщений
// (не дольше ctx) и закрывает /healthz
func (s *Server) Stop(ctx context.Context) error {
	if s.stopConsumer == nil {
		return nil
	}
	s.stopConsumer()
	var err error
	select {
	case <-s.consumerDone:
	case <-ctx.Done():
		err = fmt.Errorf("consumer did not stop: %w", ctx.Err())
	}
	return errors.Join(err, s.health.Shutdown(ctx))
}
