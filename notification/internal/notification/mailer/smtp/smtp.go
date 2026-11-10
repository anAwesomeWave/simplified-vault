// Package smtp отправляет письма по SMTP (в учебном стенде - в Mailpit).
package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/anAwesomeWave/simplified-vault/notification/internal/models"
	"github.com/anAwesomeWave/simplified-vault/notification/internal/notification"
	serverErrors "github.com/anAwesomeWave/simplified-vault/notification/internal/server_errors"
)

type Config struct {
	Host string
	Port int
	// HeloName - имя в команде EHLO
	HeloName string
	// From - адрес отправителя, например "Vault <no-reply@vault.local>"
	From string
	// StartTLS требует STARTTLS перед отправкой. Mailpit в стенде работает
	// без TLS во внутренней сети mail, поэтому по умолчанию выключено
	StartTLS bool
	// Timeout - предел на всю отправку одного письма
	Timeout time.Duration
}

type smtpMailer struct {
	cfg      Config
	addr     string
	from     *mail.Address
	msgIDDom string
	now      func() time.Time
}

func NewMailer(cfg Config) (notification.Mailer, error) {
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("smtp: invalid from address: %w", err)
	}
	if cfg.Host == "" || cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, errors.New("smtp: invalid server address")
	}
	if cfg.HeloName == "" {
		cfg.HeloName = "localhost"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &smtpMailer{
		cfg:      cfg,
		addr:     net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		from:     from,
		msgIDDom: from.Address[strings.LastIndexByte(from.Address, '@')+1:],
		now:      time.Now,
	}, nil
}

// Send отправляет письмо. Ответ сервера 5xx - окончательный отказ
// (ErrPermanentDelivery), остальные ошибки (сеть, 4xx, таймаут) - временные
func (m *smtpMailer) Send(ctx context.Context, msg *models.Message) error {
	data, err := m.render(msg)
	if err != nil {
		return err
	}
	if err := m.send(ctx, msg.To.String(), data); err != nil {
		var tpErr *textproto.Error
		if errors.As(err, &tpErr) && tpErr.Code >= 500 {
			return fmt.Errorf("%w: %v", serverErrors.ErrPermanentDelivery, err)
		}
		return fmt.Errorf("smtp: %w", err)
	}
	return nil
}

func (m *smtpMailer) send(ctx context.Context, to string, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", m.addr)
	if err != nil {
		return err
	}
	// net/smtp не принимает контекст: дедлайн на соединение плюс закрытие при
	// отмене ctx не дают зависнуть на медленном или молчащем сервере
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer c.Close()

	if err := c.Hello(m.cfg.HeloName); err != nil {
		return err
	}
	if m.cfg.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("server does not support STARTTLS")
		}
		if err := c.StartTLS(&tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if err := c.Mail(m.from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	// Письмо уже принято сервером; ошибка QUIT на результат не влияет
	_ = c.Quit()
	return nil
}

// render собирает письмо: text/plain в UTF-8, тело в quoted-printable, тема по RFC 2047.
//
// Получатель - проверенный models.Email, тема очищается от переводов строк,
// поэтому внедрить свои заголовки через данные события нельзя
func (m *smtpMailer) render(msg *models.Message) ([]byte, error) {
	if _, err := models.NewEmail(msg.To.String()); err != nil {
		return nil, fmt.Errorf("%w: invalid recipient", serverErrors.ErrPermanentDelivery)
	}

	var buf bytes.Buffer
	header := func(k, v string) { buf.WriteString(k + ": " + v + "\r\n") }
	header("From", fold(m.from.String()))
	header("To", msg.To.String())
	header("Subject", fold(mime.QEncoding.Encode("utf-8", oneLine(msg.Subject))))
	header("Date", m.now().UTC().Format(time.RFC1123Z))
	if msg.ID != "" {
		header("Message-ID", "<"+oneLine(msg.ID)+"@"+m.msgIDDom+">")
	}
	header("MIME-Version", "1.0")
	header("Content-Type", `text/plain; charset="utf-8"`)
	header("Content-Transfer-Encoding", "quoted-printable")
	header("Auto-Submitted", "auto-generated")
	buf.WriteString("\r\n")

	qp := quotedprintable.NewWriter(&buf)
	if _, err := qp.Write([]byte(msg.Body)); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// fold переносит длинный заголовок по границам encoded-words (RFC 2047 §2,
// RFC 5322 §2.2.3): mime кодирует слова по 75 символов, но строки не переносит
func fold(v string) string {
	return strings.ReplaceAll(v, "?= =?", "?=\r\n =?")
}

// oneLine заменяет управляющие символы пробелами: значение заголовка
// не может содержать CR/LF
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
