package smtp

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anAwesomeWave/simplified-vault/notification/internal/models"
	serverErrors "github.com/anAwesomeWave/simplified-vault/notification/internal/server_errors"
)

// fakeSMTP - минимальный SMTP-сервер: принимает одно письмо на соединение
// и отвечает на RCPT заданным кодом
type fakeSMTP struct {
	ln       net.Listener
	rcptCode string // "250", "550 ...", "451 ..."
	silent   bool   // не отвечать вообще (проверка таймаута)

	mu   sync.Mutex
	from string
	to   []string
	data []string
}

func startFakeSMTP(t *testing.T, rcptCode string) *fakeSMTP {
	t.Helper()
	return startFakeSMTPMode(t, rcptCode, false)
}

func startFakeSMTPMode(t *testing.T, rcptCode string, silent bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSMTP{ln: ln, rcptCode: rcptCode, silent: silent}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	if s.silent {
		_, _ = io.Copy(io.Discard, c)
		return
	}
	tp := textproto.NewConn(c)
	_ = tp.PrintfLine("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch {
		case cmd == "EHLO" || cmd == "HELO":
			_ = tp.PrintfLine("250 fake")
		case strings.HasPrefix(strings.ToUpper(line), "MAIL FROM:"):
			s.mu.Lock()
			s.from = line[len("MAIL FROM:"):]
			s.mu.Unlock()
			_ = tp.PrintfLine("250 ok")
		case strings.HasPrefix(strings.ToUpper(line), "RCPT TO:"):
			s.mu.Lock()
			s.to = append(s.to, line[len("RCPT TO:"):])
			s.mu.Unlock()
			_ = tp.PrintfLine("%s", s.rcptCode)
		case cmd == "DATA":
			_ = tp.PrintfLine("354 go ahead")
			b, err := io.ReadAll(tp.DotReader())
			if err != nil {
				return
			}
			s.mu.Lock()
			s.data = append(s.data, string(b))
			s.mu.Unlock()
			_ = tp.PrintfLine("250 queued")
		case cmd == "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("502 unknown")
		}
	}
}

func newTestMailer(t *testing.T, s *fakeSMTP, timeout time.Duration) *smtpMailer {
	t.Helper()
	addr := s.ln.Addr().(*net.TCPAddr)
	m, err := NewMailer(Config{
		Host: "127.0.0.1", Port: addr.Port, HeloName: "notification",
		From: "Сервис передачи секретов <no-reply@vault.local>", Timeout: timeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m.(*smtpMailer)
}

func TestSendRendersMessage(t *testing.T) {
	s := startFakeSMTP(t, "250 ok")
	m := newTestMailer(t, s, 5*time.Second)

	msg := &models.Message{
		ID:      "7f3e2a10-4c1b-4d7e-9a55-0b8e1f6c2d91.0",
		To:      "anna@company.com",
		Subject: "Запрос доступа к секрету «CRM»\r\nBcc: evil@x.co",
		Body:    "Строка 1\nСтрока 2: " + strings.Repeat("длинная ", 30) + "\n",
	}
	if err := m.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.from != "<no-reply@vault.local>" || len(s.to) != 1 || s.to[0] != "<anna@company.com>" {
		t.Fatalf("envelope from=%q to=%q", s.from, s.to)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(s.data[0]))
	if err != nil {
		t.Fatal(err)
	}
	h := parsed.Header
	if !strings.Contains(s.data[0], "?=\n =?") {
		t.Error("long encoded header is not folded")
	}
	if h.Get("To") != "anna@company.com" || h.Get("Bcc") != "" {
		t.Fatalf("headers = %v", h)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(h.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	if subject != "Запрос доступа к секрету «CRM»  Bcc: evil@x.co" {
		t.Fatalf("subject = %q", subject)
	}
	from, err := mail.ParseAddress(h.Get("From"))
	if err != nil || from.Name != "Сервис передачи секретов" || from.Address != "no-reply@vault.local" {
		t.Fatalf("from = %v (%v)", from, err)
	}
	if h.Get("Message-Id") != "<7f3e2a10-4c1b-4d7e-9a55-0b8e1f6c2d91.0@vault.local>" {
		t.Fatalf("message-id = %q", h.Get("Message-Id"))
	}
	if !strings.HasPrefix(h.Get("Content-Type"), "text/plain") || h.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Fatalf("content headers = %v", h)
	}
	// mail.ReadMessage не декодирует quoted-printable сам
	body, _ := io.ReadAll(parsed.Body)
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(string(body))))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(decoded), "Строка 1\nСтрока 2: длинная") {
		t.Fatalf("body = %q", decoded)
	}
	// DotReader отдаёт строки с LF вместо CRLF
	for _, line := range strings.Split(s.data[0], "\n") {
		// RFC 5322 §2.1.1: жёсткий предел 998 символов; длинные темы переносятся
		if len(line) > 998 {
			t.Fatalf("line longer than 998 chars: %q", line)
		}
	}
}

func TestSendErrorClassification(t *testing.T) {
	msg := &models.Message{To: "anna@company.com", Subject: "s", Body: "b"}

	m := newTestMailer(t, startFakeSMTP(t, "550 no such user"), 5*time.Second)
	if err := m.Send(context.Background(), msg); !errors.Is(err, serverErrors.ErrPermanentDelivery) {
		t.Errorf("550: err = %v, want permanent", err)
	}

	m = newTestMailer(t, startFakeSMTP(t, "451 try later"), 5*time.Second)
	if err := m.Send(context.Background(), msg); err == nil || serverErrors.IsPermanent(err) {
		t.Errorf("451: err = %v, want transient", err)
	}

	// Сервер недоступен - временная ошибка
	s := startFakeSMTP(t, "250 ok")
	m = newTestMailer(t, s, 5*time.Second)
	_ = s.ln.Close()
	if err := m.Send(context.Background(), msg); err == nil || serverErrors.IsPermanent(err) {
		t.Errorf("closed: err = %v, want transient", err)
	}

	// Некорректный адрес получателя не уходит на сервер
	m = newTestMailer(t, startFakeSMTP(t, "250 ok"), 5*time.Second)
	bad := &models.Message{To: "anna@company.com\r\nRCPT TO:<evil@x.co>", Subject: "s", Body: "b"}
	if err := m.Send(context.Background(), bad); !errors.Is(err, serverErrors.ErrPermanentDelivery) {
		t.Errorf("bad recipient: err = %v", err)
	}
}

func TestSendTimeoutAndCancel(t *testing.T) {
	msg := &models.Message{To: "anna@company.com", Subject: "s", Body: "b"}
	s := startFakeSMTPMode(t, "250 ok", true)

	m := newTestMailer(t, s, 200*time.Millisecond)
	start := time.Now()
	if err := m.Send(context.Background(), msg); err == nil || serverErrors.IsPermanent(err) {
		t.Fatalf("silent server: err = %v, want transient", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout is not enforced")
	}

	m = newTestMailer(t, s, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start = time.Now()
	if err := m.Send(ctx, msg); err == nil {
		t.Fatal("cancelled send succeeded")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancel is not enforced")
	}
}
