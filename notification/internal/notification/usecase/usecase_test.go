package usecase

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/anAwesomeWave/simplified-vault/notification/internal/models"
	serverErrors "github.com/anAwesomeWave/simplified-vault/notification/internal/server_errors"
)

// fakeMailer - фейковая реализация notification.Mailer: usecase тестируется без SMTP.
// errs - ошибки, которые вернут первые вызовы Send
type fakeMailer struct {
	sent  []*models.Message
	errs  []error
	calls int
}

func (m *fakeMailer) Send(_ context.Context, msg *models.Message) error {
	m.calls++
	if len(m.errs) > 0 {
		err := m.errs[0]
		m.errs = m.errs[1:]
		if err != nil {
			return err
		}
	}
	cp := *msg
	m.sent = append(m.sent, &cp)
	return nil
}

var ctx = context.Background()

const (
	secretID  = "c2a9e5d4-1f0b-4b8e-8d3a-6e7f9a1b2c3d"
	requestID = "41d0b6e2-9c7a-4f3e-b1d5-2a8c6e4f0b97"
	head      = `"event_id":"7f3e2a10-4c1b-4d7e-9a55-0b8e1f6c2d91","occurred_at":"2026-11-03T10:15:00Z",` +
		`"secret_id":"` + secretID + `","title":"Доступ к админке CRM",`
)

// newUC возвращает usecase без реальных пауз; sleeps накапливает запрошенные паузы
func newUC(m *fakeMailer) (*notificationUC, *[]time.Duration) {
	uc := NewNotificationUC(m, "https://vault.example.com/", RetryPolicy{Initial: time.Second, Max: 4 * time.Second},
		slog.New(slog.NewTextHandler(io.Discard, nil))).(*notificationUC)
	var sleeps []time.Duration
	uc.sleep = func(ctx context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return ctx.Err()
	}
	return uc, &sleeps
}

func mustContain(t *testing.T, s string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(s, p) {
			t.Errorf("%q does not contain %q", s, p)
		}
	}
}

func TestAccessRequested(t *testing.T) {
	m := &fakeMailer{}
	uc, _ := newUC(m)
	err := uc.Handle(ctx, []byte(`{`+head+`"type":"access.requested","request_id":"`+requestID+`",`+
		`"requester_email":"ivan@company.com","owner_email":"anna@company.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.sent) != 1 {
		t.Fatalf("sent %d messages", len(m.sent))
	}
	msg := m.sent[0]
	if msg.To != "anna@company.com" {
		t.Errorf("to = %s, want owner", msg.To)
	}
	if msg.ID != "7f3e2a10-4c1b-4d7e-9a55-0b8e1f6c2d91.0" {
		t.Errorf("id = %s", msg.ID)
	}
	mustContain(t, msg.Subject, "Доступ к админке CRM")
	mustContain(t, msg.Body, "ivan@company.com", "«Доступ к админке CRM»",
		"https://vault.example.com/secrets/"+secretID+"/requests", requestID)
}

func TestAccessDecided(t *testing.T) {
	for decision, word := range map[string]string{"approved": "одобрен", "denied": "отклонён"} {
		m := &fakeMailer{}
		uc, _ := newUC(m)
		err := uc.Handle(ctx, []byte(`{`+head+`"type":"access.decided","decision":"`+decision+`","requester_email":"ivan@company.com"}`))
		if err != nil {
			t.Fatal(err)
		}
		if len(m.sent) != 1 || m.sent[0].To != "ivan@company.com" {
			t.Fatalf("%s: sent = %+v", decision, m.sent)
		}
		mustContain(t, m.sent[0].Subject, word)
		mustContain(t, m.sent[0].Body, "https://vault.example.com/secrets/"+secretID)
	}
}

func TestSecretViewed(t *testing.T) {
	m := &fakeMailer{}
	uc, _ := newUC(m)
	err := uc.Handle(ctx, []byte(`{`+head+`"type":"secret.viewed","viewer_email":"ivan@company.com",`+
		`"owner_email":"anna@company.com","ip":"203.0.113.7"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.sent) != 1 || m.sent[0].To != "anna@company.com" {
		t.Fatalf("sent = %+v", m.sent)
	}
	mustContain(t, m.sent[0].Body, "ivan@company.com", "203.0.113.7", "2026-11-03 10:15:00 UTC")
}

func TestAccessRevokedOneMailPerUser(t *testing.T) {
	m := &fakeMailer{}
	uc, _ := newUC(m)
	err := uc.Handle(ctx, []byte(`{`+head+`"type":"access.revoked","user_emails":["a@b.co","c@d.co","a@b.co"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.sent) != 2 || m.sent[0].To != "a@b.co" || m.sent[1].To != "c@d.co" {
		t.Fatalf("sent = %+v", m.sent)
	}
	if m.sent[0].ID == m.sent[1].ID {
		t.Error("message ids must differ")
	}
	mustContain(t, m.sent[0].Body, "«Доступ к админке CRM»", "закрыт")
}

func TestSecretCreatedOnlyLogs(t *testing.T) {
	m := &fakeMailer{}
	uc, _ := newUC(m)
	err := uc.Handle(ctx, []byte(`{`+head+`"type":"secret.created","owner_id":"`+requestID+`","expires_at":"2026-11-04T10:15:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.calls != 0 {
		t.Fatalf("secret.created must not send mail, sent %d", m.calls)
	}
}

// ФТ-17: текст секрета не попадает в письма никогда, даже если по ошибке окажется в событии
func TestSecretTextNeverInMail(t *testing.T) {
	const leak = "s3cr3t-P@ssw0rd"
	m := &fakeMailer{}
	uc, _ := newUC(m)
	bodies := []string{
		`{` + head + `"type":"access.requested","request_id":"` + requestID + `","requester_email":"ivan@company.com","owner_email":"anna@company.com","text":"` + leak + `","ciphertext":"` + leak + `"}`,
		`{` + head + `"type":"access.decided","decision":"approved","requester_email":"ivan@company.com","text":"` + leak + `"}`,
		`{` + head + `"type":"secret.viewed","viewer_email":"ivan@company.com","owner_email":"anna@company.com","ip":"10.0.0.1","text":"` + leak + `"}`,
		`{` + head + `"type":"access.revoked","user_emails":["ivan@company.com"],"text":"` + leak + `"}`,
	}
	for _, b := range bodies {
		if err := uc.Handle(ctx, []byte(b)); err != nil {
			t.Fatal(err)
		}
	}
	for _, msg := range m.sent {
		if strings.Contains(msg.Subject+msg.Body, leak) {
			t.Fatalf("secret text leaked into mail: %+v", msg)
		}
	}
}

func TestInvalidEventIsPermanent(t *testing.T) {
	m := &fakeMailer{}
	uc, _ := newUC(m)
	err := uc.Handle(ctx, []byte(`{`+head+`"type":"access.requested"}`))
	if !serverErrors.IsPermanent(err) {
		t.Fatalf("err = %v, want permanent", err)
	}
	if m.calls != 0 {
		t.Fatal("invalid event must not send mail")
	}
}

func TestRetryTransientErrors(t *testing.T) {
	transient := errors.New("connection refused")
	m := &fakeMailer{errs: []error{transient, transient, transient, transient}}
	uc, sleeps := newUC(m)
	err := uc.Handle(ctx, []byte(`{`+head+`"type":"access.decided","decision":"deny","requester_email":"ivan@company.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.sent) != 1 || m.calls != 5 {
		t.Fatalf("sent %d, calls %d", len(m.sent), m.calls)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second}
	if len(*sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %v", *sleeps, want)
	}
	for i := range want {
		if (*sleeps)[i] != want[i] {
			t.Fatalf("sleeps = %v, want %v", *sleeps, want)
		}
	}
}

// При повторе после временной ошибки уже отправленные письма access.revoked
// не переотправляются
func TestRetryDoesNotResendDelivered(t *testing.T) {
	m := &fakeMailer{errs: []error{nil, errors.New("timeout"), nil}}
	uc, _ := newUC(m)
	err := uc.Handle(ctx, []byte(`{`+head+`"type":"access.revoked","user_emails":["a@b.co","c@d.co"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.sent) != 2 || m.sent[0].To != "a@b.co" || m.sent[1].To != "c@d.co" {
		t.Fatalf("sent = %+v", m.sent)
	}
}

func TestPermanentDeliveryErrorStopsRetries(t *testing.T) {
	m := &fakeMailer{errs: []error{serverErrors.ErrPermanentDelivery}}
	uc, sleeps := newUC(m)
	err := uc.Handle(ctx, []byte(`{`+head+`"type":"access.decided","decision":"deny","requester_email":"ivan@company.com"}`))
	if !errors.Is(err, serverErrors.ErrPermanentDelivery) {
		t.Fatalf("err = %v", err)
	}
	if m.calls != 1 || len(*sleeps) != 0 {
		t.Fatalf("calls %d, sleeps %v", m.calls, *sleeps)
	}
}

func TestCancelStopsRetries(t *testing.T) {
	m := &fakeMailer{errs: []error{errors.New("down"), errors.New("down"), errors.New("down")}}
	uc, _ := newUC(m)
	cctx, cancel := context.WithCancel(ctx)
	uc.sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }

	err := uc.Handle(cctx, []byte(`{`+head+`"type":"access.decided","decision":"deny","requester_email":"ivan@company.com"}`))
	if !errors.Is(err, context.Canceled) || serverErrors.IsPermanent(err) {
		t.Fatalf("err = %v, want non-permanent context.Canceled", err)
	}
}
