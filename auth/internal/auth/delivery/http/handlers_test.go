package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/models"
	serverErrors "github.com/anAwesomeWave/simplified-vault/auth/internal/server_errors"
)

// stubUC - заглушка auth.UseCase: проверяется только слой delivery -
// разбор запросов, коды ответов и сопоставление ошибок
type stubUC struct {
	got       models.Credentials
	userID    uuid.UUID
	token     *models.AccessToken
	err       error
	healthErr error
}

func (s *stubUC) Register(_ context.Context, r models.Credentials) (uuid.UUID, error) {
	s.got = r
	return s.userID, s.err
}

func (s *stubUC) Login(_ context.Context, r models.Credentials) (*models.AccessToken, error) {
	s.got = r
	return s.token, s.err
}

func (s *stubUC) CheckHealth(context.Context) error { return s.healthErr }

func newServer(t *testing.T, uc *stubUC) *httptest.Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(NewRouter(NewHandler(uc, log), log))
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, srv *httptest.Server, method, path, body string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: non-JSON response %q", method, path, raw)
		}
	}
	return resp, out
}

func TestRegisterSuccess(t *testing.T) {
	uc := &stubUC{userID: uuid.New()}
	srv := newServer(t, uc)

	resp, body := do(t, srv, "POST", "/auth/register", `{"email":"anna@company.com","password":"0123456789"}`)
	if resp.StatusCode != http.StatusCreated || body["user_id"] != uc.userID.String() {
		t.Fatalf("%d %v", resp.StatusCode, body)
	}
	if uc.got != (models.Credentials{Email: "anna@company.com", Password: "0123456789"}) {
		t.Fatalf("usecase got %+v", uc.got)
	}
}

func TestLoginSuccess(t *testing.T) {
	uc := &stubUC{token: &models.AccessToken{AccessToken: "jwt", TokenType: "Bearer", ExpiresIn: 900}}
	srv := newServer(t, uc)

	resp, body := do(t, srv, "POST", "/auth/login", `{"email":"anna@company.com","password":"0123456789"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %v", resp.StatusCode, body)
	}
	if body["access_token"] != "jwt" || body["expires_in"] != float64(900) || body["token_type"] != "Bearer" {
		t.Fatalf("body = %v", body)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("token response must not be cached")
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		path   string
		err    error
		status int
		code   string
	}{
		{"/auth/register", serverErrors.ErrInvalidEmail, 400, "invalid_email"},
		{"/auth/register", serverErrors.ErrPasswordTooShort, 400, "password_too_short"},
		{"/auth/register", serverErrors.ErrPasswordTooLong, 400, "password_too_long"},
		{"/auth/register", serverErrors.ErrEmailTaken, 409, "email_taken"},
		{"/auth/register", errors.New("pq: connection refused"), 500, "internal_error"},
		{"/auth/login", serverErrors.ErrInvalidCredentials, 401, "invalid_credentials"},
		{"/auth/login", errors.New("pq: connection refused"), 500, "internal_error"},
	}
	for _, tc := range cases {
		t.Run(tc.path+" "+tc.code, func(t *testing.T) {
			srv := newServer(t, &stubUC{err: tc.err})
			resp, body := do(t, srv, "POST", tc.path, `{"email":"a@b.co","password":"0123456789"}`)
			if resp.StatusCode != tc.status || body["error"] != tc.code {
				t.Fatalf("%d %v; want %d %s", resp.StatusCode, body, tc.status, tc.code)
			}
			if msg, _ := body["message"].(string); msg == "" || strings.Contains(msg, "pq:") {
				t.Fatalf("message = %q: must be non-empty and must not leak internals", msg)
			}
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	srv := newServer(t, &stubUC{})
	cases := []struct {
		body   string
		status int
		code   string
	}{
		{`{"email":`, 400, "invalid_json"},
		{`{}{}`, 400, "invalid_json"},
		{`[]`, 400, "invalid_json"},
		{`{"email":"` + strings.Repeat("a", 20<<10) + `"}`, 413, "body_too_large"},
	}
	for _, tc := range cases {
		resp, body := do(t, srv, "POST", "/auth/register", tc.body)
		if resp.StatusCode != tc.status || body["error"] != tc.code {
			t.Errorf("body %.20q: %d %v; want %d %s", tc.body, resp.StatusCode, body, tc.status, tc.code)
		}
	}
}

func TestRouting(t *testing.T) {
	srv := newServer(t, &stubUC{})

	resp, body := do(t, srv, "GET", "/auth/login", "")
	if resp.StatusCode != 405 || body["error"] != "method_not_allowed" || resp.Header.Get("Allow") != "POST" {
		t.Fatalf("GET /auth/login: %d %v", resp.StatusCode, body)
	}
	resp, body = do(t, srv, "GET", "/nope", "")
	if resp.StatusCode != 404 || body["error"] != "not_found" {
		t.Fatalf("GET /nope: %d %v", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("X-Request-ID") == "" {
		t.Fatal("security headers / request id are missing")
	}
}

func TestHealth(t *testing.T) {
	ok := newServer(t, &stubUC{})
	if resp, body := do(t, ok, "GET", "/healthz", ""); resp.StatusCode != 200 || body["status"] != "ok" {
		t.Fatalf("healthy: %d %v", resp.StatusCode, body)
	}
	down := newServer(t, &stubUC{healthErr: errors.New("down")})
	if resp, body := do(t, down, "GET", "/healthz", ""); resp.StatusCode != 503 || body["error"] != "unavailable" {
		t.Fatalf("unhealthy: %d %v", resp.StatusCode, body)
	}
}
