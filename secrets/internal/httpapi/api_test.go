package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"simple-vault/secrets/internal/domain"
)

const secretID = "0156fcb7-8669-4719-ab93-91393fbdbdc8"
const requestID = "444b0372-60ad-48bd-8830-19b2ee8dcf96"
const userID = "bf618afa-1bb8-47b6-b92f-9653850ec8db"

var identity = domain.User{ID: userID, Email: "user@example.com"}

type stubService struct {
	domain.Service
	create       func(context.Context, domain.User, domain.CreateInput) (domain.Created, error)
	owned        func(context.Context, domain.User) ([]domain.Owned, error)
	shared       func(context.Context, domain.User) ([]domain.Shared, error)
	open         func(context.Context, domain.User, string, string) (*domain.Opened, error)
	history      func(context.Context, domain.User, string) (domain.History, error)
	decide       func(context.Context, domain.User, string, string, string) (domain.Decision, error)
	revokeAccess func(context.Context, domain.User, string, string) error
	revoke       func(context.Context, domain.User, string) error
}

func (s stubService) Create(c context.Context, u domain.User, in domain.CreateInput) (domain.Created, error) {
	return s.create(c, u, in)
}
func (s stubService) ListOwned(c context.Context, u domain.User) ([]domain.Owned, error) {
	return s.owned(c, u)
}
func (s stubService) ListShared(c context.Context, u domain.User) ([]domain.Shared, error) {
	return s.shared(c, u)
}
func (s stubService) Open(c context.Context, u domain.User, id, ip string) (*domain.Opened, error) {
	return s.open(c, u, id, ip)
}
func (s stubService) History(c context.Context, u domain.User, id string) (domain.History, error) {
	return s.history(c, u, id)
}
func (s stubService) Decide(c context.Context, u domain.User, id, rid, d string) (domain.Decision, error) {
	return s.decide(c, u, id, rid, d)
}
func (s stubService) RevokeAccess(c context.Context, u domain.User, id, uid string) error {
	return s.revokeAccess(c, u, id, uid)
}
func (s stubService) Revoke(c context.Context, u domain.User, id string) error {
	return s.revoke(c, u, id)
}

func testHandler(service domain.Service) http.Handler {
	return New(service, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Second)
}

func perform(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.20:12345"
	setIdentity(r)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func assertError(t *testing.T, w *httptest.ResponseRecorder, status int, kind string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status=%d want=%d body=%s", w.Code, status, w.Body.String())
	}
	var value map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if len(value) != 2 || value["error"] != kind || value["message"] == "" {
		t.Fatalf("invalid error contract: %v", value)
	}
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatal("error response is not JSON")
	}
}

func setIdentity(r *http.Request) {
	r.Header.Set("X-User-ID", identity.ID)
	r.Header.Set("X-User-Email", identity.Email)
}

func TestEverySecretsRouteRequiresGatewayIdentity(t *testing.T) {
	h := testHandler(stubService{})
	routes := [][2]string{
		{"POST", "/secrets"}, {"GET", "/secrets"}, {"GET", "/secrets/shared"}, {"GET", "/secrets/" + secretID},
		{"GET", "/secrets/" + secretID + "/requests"}, {"POST", "/secrets/" + secretID + "/requests/" + requestID},
		{"DELETE", "/secrets/" + secretID + "/access/" + userID}, {"DELETE", "/secrets/" + secretID},
	}
	for _, route := range routes {
		t.Run(route[0]+route[1], func(t *testing.T) {
			r := httptest.NewRequest(route[0], route[1], strings.NewReader(`{}`))
			r.Header.Set("Authorization", "Bearer ignored-token")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assertError(t, w, http.StatusUnauthorized, "gateway_identity_required")
			if w.Header().Get("WWW-Authenticate") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("unexpected authentication/cache response headers")
			}
		})
	}
}

func TestRejectsMissingMalformedAndDuplicateIdentityHeaders(t *testing.T) {
	h := testHandler(stubService{})
	cases := []struct {
		name   string
		mutate func(http.Header)
	}{
		{"missing ID", func(h http.Header) { h.Del("X-User-ID") }},
		{"missing email", func(h http.Header) { h.Del("X-User-Email") }},
		{"empty ID", func(h http.Header) { h.Set("X-User-ID", "") }},
		{"empty email", func(h http.Header) { h.Set("X-User-Email", "") }},
		{"malformed ID", func(h http.Header) { h.Set("X-User-ID", "invalid") }},
		{"zero ID", func(h http.Header) { h.Set("X-User-ID", "00000000-0000-0000-0000-000000000000") }},
		{"malformed email", func(h http.Header) { h.Set("X-User-Email", "invalid") }},
		{"display name email", func(h http.Header) { h.Set("X-User-Email", "User <user@example.com>") }},
		{"duplicate ID", func(h http.Header) { h.Add("X-User-ID", userID) }},
		{"duplicate email", func(h http.Header) { h.Add("X-User-Email", identity.Email) }},
		{"joined ID", func(h http.Header) { h.Set("X-User-ID", userID+","+userID) }},
		{"joined email", func(h http.Header) { h.Set("X-User-Email", identity.Email+","+identity.Email) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/secrets", nil)
			setIdentity(r)
			tc.mutate(r.Header)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assertError(t, w, 401, "gateway_identity_required")
		})
	}
}

func TestAuthorizationIsIgnoredWhenGatewayIdentityIsPresent(t *testing.T) {
	h := testHandler(stubService{owned: func(_ context.Context, u domain.User) ([]domain.Owned, error) {
		if u != identity {
			t.Fatalf("wrong identity: %+v", u)
		}
		return nil, nil
	}})
	r := httptest.NewRequest("GET", "/secrets", nil)
	setIdentity(r)
	r.Header.Set("Authorization", "malformed and ignored")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("gateway identity rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestPublicEndpointsDoNotRequireGatewayIdentity(t *testing.T) {
	h := testHandler(stubService{})
	for path, status := range map[string]int{"/health/live": 200, "/docs": 200, "/openapi.yaml": 200, "/health/ready": 404} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s: status=%d want=%d", path, w.Code, status)
		}
	}
}

func TestCreateForwardsIdentityAndReturnsContract(t *testing.T) {
	expiry := time.Date(2026, 11, 5, 14, 0, 0, 0, time.UTC)
	h := testHandler(stubService{create: func(ctx context.Context, u domain.User, in domain.CreateInput) (domain.Created, error) {
		if u != identity || in.Title != "title" || in.Text != "secret text" || in.TTLSeconds == nil || *in.TTLSeconds != 300 {
			t.Fatalf("wrong create inputs: %+v %+v", u, in)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("request deadline missing")
		}
		return domain.Created{ID: secretID, Link: "https://vault.example/secrets/" + secretID, ExpiresAt: expiry}, nil
	}})
	w := perform(h, "POST", "/secrets", `{"title":"title","text":"secret text","ttl_seconds":300}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 || result["id"] != secretID || result["link"] != "https://vault.example/secrets/"+secretID || result["expires_at"] != expiry.Format(time.RFC3339) {
		t.Fatalf("invalid create contract: %v", result)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("create response may be cached")
	}
}

func TestRejectsMalformedOrAmbiguousJSON(t *testing.T) {
	service := stubService{create: func(context.Context, domain.User, domain.CreateInput) (domain.Created, error) {
		t.Error("invalid JSON reached service")
		return domain.Created{}, nil
	}}
	h := testHandler(service)
	for _, body := range []string{`{"title":"x","text":"s","recipients":[]}`, `{"title":"x"} {"text":"s"}`, `{"ttl_seconds":"300"}`, `{"title":`, strings.Repeat(" ", 128*1024) + `{}`} {
		t.Run(fmt.Sprintf("body length%d", len(body)), func(t *testing.T) {
			assertError(t, perform(h, "POST", "/secrets", body), 400, "invalid_request")
		})
	}
	r := httptest.NewRequest("POST", "/secrets", strings.NewReader(`{}`))
	setIdentity(r)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertError(t, w, 400, "invalid_request")
}

func TestOpenPendingAndErrorContracts(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		kind   string
	}{
		{"pending", nil, 202, ""}, {"denied", domain.ErrForbidden, 403, "forbidden"}, {"expired", domain.ErrNotFound, 404, "not_found"},
		{"conflict", fmt.Errorf("wrapped: %w", domain.ErrConflict), 409, "conflict"}, {"invalid", domain.ErrInvalid, 400, "invalid_request"},
		{"timeout", context.DeadlineExceeded, 504, "timeout"}, {"canceled", context.Canceled, 503, "unavailable"}, {"internal", errors.New("database password sensitive"), 500, "internal_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := testHandler(stubService{open: func(_ context.Context, u domain.User, id, ip string) (*domain.Opened, error) {
				if u != identity || id != secretID || ip != "192.0.2.20" {
					t.Fatalf("wrong access inputs: %+v %s %s", u, id, ip)
				}
				return nil, tc.err
			}})
			w := perform(h, "GET", "/secrets/"+secretID, "")
			if tc.err != nil {
				assertError(t, w, tc.status, tc.kind)
			} else if w.Code != 202 || strings.TrimSpace(w.Body.String()) != `{"status":"pending"}` {
				t.Fatalf("invalid pending contract: %d %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "sensitive") {
				t.Fatal("internal error leaked")
			}
		})
	}
}

func TestSuccessfulOpenUsesGatewayIPWithPeerFallback(t *testing.T) {
	cases := []struct {
		name string
		ips  []string
		want string
	}{
		{"gateway IPv4", []string{"198.51.100.7"}, "198.51.100.7"},
		{"gateway IPv6", []string{"2001:db8::7"}, "2001:db8::7"},
		{"missing", nil, "192.0.2.20"},
		{"invalid", []string{"invalid"}, "192.0.2.20"},
		{"duplicate", []string{"198.51.100.7", "198.51.100.8"}, "192.0.2.20"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := testHandler(stubService{open: func(_ context.Context, u domain.User, id, ip string) (*domain.Opened, error) {
				if u != identity || ip != tc.want {
					t.Fatalf("identity=%+v IP=%q want=%q", u, ip, tc.want)
				}
				return &domain.Opened{ID: id, Title: "title", Text: "secret text", ExpiresAt: time.Now().Add(time.Hour)}, nil
			}})
			r := httptest.NewRequest("GET", "/secrets/"+secretID, nil)
			r.RemoteAddr = "192.0.2.20:12345"
			setIdentity(r)
			for _, ip := range tc.ips {
				r.Header.Add("X-Real-IP", ip)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var result map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || len(result) != 4 || result["id"] != secretID || result["text"] != "secret text" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("invalid secret response: %d %v", w.Code, result)
			}
		})
	}
}

func TestEmptyListsAndHistoryAreArrays(t *testing.T) {
	h := testHandler(stubService{
		owned: func(_ context.Context, u domain.User) ([]domain.Owned, error) {
			if u != identity {
				t.Fatalf("wrong owner identity: %+v", u)
			}
			return nil, nil
		},
		shared: func(_ context.Context, u domain.User) ([]domain.Shared, error) {
			if u != identity {
				t.Fatalf("wrong recipient identity: %+v", u)
			}
			return nil, nil
		},
		history: func(_ context.Context, u domain.User, id string) (domain.History, error) {
			if u != identity || id != secretID {
				t.Fatal("wrong history inputs")
			}
			return domain.History{}, nil
		},
	})
	for path, want := range map[string]string{"/secrets": "[]", "/secrets/shared": "[]", "/secrets/" + secretID + "/requests": `{"requests":[],"views":[]}`} {
		w := perform(h, "GET", path, "")
		if w.Code != 200 || strings.TrimSpace(w.Body.String()) != want {
			t.Fatalf("%s: status%d body=%s want=%s", path, w.Code, w.Body.String(), want)
		}
	}
}

func TestDecisionAndRevocations(t *testing.T) {
	decisionCalls, revokeCalls, accessCalls := 0, 0, 0
	h := testHandler(stubService{
		decide: func(_ context.Context, u domain.User, id, rid, d string) (domain.Decision, error) {
			decisionCalls++
			if u != identity || id != secretID || rid != requestID || d != "approve" {
				t.Fatal("wrong decision inputs")
			}
			return domain.Decision{RequestID: rid, Status: "approved"}, nil
		},
		revoke: func(_ context.Context, u domain.User, id string) error {
			revokeCalls++
			if u != identity || id != secretID {
				t.Fatal("wrong revoke inputs")
			}
			return nil
		},
		revokeAccess: func(_ context.Context, u domain.User, id, uid string) error {
			accessCalls++
			if u != identity || id != secretID || uid != userID {
				t.Fatal("wrong access revoke inputs")
			}
			return nil
		},
	})
	path := "/secrets/" + secretID + "/requests/" + requestID
	w := perform(h, "POST", path, `{"decision":"approve"}`)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"request_id":"`+requestID+`","status":"approved"}` {
		t.Fatalf("invalid decision response: %d %s", w.Code, w.Body.String())
	}
	assertError(t, perform(h, "POST", path, `{"decision":"approved"}`), 400, "invalid_request")
	for _, path := range []string{"/secrets/" + secretID, "/secrets/" + secretID + "/access/" + userID} {
		w := perform(h, "DELETE", path, "")
		if w.Code != 204 || w.Body.Len() != 0 {
			t.Fatalf("invalid delete response: %d %s", w.Code, w.Body.String())
		}
	}
	if decisionCalls != 1 || revokeCalls != 1 || accessCalls != 1 {
		t.Fatalf("unexpected calls: decide%d revoke%d access%d", decisionCalls, revokeCalls, accessCalls)
	}
	assertError(t, perform(h, "GET", "/secrets/invalid-id", ""), 404, "not_found")
}
