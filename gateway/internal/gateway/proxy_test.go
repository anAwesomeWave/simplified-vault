package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"simple-vault/gateway/internal/auth"
	"simple-vault/gateway/internal/ratelimit"
)

const userID = "bf618afa-1bb8-47b6-b92f-9653850ec8db"
const userEmail = "user@example.com"

var signingKeyOnce sync.Once
var signingKey *rsa.PrivateKey
var signingKeyErr error

func verifierAndToken(t *testing.T) (*auth.Verifier, string) {
	t.Helper()
	signingKeyOnce.Do(func() { signingKey, signingKeyErr = rsa.GenerateKey(rand.Reader, 2048) })
	if signingKeyErr != nil {
		t.Fatal(signingKeyErr)
	}
	public, err := x509.MarshalPKIXPublicKey(&signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auth.New(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"user_id": userID, "email": userEmail, "exp": time.Now().Add(15 * time.Minute).Unix(),
	}).SignedString(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, token
}

func target(t *testing.T, address string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func fixture(t *testing.T, authHandler, secretsHandler http.Handler, limit int) (*Handler, string) {
	t.Helper()
	if authHandler == nil {
		authHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	}
	if secretsHandler == nil {
		secretsHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	}
	authServer, secretsServer := httptest.NewServer(authHandler), httptest.NewServer(secretsHandler)
	t.Cleanup(authServer.Close)
	t.Cleanup(secretsServer.Close)
	verifier, token := verifierAndToken(t)
	h := New(target(t, authServer.URL), target(t, secretsServer.URL), verifier, ratelimit.New(limit, time.Minute), slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(h.CloseIdleConnections)
	return h, token
}

func perform(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "198.51.100.9:12345"
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func assertError(t *testing.T, w *httptest.ResponseRecorder, status int, kind string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status=%d want=%d body=%s", w.Code, status, w.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 2 || payload["error"] != kind || payload["message"] == "" {
		t.Fatalf("invalid JSON error: %v", payload)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("response may be cached")
	}
}

func TestProxyPreservesPathQueryBodyAndUpstreamResponse(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, _ := strconv.Atoi(r.URL.Query().Get("status"))
		if r.URL.Query().Get("source") != "client value" {
			t.Error("query was not preserved")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(body) != `{"value":"unchanged"}` {
			t.Errorf("body changed: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Path", r.URL.Path)
		w.Header().Set("X-Upstream-Method", r.Method)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(status)
		if status != 204 {
			_, _ = io.WriteString(w, `{"upstream":"unchanged"}`)
		}
	})
	h, token := fixture(t, upstream, upstream, 100)
	cases := []struct {
		method, path string
		status       int
	}{
		{"POST", "/auth/register", 201}, {"POST", "/auth/login", 200},
		{"POST", "/secrets", 201}, {"GET", "/secrets/id", 202}, {"DELETE", "/secrets/id", 204},
		{"GET", "/secrets/id", 403}, {"POST", "/secrets/id/requests/id", 409},
	}
	for _, tc := range cases {
		t.Run(tc.method+tc.path+strconv.Itoa(tc.status), func(t *testing.T) {
			w := perform(h, tc.method, tc.path+"?source=client+value&status="+strconv.Itoa(tc.status), `{"value":"unchanged"}`, token)
			if w.Code != tc.status || w.Header().Get("X-Upstream-Path") != tc.path || w.Header().Get("X-Upstream-Method") != tc.method {
				t.Fatalf("response changed: %d %v", w.Code, w.Header())
			}
			want := `{"upstream":"unchanged"}`
			if tc.status == 204 {
				want = ""
			}
			if w.Body.String() != want || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("body/cache changed: %s %v", w.Body.String(), w.Header())
			}
		})
	}
}

func TestProxyReplacesSpoofedHeadersAfterHopByHopRemoval(t *testing.T) {
	var secretCalls, authCalls atomic.Int32
	check := func(r *http.Request, secrets bool) {
		for name := range r.Header {
			lower := strings.ToLower(name)
			if lower == "authorization" || lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") {
				t.Errorf("untrusted header forwarded: %s", name)
			}
		}
		if values := r.Header.Values("X-Real-IP"); len(values) != 1 || values[0] != "198.51.100.9" {
			t.Errorf("spoofed client IP: %v", values)
		}
		if secrets {
			if values := r.Header.Values("X-User-ID"); len(values) != 1 || values[0] != userID {
				t.Errorf("spoofed user ID: %v", values)
			}
			if values := r.Header.Values("X-User-Email"); len(values) != 1 || values[0] != userEmail {
				t.Errorf("spoofed email: %v", values)
			}
		} else if len(r.Header.Values("X-User-ID")) != 0 || len(r.Header.Values("X-User-Email")) != 0 {
			t.Error("public auth received client identity")
		}
	}
	h, token := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { authCalls.Add(1); check(r, false); w.WriteHeader(200) }), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { secretCalls.Add(1); check(r, true); w.WriteHeader(200) }), 100)
	for _, path := range []string{"/secrets/id", "/auth/register"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		r.RemoteAddr = "198.51.100.9:12345"
		r.Header.Set("Authorization", "Bearer "+token)
		for _, name := range []string{"X-User-ID", "X-User-Email", "X-Real-IP"} {
			r.Header.Add(name, "spoofed-one")
			r.Header.Add(name, "spoofed-two")
		}
		for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port"} {
			r.Header.Set(name, "spoofed")
		}
		r.Header.Set("Connection", "keep-alive, X-User-ID, X-User-Email, X-Real-IP, Authorization")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("valid request failed: %d %s", w.Code, w.Body.String())
		}
	}
	if secretCalls.Load() != 1 || authCalls.Load() != 1 {
		t.Fatal("request sent to wrong upstream")
	}
}

func TestSecretsRejectMissingMalformedOrDuplicateAuthorization(t *testing.T) {
	var calls atomic.Int32
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) })
	h, token := fixture(t, upstream, upstream, 100)
	for _, values := range [][]string{nil, {"Basic invalid"}, {"Bearer invalid"}, {"Bearer " + token, "Bearer " + token}} {
		r := httptest.NewRequest("GET", "/secrets/id", nil)
		r.Header["Authorization"] = values
		r.Header.Set("X-User-ID", userID)
		r.Header.Set("X-User-Email", userEmail)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assertError(t, w, 401, "unauthorized")
		if w.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatal("missing bearer challenge")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized request reached upstream")
	}
}

func TestRoutesAndMethodsAreRestricted(t *testing.T) {
	var calls atomic.Int32
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) })
	h, _ := fixture(t, upstream, upstream, 100)
	for _, path := range []string{"/", "/auth/anything", "/auth/login/", "/secretsevil", "/health/ready"} {
		assertError(t, perform(h, "POST", path, `{}`, ""), 404, "not_found")
	}
	for _, path := range []string{"/auth/register", "/auth/login"} {
		w := perform(h, "GET", path, "", "")
		assertError(t, w, 405, "method_not_allowed")
		if w.Header().Get("Allow") != "POST" {
			t.Fatal("incorrect Allow header")
		}
	}
	if w := perform(h, "GET", "/health/live", "", ""); w.Code != 200 {
		t.Fatal("live probe failed")
	}
	if calls.Load() != 0 {
		t.Fatal("unknown route reached upstream")
	}
}

func TestLoginLimitUsesPeerIPAndCannotBeBypassedWithForwardedHeaders(t *testing.T) {
	var calls atomic.Int32
	h, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }), nil, 1)
	if w := perform(h, "POST", "/auth/login", `{}`, ""); w.Code != 200 {
		t.Fatal("first login rejected")
	}
	for _, fakeIP := range []string{"203.0.113.1", "203.0.113.2"} {
		r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{}`))
		r.RemoteAddr = "198.51.100.9:54321"
		r.Header.Set("X-Forwarded-For", fakeIP)
		r.Header.Set("X-Real-IP", fakeIP)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assertError(t, w, 429, "rate_limited")
		if seconds, err := strconv.Atoi(w.Header().Get("Retry-After")); err != nil || seconds < 1 {
			t.Fatal("invalid Retry-After")
		}
	}
	r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{}`))
	r.RemoteAddr = "198.51.100.10:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("another peer incorrectly rate limited")
	}
	if w := perform(h, "POST", "/auth/register", `{}`, ""); w.Code != 200 {
		t.Fatal("registration incorrectly rate limited")
	}
	if calls.Load() != 3 {
		t.Fatalf("rate limited requests reached upstream: %d", calls.Load())
	}
}

func TestUpstreamErrorsAreJSONAndDoNotLeakCredentials(t *testing.T) {
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	verifier, _ := verifierAndToken(t)
	var logs bytes.Buffer
	h := New(target(t, closed.URL), target(t, closed.URL), verifier, ratelimit.New(100, time.Minute), slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(h.CloseIdleConnections)
	w := perform(h, "POST", "/auth/register?secret=sensitive-query", `{"password":"sensitive-password"}`, "")
	assertError(t, w, 502, "upstream_unavailable")
	if strings.Contains(logs.String(), "sensitive-") {
		t.Fatal("credentials leaked to logs")
	}
}

func TestProxyTimeoutCancelsUpstream(t *testing.T) {
	canceled := make(chan struct{})
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
		close(canceled)
	})
	h, _ := fixture(t, upstream, nil, 100)
	h.requestTimeout = 30 * time.Millisecond
	w := perform(h, "POST", "/auth/register", `{}`, "")
	assertError(t, w, 504, "upstream_timeout")
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("gateway timeout did not cancel upstream request")
	}
}

func TestClientCancellationCancelsUpstream(t *testing.T) {
	entered, canceled := make(chan struct{}), make(chan struct{})
	h, _ := fixture(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
		close(canceled)
	}), nil, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("POST", "/auth/register", strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(w, r) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not reach upstream")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("client cancellation did not cancel upstream")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("gateway handler did not return")
	}
}
