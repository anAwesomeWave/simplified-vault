package gateway_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"simple-vault/gateway/internal/auth"
	"simple-vault/gateway/internal/gateway"
	"simple-vault/gateway/internal/ratelimit"
)

// Auth is a local fixture; scripts/smoke.py checks the complete stack with real auth.
func TestIntegrationWithSecrets(t *testing.T) {
	upstream := os.Getenv("TEST_SECRETS_URL")
	if upstream == "" {
		t.Skip("set TEST_SECRETS_URL to test against a running secrets service")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auth.New(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
	if err != nil {
		t.Fatal(err)
	}
	ownerID, readerID := uuid.NewString(), uuid.NewString()
	ownerEmail, readerEmail := ownerID+"@example.test", readerID+"@example.test"
	accounts := map[string]string{ownerEmail: ownerID, readerEmail: readerID}
	authUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var credentials struct{ Email, Password string }
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&credentials) != nil || credentials.Password != "test-password-123" || accounts[credentials.Email] == "" {
			http.Error(w, "unexpected fixture request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/auth/register" {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"user_id": accounts[credentials.Email]})
			return
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"user_id": accounts[credentials.Email], "email": credentials.Email, "iss": "auth", "aud": []string{"secrets"}, "exp": time.Now().Add(15 * time.Minute).Unix(),
		}).SignedString(key)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "expires_in": 900})
	}))
	t.Cleanup(authUpstream.Close)
	authURL, _ := url.Parse(authUpstream.URL)
	secretsURL, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	handler := gateway.New(authURL, secretsURL, verifier, ratelimit.New(5, time.Minute), slog.New(slog.NewTextHandler(io.Discard, nil)))
	front := httptest.NewServer(handler)
	t.Cleanup(func() { front.Close(); handler.CloseIdleConnections() })
	client := &http.Client{Timeout: 20 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	request := func(method, path, token string, body any, status int, out any) {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r, err := http.NewRequest(method, front.URL+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		// All of these must be replaced, including fields named hop-by-hop.
		r.Header.Add("X-User-ID", uuid.NewString())
		r.Header.Add("X-User-ID", uuid.NewString())
		r.Header.Set("X-User-Email", "spoofed@example.test")
		r.Header.Set("X-Real-IP", "198.51.100.99")
		r.Header.Set("X-Forwarded-For", "198.51.100.99")
		r.Header.Set("Connection", "X-User-ID, X-User-Email, X-Real-IP, Authorization")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != status {
			t.Fatalf("%s %s: status=%d want=%d", method, path, response.StatusCode, status)
		}
		if status == 204 && len(data) != 0 {
			t.Fatal("204 response has a body")
		}
		if status >= 400 {
			var failure map[string]string
			if json.Unmarshal(data, &failure) != nil || len(failure) != 2 || failure["error"] == "" || failure["message"] == "" {
				t.Fatal("invalid JSON error contract")
			}
		}
		if out != nil && json.Unmarshal(data, out) != nil {
			t.Fatal("invalid JSON response")
		}
	}
	login := func(email string) string {
		t.Helper()
		credentials := map[string]string{"email": email, "password": "test-password-123"}
		var registered struct {
			ID string `json:"user_id"`
		}
		request("POST", "/auth/register", "", credentials, 201, &registered)
		if registered.ID != accounts[email] {
			t.Fatal("registration response changed")
		}
		var session struct {
			Token     string `json:"access_token"`
			ExpiresIn int    `json:"expires_in"`
		}
		request("POST", "/auth/login", "", credentials, 200, &session)
		if session.ExpiresIn != 900 || session.Token == "" {
			t.Fatal("login response changed")
		}
		return session.Token
	}
	owner, reader := login(ownerEmail), login(readerEmail)
	request("GET", "/secrets", "", nil, 401, nil)
	request("GET", "/secrets", "invalid", nil, 401, nil)
	var created struct {
		ID string `json:"id"`
	}
	text := "gateway-integration-" + uuid.NewString()
	request("POST", "/secrets", owner, map[string]any{"title": "Gateway integration", "text": text, "ttl_seconds": 300}, 201, &created)
	path := "/secrets/" + created.ID
	t.Cleanup(func() { request("DELETE", path, owner, nil, 204, nil) })
	var owned []struct {
		ID string `json:"id"`
	}
	request("GET", "/secrets", owner, nil, 200, &owned)
	if len(owned) != 1 || owned[0].ID != created.ID {
		t.Fatal("JWT identity was not used for ownership")
	}
	var opened struct {
		Text string `json:"text"`
	}
	request("GET", path, owner, nil, 200, &opened)
	if opened.Text != text {
		t.Fatal("secret text changed through gateway")
	}
	request("GET", path, reader, nil, 202, nil)
	var history struct {
		Requests []struct {
			ID    string `json:"id"`
			Email string `json:"requester_email"`
		} `json:"requests"`
		Views []struct {
			Email string `json:"email"`
			IP    string `json:"ip"`
		} `json:"views"`
	}
	request("GET", path+"/requests", owner, nil, 200, &history)
	if len(history.Requests) != 1 || history.Requests[0].Email != readerEmail {
		t.Fatal("requester identity differs from verified JWT")
	}
	if len(history.Views) != 1 || history.Views[0].Email != ownerEmail || history.Views[0].IP == "198.51.100.99" || net.ParseIP(history.Views[0].IP) == nil {
		t.Fatal("spoofed identity or IP reached the real secrets service")
	}
	decision := path + "/requests/" + history.Requests[0].ID
	request("POST", decision, owner, map[string]string{"decision": "approve"}, 200, nil)
	request("POST", decision, owner, map[string]string{"decision": "deny"}, 409, nil)
	request("GET", path, reader, nil, 200, &opened)
	if opened.Text != text {
		t.Fatal("approved reader text differs")
	}
	var shared []struct {
		ID string `json:"id"`
	}
	request("GET", "/secrets/shared", reader, nil, 200, &shared)
	if len(shared) != 1 || shared[0].ID != created.ID {
		t.Fatal("shared list not proxied")
	}
	request("DELETE", path+"/access/"+readerID, owner, nil, 204, nil)
	request("GET", path, reader, nil, 403, nil)
	request("DELETE", path, reader, nil, 403, nil)
}
