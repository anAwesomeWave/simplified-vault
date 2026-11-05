package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"simple-vault/secrets/internal/core"
	"simple-vault/secrets/internal/domain"
)

type deployedService struct {
	t      *testing.T
	ctx    context.Context
	base   string
	client *http.Client
	db     *pgxpool.Pool
	cache  *redis.Client
	owner  domain.User
	ids    []string
}

func newDeployedService(t *testing.T) *deployedService {
	t.Helper()
	base, dsn, addr := os.Getenv("TEST_HTTP_URL"), os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_REDIS_ADDR")
	if base == "" || dsn == "" || addr == "" {
		t.Skip("set TEST_HTTP_URL, TEST_DATABASE_URL and TEST_REDIS_ADDR for deployed-service integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	s := &deployedService{t: t, ctx: ctx, base: strings.TrimRight(base, "/"), client: &http.Client{Timeout: 10 * time.Second}, db: db, cache: redis.NewClient(&redis.Options{Addr: addr, ContextTimeoutEnabled: true}), owner: newUser()}
	t.Cleanup(func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		for _, id := range s.ids {
			_, _, _ = s.request("DELETE", "/secrets/"+id, &s.owner, nil)
			_ = s.cache.Del(cleanupCtx, "secret:"+id).Err()
		}
		if len(s.ids) > 0 {
			if _, err := db.Exec(cleanupCtx, `DELETE FROM secrets WHERE id=ANY($1::uuid[]) AND owner_id=$2`, s.ids, s.owner.ID); err != nil {
				t.Errorf("clean up test secrets: %v", err)
			}
		}
		_ = s.cache.Close()
		db.Close()
		s.client.CloseIdleConnections()
	})
	return s
}

func newUser() domain.User {
	return domain.User{ID: uuid.NewString(), Email: uuid.NewString() + "@example.test"}
}

func (s *deployedService) request(method, path string, user *domain.User, body any) (int, []byte, error) {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
	}
	req, err := http.NewRequestWithContext(s.ctx, method, s.base+path, bytes.NewReader(data))
	if err != nil {
		return 0, nil, err
	}
	if user != nil {
		req.Header.Set("X-User-ID", user.ID)
		req.Header.Set("X-User-Email", user.Email)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "198.51.100.9")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}

func (s *deployedService) call(method, path string, user *domain.User, body any, status int, out any) {
	s.t.Helper()
	got, data, err := s.request(method, path, user, body)
	if err != nil || got != status {
		s.t.Fatalf("%s %s: status=%d want=%d err=%v response=%.300s", method, path, got, status, err, data)
	}
	if status >= 400 {
		var failure struct{ Error, Message string }
		if err = json.Unmarshal(data, &failure); err != nil || failure.Error == "" || failure.Message == "" {
			s.t.Fatalf("invalid error contract: %.300s", data)
		}
	}
	if out != nil {
		if err = json.Unmarshal(data, out); err != nil {
			s.t.Fatalf("decode response: %v", err)
		}
	}
}

func (s *deployedService) create(text string, ttl *int64) domain.Created {
	s.t.Helper()
	var result domain.Created
	s.call("POST", "/secrets", &s.owner, domain.CreateInput{Title: "Integration token", Text: text, TTLSeconds: ttl}, 201, &result)
	s.ids = append(s.ids, result.ID)
	if _, err := uuid.Parse(result.ID); err != nil || !strings.HasSuffix(result.Link, "/secrets/"+result.ID) {
		s.t.Fatalf("invalid create response: %#v", result)
	}
	return result
}

func TestDeployedServiceWorkflow(t *testing.T) {
	s := newDeployedService(t)
	reader, denied := newUser(), newUser()
	s.call("GET", "/secrets", nil, nil, 401, nil)
	s.call("GET", "/secrets", &domain.User{ID: "invalid", Email: "invalid"}, nil, 401, nil)
	s.call("GET", "/unknown", nil, nil, 404, nil)
	s.call("GET", "/secrets/"+uuid.NewString(), &s.owner, nil, 404, nil)
	for _, ttl := range []int64{0, 299, 604801} {
		s.call("POST", "/secrets", &s.owner, domain.CreateInput{Title: "Bad TTL", Text: "secret", TTLSeconds: &ttl}, 400, nil)
	}
	s.call("POST", "/secrets", &s.owner, domain.CreateInput{Title: "Oversized", Text: strings.Repeat("x", 10241)}, 400, nil)
	boundary := s.create(strings.Repeat("x", 10240), nil)
	s.call("DELETE", "/secrets/"+boundary.ID, &s.owner, nil, 204, nil)
	text := "private-integration-token-" + uuid.NewString()
	created := s.create(text, nil)
	if ttl := time.Until(created.ExpiresAt); ttl < 23*time.Hour+59*time.Minute || ttl > 24*time.Hour {
		t.Fatalf("default TTL: %v", ttl)
	}
	path := "/secrets/" + created.ID
	var owned []domain.Owned
	s.call("GET", "/secrets", &s.owner, nil, 200, &owned)
	if len(owned) != 1 || owned[0].ID != created.ID || owned[0].PendingRequests != 0 {
		t.Fatalf("owned: %#v", owned)
	}
	var shared []domain.Shared
	s.call("GET", "/secrets/shared", &reader, nil, 200, &shared)
	if len(shared) != 0 {
		t.Fatal("unapproved shared secret")
	}
	var opened domain.Opened
	s.call("GET", path, &s.owner, nil, 200, &opened)
	if opened.Text != text {
		t.Fatal("owner text mismatch")
	}
	var wg sync.WaitGroup
	errors := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, body, err := s.request("GET", path, &reader, nil)
			if err != nil || status != 202 || !bytes.Contains(body, []byte(`"pending"`)) {
				errors <- fmt.Errorf("concurrent request: status=%d err=%v body=%s", status, err, body)
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	var count int
	if err := s.db.QueryRow(s.ctx, `SELECT count(*) FROM access_requests WHERE secret_id=$1 AND requester_id=$2`, created.ID, reader.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("requests=%d err=%v", count, err)
	}
	s.call("GET", path+"/requests", &reader, nil, 403, nil)
	var history domain.History
	s.call("GET", path+"/requests", &s.owner, nil, 200, &history)
	if len(history.Requests) != 1 || len(history.Views) != 1 || history.Views[0].IP != "198.51.100.9" || history.Views[0].Email != s.owner.Email {
		t.Fatalf("history: %#v", history)
	}
	decisionPath := path + "/requests/" + history.Requests[0].ID
	decision := map[string]string{"decision": "approve"}
	s.call("POST", decisionPath, &reader, decision, 403, nil)
	other := s.create("other secret", nil)
	s.call("POST", "/secrets/"+other.ID+"/requests/"+history.Requests[0].ID, &s.owner, decision, 404, nil)
	s.call("DELETE", "/secrets/"+other.ID, &s.owner, nil, 204, nil)
	var decided domain.Decision
	s.call("POST", decisionPath, &s.owner, decision, 200, &decided)
	if decided.Status != "approved" {
		t.Fatalf("decision: %#v", decided)
	}
	s.call("POST", decisionPath, &s.owner, decision, 409, nil)
	s.call("GET", path, &reader, nil, 200, &opened)
	if opened.Text != text {
		t.Fatal("reader text mismatch")
	}
	s.call("GET", "/secrets/shared", &reader, nil, 200, &shared)
	if len(shared) != 1 || shared[0].OwnerEmail != s.owner.Email {
		t.Fatalf("shared: %#v", shared)
	}
	stale, err := s.cache.Get(s.ctx, "secret:"+created.ID).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if ttl, err := s.cache.PTTL(s.ctx, "secret:"+created.ID).Result(); err != nil || ttl <= 0 || ttl > 5*time.Minute {
		t.Fatalf("cache TTL: %v %v", ttl, err)
	}
	var cached map[string]json.RawMessage
	if err = json.Unmarshal(stale, &cached); err != nil || len(cached) != 2 || cached["ciphertext"] == nil || cached["nonce"] == nil || bytes.Contains(stale, []byte(text)) {
		t.Fatalf("unsafe cache payload: %v", err)
	}
	var encrypted struct{ Ciphertext, Nonce []byte }
	if err = json.Unmarshal(stale, &encrypted); err != nil || len(encrypted.Nonce) != 12 || bytes.Contains(encrypted.Ciphertext, []byte(text)) {
		t.Fatal("unsafe cached encryption")
	}
	var ciphertext, nonce []byte
	if err = s.db.QueryRow(s.ctx, `SELECT ciphertext,nonce FROM secrets WHERE id=$1`, created.ID).Scan(&ciphertext, &nonce); err != nil || len(nonce) != 12 || bytes.Contains(ciphertext, []byte(text)) {
		t.Fatalf("unsafe stored encryption: %v", err)
	}
	s.call("DELETE", path+"/access/"+reader.ID, &reader, nil, 403, nil)
	s.call("DELETE", path+"/access/"+reader.ID, &s.owner, nil, 204, nil)
	if n, err := s.cache.Exists(s.ctx, "secret:"+created.ID).Result(); err != nil || n != 0 {
		t.Fatalf("cache not invalidated: %d %v", n, err)
	}
	if err = s.cache.Set(s.ctx, "secret:"+created.ID, stale, time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	s.call("GET", path, &reader, nil, 403, nil)
	s.call("GET", "/secrets/shared", &reader, nil, 200, &shared)
	if len(shared) != 0 {
		t.Fatal("revoked secret remains shared")
	}
	s.call("DELETE", path+"/access/"+reader.ID, &s.owner, nil, 404, nil)
	s.call("GET", path, &denied, nil, 202, nil)
	s.call("GET", path+"/requests", &s.owner, nil, 200, &history)
	for _, request := range history.Requests {
		if request.RequesterEmail == denied.Email {
			s.call("POST", path+"/requests/"+request.ID, &s.owner, map[string]string{"decision": "deny"}, 200, nil)
		}
	}
	s.call("GET", path, &denied, nil, 403, nil)
	s.call("GET", path, &denied, nil, 403, nil)
	s.call("DELETE", path, &reader, nil, 403, nil)
	s.call("DELETE", path, &s.owner, nil, 204, nil)
	s.call("GET", path, &s.owner, nil, 404, nil)
	if err = s.db.QueryRow(s.ctx, `SELECT (SELECT count(*) FROM access_requests WHERE secret_id=$1)+(SELECT count(*) FROM secret_views WHERE secret_id=$1)`, created.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cascade count=%d err=%v", count, err)
	}
	if n, err := s.cache.Exists(s.ctx, "secret:"+created.ID).Result(); err != nil || n != 0 {
		t.Fatalf("deleted cache remains: %d %v", n, err)
	}
}

func TestDeployedServiceExpiry(t *testing.T) {
	s := newDeployedService(t)
	reader := newUser()
	created := s.create("expiring token", nil)
	path := "/secrets/" + created.ID
	s.call("GET", path, &reader, nil, 202, nil)
	var history domain.History
	s.call("GET", path+"/requests", &s.owner, nil, 200, &history)
	if len(history.Requests) != 1 {
		t.Fatalf("expiry access request missing: %#v", history.Requests)
	}
	s.call("POST", path+"/requests/"+history.Requests[0].ID, &s.owner, map[string]string{"decision": "approve"}, 200, nil)
	s.call("GET", path, &reader, nil, 200, nil)
	if n, err := s.cache.Exists(s.ctx, "secret:"+created.ID).Result(); err != nil || n != 1 {
		t.Fatalf("cache miss before expiry: %d %v", n, err)
	}
	if _, err := s.db.Exec(s.ctx, `UPDATE secrets SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1 AND owner_id=$2`, created.ID, s.owner.ID); err != nil {
		t.Fatal(err)
	}
	s.call("GET", path, &s.owner, nil, 404, nil)
	s.call("GET", path, &reader, nil, 404, nil)
	var owned []domain.Owned
	var shared []domain.Shared
	s.call("GET", "/secrets", &s.owner, nil, 200, &owned)
	s.call("GET", "/secrets/shared", &reader, nil, 200, &shared)
	if len(owned) != 0 || len(shared) != 0 {
		t.Fatal("expired secret listed")
	}
	var count int
	if err := s.db.QueryRow(s.ctx, `SELECT count(*) FROM secrets WHERE expires_at<=clock_timestamp() AND id<>$1`, created.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cleanup test requires no unrelated expired secrets: count=%d err=%v", count, err)
	}
	if err := core.New(s.db, s.cache, nil, s.base).Cleanup(s.ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(s.ctx, `SELECT (SELECT count(*) FROM secrets WHERE id=$1)+(SELECT count(*) FROM access_requests WHERE secret_id=$1)+(SELECT count(*) FROM secret_views WHERE secret_id=$1)`, created.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expired cascade count=%d err=%v", count, err)
	}
}
