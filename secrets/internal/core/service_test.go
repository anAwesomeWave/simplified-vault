package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"simple-vault/secrets/internal/domain"
	"simple-vault/secrets/internal/secure"
)

func TestCreateRejectsInvalidInputBeforeStorage(t *testing.T) {
	service := New(nil, nil, nil, "https://vault.example")
	for _, input := range []domain.CreateInput{
		{Title: "", Text: "secret"},
		{Title: "   ", Text: "secret"},
		{Title: "title", Text: ""},
		{Title: "title", Text: strings.Repeat("x", 10241)},
		{Title: "title", Text: "secret", TTLSeconds: seconds(299)},
		{Title: "title", Text: "secret", TTLSeconds: seconds(604801)},
		{Title: "title", Text: "secret", TTLSeconds: seconds(0)},
	} {
		if _, err := service.Create(context.Background(), domain.User{}, input); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("expected invalid input, got %v", err)
		}
	}
	if _, err := service.Decide(context.Background(), domain.User{}, "", "", "maybe"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("invalid decision: %v", err)
	}
}

func seconds(value int64) *int64 { return &value }

// Integration tests use a new schema on every invocation, including when pointed
// at a developer's database. They never truncate the service's own tables.
func integrationService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run isolated PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "secrets_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("drop isolated test schema: %v", err)
		}
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 20
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err = Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, db); err != nil {
		t.Fatalf("migration is not idempotent: %v", err)
	}
	encryption, err := secure.New(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var cache *redis.Client
	if addr := os.Getenv("TEST_REDIS_ADDR"); addr != "" {
		cache = redis.NewClient(&redis.Options{Addr: addr})
		if err = cache.Ping(ctx).Err(); err != nil {
			cache.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cache.Close() })
	}
	return New(db, cache, encryption, "https://vault.example"), ctx
}

func testUser(name string) domain.User {
	return domain.User{ID: uuid.NewString(), Email: name + "@example.com"}
}

func createTestSecret(t *testing.T, s *Service, ctx context.Context, owner domain.User) domain.Created {
	t.Helper()
	result, err := s.Create(ctx, owner, domain.CreateInput{Title: "Access token", Text: "sensitive-plaintext-that-must-not-leak"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Link != "https://vault.example/secrets/"+result.ID {
		t.Fatalf("wrong link: %q", result.Link)
	}
	if delta := time.Until(result.ExpiresAt); delta < 23*time.Hour+59*time.Minute || delta > 24*time.Hour {
		t.Fatalf("wrong default TTL: %s", delta)
	}
	if s.cache != nil {
		t.Cleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = s.cache.Del(cleanupCtx, "secret:"+result.ID).Err()
		})
	}
	return result
}

func requestAndApprove(t *testing.T, s *Service, ctx context.Context, owner, user domain.User, id string) {
	t.Helper()
	if opened, err := s.Open(ctx, user, id, "192.0.2.10"); err != nil || opened != nil {
		t.Fatalf("request access: %#v %v", opened, err)
	}
	var requestID string
	if err := s.db.QueryRow(ctx, `SELECT id::text FROM access_requests WHERE secret_id=$1 AND requester_id=$2`, id, user.ID).Scan(&requestID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(ctx, owner, id, requestID, "approve"); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationWorkflowDeduplicatesRequestsAndRevokesCachedAccess(t *testing.T) {
	s, ctx := integrationService(t)
	owner, reader, outsider := testUser("owner"), testUser("reader"), testUser("outsider")
	created := createTestSecret(t, s, ctx, owner)
	var ciphertext []byte
	if err := s.db.QueryRow(ctx, `SELECT ciphertext FROM secrets WHERE id=$1`, created.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("sensitive-plaintext")) {
		t.Fatal("plaintext in PostgreSQL")
	}
	var wg sync.WaitGroup
	failures := make(chan error, 32)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			opened, err := s.Open(ctx, reader, created.ID, "192.0.2.10")
			if err != nil {
				failures <- err
			}
			if opened != nil {
				failures <- errors.New("unapproved reader obtained secret")
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	var requests, events int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM access_requests WHERE secret_id=$1`, created.ID).Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE type='access.requested'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || events != 1 {
		t.Fatalf("duplicate requests/events: %d/%d", requests, events)
	}
	owned, err := s.ListOwned(ctx, owner)
	if err != nil || len(owned) != 1 || owned[0].PendingRequests != 1 {
		t.Fatalf("owned list: %#v %v", owned, err)
	}
	if _, err = s.History(ctx, reader, created.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("history visible to non-owner: %v", err)
	}
	history, err := s.History(ctx, owner, created.ID)
	if err != nil || len(history.Requests) != 1 || len(history.Views) != 0 {
		t.Fatalf("initial history: %#v %v", history, err)
	}
	requestID := history.Requests[0].ID
	if _, err = s.Decide(ctx, outsider, created.ID, requestID, "approve"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("outsider decided request: %v", err)
	}
	decision, err := s.Decide(ctx, owner, created.ID, requestID, "approve")
	if err != nil || decision.Status != "approved" {
		t.Fatalf("approve: %#v %v", decision, err)
	}
	if _, err = s.Decide(ctx, owner, created.ID, requestID, "deny"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("decision repeated: %v", err)
	}
	for i := 0; i < 2; i++ {
		opened, err := s.Open(ctx, reader, created.ID, "192.0.2.10")
		if err != nil || opened == nil || opened.Text != "sensitive-plaintext-that-must-not-leak" {
			t.Fatalf("approved open: %#v %v", opened, err)
		}
	}
	if _, err = s.Open(ctx, owner, created.ID, "192.0.2.11"); err != nil {
		t.Fatal(err)
	}
	shared, err := s.ListShared(ctx, reader)
	if err != nil || len(shared) != 1 || shared[0].OwnerEmail != owner.Email {
		t.Fatalf("shared: %#v %v", shared, err)
	}
	history, err = s.History(ctx, owner, created.ID)
	if err != nil || len(history.Views) != 3 {
		t.Fatalf("every open audited: %#v %v", history, err)
	}
	var stale []byte
	if s.cache != nil {
		stale, err = s.cache.Get(ctx, "secret:"+created.ID).Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(stale, []byte("sensitive-plaintext")) {
			t.Fatal("plaintext in Redis")
		}
		ttl, err := s.cache.PTTL(ctx, "secret:"+created.ID).Result()
		if err != nil || ttl <= 0 || ttl > 5*time.Minute {
			t.Fatalf("cache TTL: %s %v", ttl, err)
		}
	}
	if err = s.RevokeAccess(ctx, outsider, created.ID, reader.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("outsider revoked access: %v", err)
	}
	if err = s.RevokeAccess(ctx, owner, created.ID, reader.ID); err != nil {
		t.Fatal(err)
	}
	if s.cache != nil {
		if count, err := s.cache.Exists(ctx, "secret:"+created.ID).Result(); err != nil || count != 0 {
			t.Fatalf("cache not invalidated: %d %v", count, err)
		}
		if err = s.cache.Set(ctx, "secret:"+created.ID, stale, time.Minute).Err(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.Open(ctx, reader, created.ID, "192.0.2.10"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("revoked access accepted with stale cache: %v", err)
	}
	shared, err = s.ListShared(ctx, reader)
	if err != nil || len(shared) != 0 {
		t.Fatalf("revoked reader in shared list: %#v %v", shared, err)
	}
	if err = s.RevokeAccess(ctx, owner, created.ID, reader.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("revoked access still exists: %v", err)
	}
	if err = s.db.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE type='secret.viewed'`).Scan(&events); err != nil || events != 3 {
		t.Fatalf("view events: %d %v", events, err)
	}
	var leaked bool
	if err = s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM outbox WHERE payload::text LIKE '%sensitive-plaintext%')`).Scan(&leaked); err != nil || leaked {
		t.Fatalf("plaintext in events: %v %v", leaked, err)
	}
}

func TestIntegrationDenialWholeRevokeAndCascade(t *testing.T) {
	s, ctx := integrationService(t)
	owner, approved, denied, pending := testUser("owner"), testUser("approved"), testUser("denied"), testUser("pending")
	created := createTestSecret(t, s, ctx, owner)
	requestAndApprove(t, s, ctx, owner, approved, created.ID)
	for _, user := range []domain.User{denied, pending} {
		if _, err := s.Open(ctx, user, created.ID, "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	var deniedID string
	if err := s.db.QueryRow(ctx, `SELECT id::text FROM access_requests WHERE secret_id=$1 AND requester_id=$2`, created.ID, denied.ID).Scan(&deniedID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(ctx, owner, created.ID, deniedID, "deny"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.Open(ctx, denied, created.ID, "192.0.2.1"); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("denied user requested again: %v", err)
		}
	}
	if _, err := s.Open(ctx, approved, created.ID, "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, pending, created.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("non-owner revoked secret: %v", err)
	}
	if err := s.Revoke(ctx, owner, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, owner, created.ID, "192.0.2.1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted secret opened: %v", err)
	}
	var requests, views int
	if err := s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM access_requests),(SELECT count(*) FROM secret_views)`).Scan(&requests, &views); err != nil {
		t.Fatal(err)
	}
	if requests != 0 || views != 0 {
		t.Fatalf("cascade left %d requests and %d views", requests, views)
	}
	var payload []byte
	if err := s.db.QueryRow(ctx, `SELECT payload FROM outbox WHERE type='access.revoked'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var revoke struct {
		UserEmails []string `json:"user_emails"`
	}
	if err := json.Unmarshal(payload, &revoke); err != nil {
		t.Fatal(err)
	}
	if len(revoke.UserEmails) != 1 || revoke.UserEmails[0] != approved.Email {
		t.Fatalf("revoke notified unapproved users: %s", payload)
	}
}

func TestIntegrationExpiryAndCleanup(t *testing.T) {
	s, ctx := integrationService(t)
	owner, reader := testUser("owner"), testUser("reader")
	created := createTestSecret(t, s, ctx, owner)
	requestAndApprove(t, s, ctx, owner, reader, created.ID)
	if _, err := s.Open(ctx, reader, created.ID, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `UPDATE secrets SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, created.ID); err != nil {
		t.Fatal(err)
	}
	for _, user := range []domain.User{owner, reader} {
		if _, err := s.Open(ctx, user, created.ID, "192.0.2.1"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expired secret opened: %v", err)
		}
	}
	owned, err := s.ListOwned(ctx, owner)
	if err != nil || len(owned) != 0 {
		t.Fatalf("expired owned secret listed: %#v %v", owned, err)
	}
	shared, err := s.ListShared(ctx, reader)
	if err != nil || len(shared) != 0 {
		t.Fatalf("expired shared secret listed: %#v %v", shared, err)
	}
	var before, after int
	if err = s.db.QueryRow(ctx, `SELECT count(*) FROM outbox`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = s.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	var secrets, requests, views int
	if err = s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM secrets),(SELECT count(*) FROM access_requests),(SELECT count(*) FROM secret_views),(SELECT count(*) FROM outbox)`).Scan(&secrets, &requests, &views, &after); err != nil {
		t.Fatal(err)
	}
	if secrets != 0 || requests != 0 || views != 0 || before != after {
		t.Fatalf("cleanup: secrets=%d requests=%d views=%d events=%d->%d", secrets, requests, views, before, after)
	}
}

func TestIntegrationOutboxFailureRollsBackCreation(t *testing.T) {
	s, ctx := integrationService(t)
	if _, err := s.db.Exec(ctx, `ALTER TABLE outbox ADD CONSTRAINT reject_created CHECK(type<>'secret.created') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, testUser("owner"), domain.CreateInput{Title: "title", Text: "secret"}); err == nil {
		t.Fatal("create succeeded after outbox insert failed")
	}
	var count int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM secrets`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("secret persisted without its event")
	}
}

func TestIntegrationConcurrentDecisionsHaveOneWinner(t *testing.T) {
	s, ctx := integrationService(t)
	owner, reader := testUser("owner"), testUser("reader")
	created := createTestSecret(t, s, ctx, owner)
	if _, err := s.Open(ctx, reader, created.ID, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	history, err := s.History(ctx, owner, created.ID)
	if err != nil || len(history.Requests) != 1 {
		t.Fatalf("request history: %#v %v", history, err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, decision := range []string{"approve", "deny"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Decide(ctx, owner, created.ID, history.Requests[0].ID, decision)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	var wins, conflicts int
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, domain.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("concurrent decisions: %d wins, %d conflicts", wins, conflicts)
	}
	var events int
	if err = s.db.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE type='access.decided'`).Scan(&events); err != nil || events != 1 {
		t.Fatalf("decision events: %d %v", events, err)
	}
}
