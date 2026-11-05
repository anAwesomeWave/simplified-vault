package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"simple-vault/secrets/internal/domain"
	"simple-vault/secrets/internal/secure"
)

type Service struct {
	db      *pgxpool.Pool
	cache   *redis.Client
	cipher  *secure.Cipher
	baseURL string
}

var _ domain.Service = (*Service)(nil)

func New(db *pgxpool.Pool, cache *redis.Client, encryption *secure.Cipher, baseURL string) *Service {
	return &Service{db: db, cache: cache, cipher: encryption, baseURL: strings.TrimRight(baseURL, "/")}
}

type secret struct {
	ID         string
	OwnerID    string
	OwnerEmail string
	Title      string
	ExpiresAt  time.Time
}

// Every access-changing operation locks the secret row before checking access.
// The cache is never an authority for existence, expiry or approval.
func lockSecret(ctx context.Context, tx pgx.Tx, id string) (secret, error) {
	var item secret
	err := tx.QueryRow(ctx, `SELECT id::text,owner_id::text,owner_email,title,expires_at
		FROM secrets WHERE id=$1 AND expires_at>clock_timestamp() FOR UPDATE`, id).
		Scan(&item.ID, &item.OwnerID, &item.OwnerEmail, &item.Title, &item.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return item, domain.ErrNotFound
	}
	if err != nil {
		return item, err
	}
	if !item.ExpiresAt.After(time.Now()) {
		return item, domain.ErrNotFound
	}
	return item, nil
}

func event(ctx context.Context, tx pgx.Tx, kind string, fields map[string]any) error {
	id := uuid.NewString()
	fields["event_id"], fields["type"], fields["occurred_at"] = id, kind, time.Now().UTC()
	payload, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO outbox(event_id,type,payload) VALUES($1,$2,$3)`, id, kind, payload)
	return err
}

func (s *Service) Create(ctx context.Context, user domain.User, input domain.CreateInput) (domain.Created, error) {
	var result domain.Created
	if strings.TrimSpace(input.Title) == "" || len(input.Text) == 0 || len(input.Text) > 10*1024 {
		return result, fmt.Errorf("%w: title and text are required; text must be at most 10240 bytes", domain.ErrInvalid)
	}
	ttl := int64(86400)
	if input.TTLSeconds != nil {
		ttl = *input.TTLSeconds
	}
	if ttl < 300 || ttl > 604800 {
		return result, fmt.Errorf("%w: ttl_seconds must be between 300 and 604800", domain.ErrInvalid)
	}
	id := uuid.NewString()
	ciphertext, nonce, err := s.cipher.Encrypt(id, input.Text)
	if err != nil {
		return result, err
	}
	created := time.Now().UTC()
	expires := created.Add(time.Duration(ttl) * time.Second)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, `INSERT INTO secrets(id,owner_id,owner_email,title,ciphertext,nonce,expires_at,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, user.ID, user.Email, input.Title, ciphertext, nonce, expires, created); err != nil {
		return result, err
	}
	if err = event(ctx, tx, "secret.created", map[string]any{"secret_id": id, "owner_id": user.ID, "expires_at": expires}); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return domain.Created{ID: id, Link: s.baseURL + "/secrets/" + id, ExpiresAt: expires}, nil
}

func (s *Service) ListOwned(ctx context.Context, user domain.User) ([]domain.Owned, error) {
	result := make([]domain.Owned, 0)
	rows, err := s.db.Query(ctx, `SELECT s.id::text,s.title,s.expires_at,
		(SELECT count(*) FROM access_requests r WHERE r.secret_id=s.id AND r.status='pending')
		FROM secrets s WHERE s.owner_id=$1 AND s.expires_at>clock_timestamp() ORDER BY s.created_at DESC,s.id`, user.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item domain.Owned
		if err = rows.Scan(&item.ID, &item.Title, &item.ExpiresAt, &item.PendingRequests); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) ListShared(ctx context.Context, user domain.User) ([]domain.Shared, error) {
	result := make([]domain.Shared, 0)
	rows, err := s.db.Query(ctx, `SELECT s.id::text,s.title,s.owner_email,s.expires_at FROM secrets s
		JOIN access_requests r ON r.secret_id=s.id WHERE r.requester_id=$1 AND r.status='approved'
		AND s.expires_at>clock_timestamp() ORDER BY s.created_at DESC,s.id`, user.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item domain.Shared
		if err = rows.Scan(&item.ID, &item.Title, &item.OwnerEmail, &item.ExpiresAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) Open(ctx context.Context, user domain.User, id, ip string) (*domain.Opened, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	item, err := lockSecret(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if item.OwnerID != user.ID {
		var status string
		err = tx.QueryRow(ctx, `SELECT status FROM access_requests WHERE secret_id=$1 AND requester_id=$2`, id, user.ID).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) {
			requestID := uuid.NewString()
			if _, err = tx.Exec(ctx, `INSERT INTO access_requests(id,secret_id,requester_id,requester_email) VALUES($1,$2,$3,$4)`, requestID, id, user.ID, user.Email); err != nil {
				return nil, err
			}
			if err = event(ctx, tx, "access.requested", map[string]any{"secret_id": id, "title": item.Title, "request_id": requestID, "requester_email": user.Email, "owner_email": item.OwnerEmail}); err != nil {
				return nil, err
			}
			return nil, tx.Commit(ctx)
		}
		if err != nil {
			return nil, err
		}
		if status == "pending" {
			return nil, tx.Commit(ctx)
		}
		if status != "approved" {
			return nil, domain.ErrForbidden
		}
	}
	text, err := s.readText(ctx, tx, &item)
	if err != nil {
		return nil, err
	}
	viewed := time.Now().UTC()
	if !item.ExpiresAt.After(viewed) {
		return nil, domain.ErrNotFound
	}
	if _, err = tx.Exec(ctx, `INSERT INTO secret_views(secret_id,user_id,user_email,ip,viewed_at) VALUES($1,$2,$3,$4,$5)`, id, user.ID, user.Email, ip, viewed); err != nil {
		return nil, err
	}
	if err = event(ctx, tx, "secret.viewed", map[string]any{"secret_id": id, "title": item.Title, "viewer_email": user.Email, "owner_email": item.OwnerEmail, "ip": ip}); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &domain.Opened{ID: id, Title: item.Title, Text: text, ExpiresAt: item.ExpiresAt}, nil
}

func (s *Service) History(ctx context.Context, user domain.User, id string) (domain.History, error) {
	result := domain.History{Requests: make([]domain.Request, 0), Views: make([]domain.View, 0)}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(tx)
	item, err := lockSecret(ctx, tx, id)
	if err != nil {
		return result, err
	}
	if item.OwnerID != user.ID {
		return result, domain.ErrForbidden
	}
	rows, err := tx.Query(ctx, `SELECT id::text,requester_email,status,created_at FROM access_requests WHERE secret_id=$1 ORDER BY created_at,id`, id)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var request domain.Request
		if err = rows.Scan(&request.ID, &request.RequesterEmail, &request.Status, &request.CreatedAt); err != nil {
			rows.Close()
			return result, err
		}
		result.Requests = append(result.Requests, request)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return result, err
	}
	rows, err = tx.Query(ctx, `SELECT user_email,ip,viewed_at FROM secret_views WHERE secret_id=$1 ORDER BY viewed_at,id`, id)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var view domain.View
		if err = rows.Scan(&view.Email, &view.IP, &view.ViewedAt); err != nil {
			rows.Close()
			return result, err
		}
		result.Views = append(result.Views, view)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func (s *Service) Decide(ctx context.Context, user domain.User, id, requestID, decision string) (domain.Decision, error) {
	var result domain.Decision
	status := "approved"
	if decision == "deny" {
		status = "denied"
	} else if decision != "approve" {
		return result, fmt.Errorf("%w: decision must be approve or deny", domain.ErrInvalid)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(tx)
	item, err := lockSecret(ctx, tx, id)
	if err != nil {
		return result, err
	}
	if item.OwnerID != user.ID {
		return result, domain.ErrForbidden
	}
	var current, email string
	err = tx.QueryRow(ctx, `SELECT status,requester_email FROM access_requests WHERE id=$1 AND secret_id=$2`, requestID, id).Scan(&current, &email)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, domain.ErrNotFound
	}
	if err != nil {
		return result, err
	}
	if current != "pending" {
		return result, domain.ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE access_requests SET status=$1,decided_at=clock_timestamp() WHERE id=$2`, status, requestID); err != nil {
		return result, err
	}
	if err = event(ctx, tx, "access.decided", map[string]any{"secret_id": id, "title": item.Title, "decision": decision, "requester_email": email}); err != nil {
		return result, err
	}
	s.invalidate(ctx, id)
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return domain.Decision{RequestID: requestID, Status: status}, nil
}

func (s *Service) RevokeAccess(ctx context.Context, user domain.User, id, userID string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	item, err := lockSecret(ctx, tx, id)
	if err != nil {
		return err
	}
	if item.OwnerID != user.ID {
		return domain.ErrForbidden
	}
	var email string
	err = tx.QueryRow(ctx, `UPDATE access_requests SET status='revoked',decided_at=clock_timestamp()
		WHERE secret_id=$1 AND requester_id=$2 AND status='approved' RETURNING requester_email`, id, userID).Scan(&email)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return err
	}
	if err = event(ctx, tx, "access.revoked", map[string]any{"secret_id": id, "title": item.Title, "user_emails": []string{email}}); err != nil {
		return err
	}
	s.invalidate(ctx, id)
	return tx.Commit(ctx)
}

func (s *Service) Revoke(ctx context.Context, user domain.User, id string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	item, err := lockSecret(ctx, tx, id)
	if err != nil {
		return err
	}
	if item.OwnerID != user.ID {
		return domain.ErrForbidden
	}
	emails := make([]string, 0)
	rows, err := tx.Query(ctx, `SELECT requester_email FROM access_requests WHERE secret_id=$1 AND status='approved' ORDER BY requester_id`, id)
	if err != nil {
		return err
	}
	for rows.Next() {
		var email string
		if err = rows.Scan(&email); err != nil {
			rows.Close()
			return err
		}
		emails = append(emails, email)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM secrets WHERE id=$1`, id); err != nil {
		return err
	}
	if len(emails) > 0 {
		if err = event(ctx, tx, "access.revoked", map[string]any{"secret_id": id, "title": item.Title, "user_emails": emails}); err != nil {
			return err
		}
	}
	s.invalidate(ctx, id)
	return tx.Commit(ctx)
}

// Cleanup removes expired rows; cascade constraints remove their requests/views.
// Expiration deliberately emits no notification event.
func (s *Service) Cleanup(ctx context.Context) error {
	rows, err := s.db.Query(ctx, `DELETE FROM secrets WHERE expires_at<=clock_timestamp() RETURNING id::text`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return err
		}
		s.invalidate(ctx, id)
	}
	return rows.Err()
}
