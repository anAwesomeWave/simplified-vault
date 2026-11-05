package domain

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrForbidden = errors.New("forbidden")
	ErrConflict  = errors.New("already decided")
	ErrInvalid   = errors.New("invalid input")
)

type User struct{ ID, Email string }

type CreateInput struct {
	Title      string `json:"title"`
	Text       string `json:"text"`
	TTLSeconds *int64 `json:"ttl_seconds,omitempty"`
}

type Created struct {
	ID        string    `json:"id"`
	Link      string    `json:"link"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Owned struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	ExpiresAt       time.Time `json:"expires_at"`
	PendingRequests int64     `json:"pending_requests"`
}

type Shared struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	OwnerEmail string    `json:"owner_email"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type Opened struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Text      string    `json:"text"`
	ExpiresAt time.Time `json:"expires_at"`
}

// A nil Opened with no error represents a pending access request (HTTP 202).
type Request struct {
	ID             string    `json:"id"`
	RequesterEmail string    `json:"requester_email"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

type View struct {
	Email    string    `json:"email"`
	IP       string    `json:"ip"`
	ViewedAt time.Time `json:"viewed_at"`
}

type History struct {
	Requests []Request `json:"requests"`
	Views    []View    `json:"views"`
}

type Decision struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

type Service interface {
	Create(context.Context, User, CreateInput) (Created, error)
	ListOwned(context.Context, User) ([]Owned, error)
	ListShared(context.Context, User) ([]Shared, error)
	Open(context.Context, User, string, string) (*Opened, error)
	History(context.Context, User, string) (History, error)
	Decide(context.Context, User, string, string, string) (Decision, error)
	RevokeAccess(context.Context, User, string, string) error
	Revoke(context.Context, User, string) error
}
