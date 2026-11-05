package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	serverErrors "github.com/anAwesomeWave/simplified-vault/notification/internal/server_errors"
)

const (
	eventID   = "7f3e2a10-4c1b-4d7e-9a55-0b8e1f6c2d91"
	secretID  = "c2a9e5d4-1f0b-4b8e-8d3a-6e7f9a1b2c3d"
	requestID = "41d0b6e2-9c7a-4f3e-b1d5-2a8c6e4f0b97"
)

// event собирает JSON события: общие поля плюс поля из extra.
// Значение nil в extra удаляет поле
func event(typ string, extra map[string]any) []byte {
	m := map[string]any{
		"event_id":    eventID,
		"type":        typ,
		"occurred_at": "2026-11-03T10:15:00Z",
		"secret_id":   secretID,
		"title":       "Доступ к админке CRM",
	}
	for k, v := range extra {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

func TestParseEventValid(t *testing.T) {
	// Пример сообщения из спецификации
	spec := []byte(`{
	  "event_id": "7f3e2a10-4c1b-4d7e-9a55-0b8e1f6c2d91",
	  "type": "access.requested",
	  "occurred_at": "2026-11-03T10:15:00Z",
	  "secret_id": "c2a9e5d4-1f0b-4b8e-8d3a-6e7f9a1b2c3d",
	  "title": "Доступ к админке CRM",
	  "request_id": "41d0b6e2-9c7a-4f3e-b1d5-2a8c6e4f0b97",
	  "requester_email": "ivan@company.com",
	  "owner_email": "anna@company.com"
	}`)
	e, err := ParseEvent(spec)
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != EventAccessRequested || e.ID.String() != eventID || e.SecretID.String() != secretID ||
		e.RequestID.String() != requestID || e.RequesterEmail != "ivan@company.com" ||
		e.OwnerEmail != "anna@company.com" || e.Title != "Доступ к админке CRM" {
		t.Fatalf("parsed = %+v", e)
	}

	e, err = ParseEvent(event("secret.created", map[string]any{
		"owner_id": requestID, "expires_at": "2026-11-04T10:15:00+03:00", "title": nil,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if e.OwnerID.String() != requestID || e.ExpiresAt.Location().String() != "UTC" {
		t.Fatalf("secret.created = %+v", e)
	}

	for in, want := range map[string]Decision{
		"approve": DecisionApproved, "approved": DecisionApproved,
		"deny": DecisionDenied, "DENIED": DecisionDenied,
	} {
		e, err := ParseEvent(event("access.decided", map[string]any{"decision": in, "requester_email": "ivan@company.com"}))
		if err != nil {
			t.Fatal(err)
		}
		if e.Decision != want {
			t.Errorf("decision %q = %q, want %q", in, e.Decision, want)
		}
	}

	e, err = ParseEvent(event("secret.viewed", map[string]any{
		"viewer_email": "Ivan@Company.com", "owner_email": "anna@company.com", "ip": "::ffff:10.0.0.7",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if e.ViewerEmail != "ivan@company.com" || e.IP.String() != "10.0.0.7" {
		t.Fatalf("secret.viewed = %+v", e)
	}

	e, err = ParseEvent(event("access.revoked", map[string]any{
		"user_emails": []string{"a@b.co", "c@d.co", "A@B.co"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(e.UserEmails) != "[a@b.co c@d.co]" {
		t.Fatalf("user_emails = %v, want deduplicated", e.UserEmails)
	}

	if _, err := ParseEvent(event("access.revoked", nil)); err != nil {
		t.Fatalf("revoked without approved users: %v", err)
	}
}

func TestParseEventInvalid(t *testing.T) {
	requested := map[string]any{"request_id": requestID, "requester_email": "ivan@company.com", "owner_email": "anna@company.com"}
	with := func(base map[string]any, k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range base {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	cases := map[string][]byte{
		"not json":            []byte("{"),
		"too big":             []byte(strings.Repeat(" ", MaxEventSize+1)),
		"no event_id":         event("access.requested", with(requested, "event_id", nil)),
		"bad event_id":        event("access.requested", with(requested, "event_id", "42")),
		"no occurred_at":      event("access.requested", with(requested, "occurred_at", nil)),
		"no type":             event("", requested),
		"no secret_id":        event("access.requested", with(requested, "secret_id", nil)),
		"no request_id":       event("access.requested", with(requested, "request_id", nil)),
		"no owner_email":      event("access.requested", with(requested, "owner_email", nil)),
		"crlf in email":       event("access.requested", with(requested, "owner_email", "anna@company.com\r\nBcc: x@evil.com")),
		"display-name email":  event("access.requested", with(requested, "owner_email", "Anna <anna@company.com>")),
		"bad decision":        event("access.decided", map[string]any{"decision": "maybe", "requester_email": "ivan@company.com"}),
		"no decision":         event("access.decided", map[string]any{"requester_email": "ivan@company.com"}),
		"bad ip":              event("secret.viewed", map[string]any{"viewer_email": "a@b.co", "owner_email": "c@d.co", "ip": "evil"}),
		"bad revoked email":   event("access.revoked", map[string]any{"user_emails": []string{"a@b.co", "nope"}}),
		"created no owner_id": event("secret.created", map[string]any{"expires_at": "2026-11-04T10:15:00Z"}),
	}
	for name, body := range cases {
		if _, err := ParseEvent(body); !errors.Is(err, serverErrors.ErrInvalidEvent) {
			t.Errorf("%s: err = %v, want ErrInvalidEvent", name, err)
		}
	}

	_, err := ParseEvent(event("secret.exploded", nil))
	if !errors.Is(err, serverErrors.ErrUnknownEventType) || !serverErrors.IsPermanent(err) {
		t.Errorf("unknown type: err = %v", err)
	}
}

func TestSanitizeTitle(t *testing.T) {
	cases := map[string]string{
		"  CRM\r\nBcc: evil@x.co ": "CRM Bcc: evil@x.co",
		"a‮b​c\x00d":               "abcd",
		"tab\there":                "tab here",
		"bad\xffutf8":              "badutf8",
	}
	for in, want := range cases {
		if got := SanitizeTitle(in); got != want {
			t.Errorf("SanitizeTitle(%q) = %q, want %q", in, got, want)
		}
	}
	long := SanitizeTitle(strings.Repeat("я", 500))
	if n := len([]rune(long)); n != MaxTitleRunes || !strings.HasSuffix(long, "…") {
		t.Errorf("long title: %d runes", n)
	}
}
