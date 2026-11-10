package models

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	serverErrors "github.com/anAwesomeWave/simplified-vault/auth/internal/server_errors"
)

func TestNewEmail(t *testing.T) {
	valid := map[string]Email{
		"anna@company.com":       "anna@company.com",
		"  Anna@Company.COM \n":  "anna@company.com",
		"first.last+tag@a.b.org": "first.last+tag@a.b.org",
	}
	for raw, want := range valid {
		got, err := NewEmail(raw)
		if err != nil || got != want {
			t.Errorf("NewEmail(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}

	invalid := []string{
		"",
		"   ",
		"not-an-email",
		"Anna <anna@company.com>",
		"anna@localhost",
		"a@b.co, c@d.co",
		strings.Repeat("a", 250) + "@b.co",
	}
	for _, raw := range invalid {
		if _, err := NewEmail(raw); !errors.Is(err, serverErrors.ErrInvalidEmail) {
			t.Errorf("NewEmail(%q) err = %v; want ErrInvalidEmail", raw, err)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	cases := map[string]error{
		"0123456789": nil,
		"пароль1234": nil, // 10 символов, 16 байт
		"012345678":  serverErrors.ErrPasswordTooShort,
		"":           serverErrors.ErrPasswordTooShort,
		"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6": serverErrors.ErrPasswordTooShort, // невалидный UTF-8
		strings.Repeat("x", MaxPasswordBytes):      nil,
		strings.Repeat("x", MaxPasswordBytes+1):    serverErrors.ErrPasswordTooLong,
	}
	for pw, want := range cases {
		if err := ValidatePassword(pw); !errors.Is(err, want) {
			t.Errorf("ValidatePassword(len=%d) = %v; want %v", len(pw), err, want)
		}
	}
}

// Тексты ошибок в server_errors записаны литералами (иначе был бы цикл импортов),
// поэтому проверяем, что числа в них совпадают с константами.
func TestPasswordErrorMessagesMatchLimits(t *testing.T) {
	if !strings.Contains(serverErrors.ErrPasswordTooShort.Error(), " "+strconv.Itoa(MinPasswordLength)+" ") {
		t.Errorf("ErrPasswordTooShort = %q, want it to mention %d", serverErrors.ErrPasswordTooShort, MinPasswordLength)
	}
	if !strings.Contains(serverErrors.ErrPasswordTooLong.Error(), " "+strconv.Itoa(MaxPasswordBytes)+" ") {
		t.Errorf("ErrPasswordTooLong = %q, want it to mention %d", serverErrors.ErrPasswordTooLong, MaxPasswordBytes)
	}
}

func TestNewUser(t *testing.T) {
	now := time.Date(2026, 11, 3, 13, 0, 0, 0, time.FixedZone("MSK", 3*3600))
	a := NewUser("anna@company.com", "hash", now)
	b := NewUser("anna@company.com", "hash", now)
	if a.ID == b.ID {
		t.Fatal("ids must be unique")
	}
	if a.ID.Version() != 4 {
		t.Fatalf("id version = %d, want 4", a.ID.Version())
	}
	if a.CreatedAt.Location() != time.UTC || !a.CreatedAt.Equal(now) {
		t.Fatalf("created_at = %v", a.CreatedAt)
	}
}
