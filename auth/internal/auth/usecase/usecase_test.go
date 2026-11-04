package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/models"
	serverErrors "github.com/anAwesomeWave/simplified-vault/auth/internal/server_errors"
)

// Фейковые реализации контрактов auth.Repository, auth.PasswordHasher и
// auth.TokenIssuer: usecase тестируется без БД и криптографии.

type fakeRepo struct {
	users map[models.Email]*models.User
	err   error
}

func newFakeRepo() *fakeRepo { return &fakeRepo{users: map[models.Email]*models.User{}} }

func (r *fakeRepo) CreateUser(_ context.Context, u *models.User) error {
	if r.err != nil {
		return r.err
	}
	if _, ok := r.users[u.Email]; ok {
		return serverErrors.ErrEmailTaken
	}
	r.users[u.Email] = u
	return nil
}

func (r *fakeRepo) GetUserByEmail(_ context.Context, email models.Email) (*models.User, error) {
	if r.err != nil {
		return nil, r.err
	}
	u, ok := r.users[email]
	if !ok {
		return nil, serverErrors.ErrUserNotFound
	}
	return u, nil
}

func (r *fakeRepo) Ping(context.Context) error { return r.err }

type fakeHasher struct {
	hashCalls, dummyCalls int
}

func (h *fakeHasher) Hash(_ context.Context, pw string) (string, error) {
	h.hashCalls++
	return "hash:" + pw, nil
}

func (h *fakeHasher) Verify(_ context.Context, pw, encoded string) (bool, error) {
	return encoded == "hash:"+pw, nil
}

func (h *fakeHasher) VerifyDummy(context.Context, string) { h.dummyCalls++ }

type fakeIssuer struct{}

func (fakeIssuer) Issue(u *models.User) (string, error) { return "token:" + u.ID.String(), nil }
func (fakeIssuer) TTL() time.Duration                   { return 15 * time.Minute }

var ctx = context.Background()

func creds(email, password string) models.Credentials {
	return models.Credentials{Email: email, Password: password}
}

func TestRegister(t *testing.T) {
	repo, hasher := newFakeRepo(), &fakeHasher{}
	uc := NewAuthUC(repo, hasher, fakeIssuer{})

	id, err := uc.Register(ctx, creds(" Anna@Company.com ", "0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	u, ok := repo.users["anna@company.com"]
	if !ok {
		t.Fatal("user is not stored under normalized email")
	}
	if u.ID != id || u.PasswordHash != "hash:0123456789" {
		t.Fatalf("stored user = %+v", u)
	}

	if _, err := uc.Register(ctx, creds("anna@company.com", "another-password")); !errors.Is(err, serverErrors.ErrEmailTaken) {
		t.Fatalf("duplicate err = %v, want ErrEmailTaken", err)
	}
}

func TestRegisterValidation(t *testing.T) {
	cases := []struct {
		email, password string
		want            error
	}{
		{"bad", "0123456789", serverErrors.ErrInvalidEmail},
		{"a@b.co", "short", serverErrors.ErrPasswordTooShort},
		{"a@b.co", strings.Repeat("x", models.MaxPasswordBytes+1), serverErrors.ErrPasswordTooLong},
	}
	for _, tc := range cases {
		hasher := &fakeHasher{}
		_, err := NewAuthUC(newFakeRepo(), hasher, fakeIssuer{}).Register(ctx, creds(tc.email, tc.password))
		if !errors.Is(err, tc.want) {
			t.Errorf("err = %v, want %v", err, tc.want)
		}
		if hasher.hashCalls != 0 {
			t.Error("invalid input must be rejected before hashing")
		}
	}
}

func TestRegisterRepoError(t *testing.T) {
	repo := newFakeRepo()
	repo.err = errors.New("db down")
	_, err := NewAuthUC(repo, &fakeHasher{}, fakeIssuer{}).Register(ctx, creds("a@b.co", "0123456789"))
	if err == nil || errors.Is(err, serverErrors.ErrEmailTaken) || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("err = %v", err)
	}
}

func TestLogin(t *testing.T) {
	repo, hasher := newFakeRepo(), &fakeHasher{}
	uc := NewAuthUC(repo, hasher, fakeIssuer{})
	id, _ := uc.Register(ctx, creds("ivan@company.com", "s3cret-pass"))

	token, err := uc.Login(ctx, creds("IVAN@company.com", "s3cret-pass"))
	if err != nil {
		t.Fatal(err)
	}
	want := models.AccessToken{AccessToken: "token:" + id.String(), TokenType: "Bearer", ExpiresIn: 900}
	if *token != want {
		t.Fatalf("token = %+v, want %+v", *token, want)
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	repo, hasher := newFakeRepo(), &fakeHasher{}
	uc := NewAuthUC(repo, hasher, fakeIssuer{})
	_, _ = uc.Register(ctx, creds("ivan@company.com", "s3cret-pass"))

	cases := []struct {
		name, email, password string
		dummy                 bool // должен ли вызываться VerifyDummy
	}{
		{"wrong password", "ivan@company.com", "wrong-pass!", false},
		{"unknown email", "nobody@company.com", "s3cret-pass", true},
		{"invalid email", "garbage", "s3cret-pass", true},
		{"huge password", "ivan@company.com", strings.Repeat("x", models.MaxPasswordBytes+1), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := hasher.dummyCalls
			_, err := uc.Login(ctx, creds(tc.email, tc.password))
			if !errors.Is(err, serverErrors.ErrInvalidCredentials) {
				t.Fatalf("err = %v, want ErrInvalidCredentials", err)
			}
			if called := hasher.dummyCalls > before; called != tc.dummy {
				t.Fatalf("VerifyDummy called = %v, want %v", called, tc.dummy)
			}
		})
	}
}

func TestLoginRepoError(t *testing.T) {
	repo := newFakeRepo()
	repo.err = errors.New("db down")
	_, err := NewAuthUC(repo, &fakeHasher{}, fakeIssuer{}).Login(ctx, creds("a@b.co", "0123456789"))
	if err == nil || errors.Is(err, serverErrors.ErrInvalidCredentials) {
		t.Fatalf("err = %v; infrastructure errors must not look like bad credentials", err)
	}
}

func TestCheckHealth(t *testing.T) {
	repo := newFakeRepo()
	uc := NewAuthUC(repo, &fakeHasher{}, fakeIssuer{})
	if err := uc.CheckHealth(ctx); err != nil {
		t.Fatal(err)
	}
	repo.err = errors.New("db down")
	if err := uc.CheckHealth(ctx); err == nil {
		t.Fatal("expected error")
	}
}
