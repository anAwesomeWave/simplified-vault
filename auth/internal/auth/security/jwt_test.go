package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/models"
)

func TestIssueAndVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := newJWTIssuer(key, "auth", "secrets", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	iss.now = func() time.Time { return fixed }

	u := &models.User{ID: uuid.MustParse("6b1f0c1e-0000-4000-8000-000000000001"), Email: "anna@company.com"}
	signed, err := iss.Issue(u)
	if err != nil {
		t.Fatal(err)
	}

	var claims Claims
	_, err = jwt.ParseWithClaims(signed, &claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer("auth"),
		jwt.WithAudience("secrets"),
		jwt.WithTimeFunc(func() time.Time { return fixed.Add(time.Minute) }),
	)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.UserID != "6b1f0c1e-0000-4000-8000-000000000001" || claims.Subject != claims.UserID {
		t.Errorf("user_id/sub = %q/%q", claims.UserID, claims.Subject)
	}
	if claims.Email != "anna@company.com" {
		t.Errorf("email = %q", claims.Email)
	}
	if got := claims.ExpiresAt.Sub(claims.IssuedAt.Time); got != 15*time.Minute {
		t.Errorf("lifetime = %v, want 15m", got)
	}
	if claims.ID == "" {
		t.Error("jti is empty")
	}

	// Через 15 минут токен истёк.
	_, err = jwt.ParseWithClaims(signed, &Claims{}, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithTimeFunc(func() time.Time { return fixed.Add(16 * time.Minute) }),
	)
	if err == nil {
		t.Fatal("expected token to be expired")
	}
}

func TestNewIssuerRejectsWeakKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newJWTIssuer(key, "auth", "secrets", time.Minute); err == nil {
		t.Fatal("expected error for 1024-bit key")
	}
}

func TestParseRSAPrivateKeyPEM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	for name, data := range map[string][]byte{"pkcs1": pkcs1, "pkcs8": pkcs8} {
		got, err := ParseRSAPrivateKeyPEM(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !got.Equal(key) {
			t.Fatalf("%s: key mismatch", name)
		}
	}
	if _, err := ParseRSAPrivateKeyPEM([]byte("garbage")); err == nil {
		t.Fatal("expected error for garbage input")
	}
}
