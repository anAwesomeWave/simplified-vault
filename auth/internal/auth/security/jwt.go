package security

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/auth"
	"github.com/anAwesomeWave/simplified-vault/auth/internal/models"
)

const minRSABits = 2048

// Claims — полезная нагрузка JWT.
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// jwtIssuer подписывает access-токены приватным RSA-ключом (RS256). Сервис secrets
// проверяет их публичным ключом и берёт user_id и email прямо из claims
type jwtIssuer struct {
	key      *rsa.PrivateKey
	issuer   string
	audience string
	ttl      time.Duration
	now      func() time.Time
}

// NewJWTIssuer создаёт выпускающего токены. Токены получают iss=issuer, aud=audience
// и истекают через ttl
func NewJWTIssuer(key *rsa.PrivateKey, issuer, audience string, ttl time.Duration) (auth.TokenIssuer, error) {
	i, err := newJWTIssuer(key, issuer, audience, ttl)
	if err != nil {
		return nil, err // явный nil: типизированный nil в интерфейсе не равен nil
	}
	return i, nil
}

func newJWTIssuer(key *rsa.PrivateKey, issuer, audience string, ttl time.Duration) (*jwtIssuer, error) {
	if key == nil {
		return nil, errors.New("token: nil private key")
	}
	if key.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("token: RSA key must be at least %d bits, got %d", minRSABits, key.N.BitLen())
	}
	if ttl <= 0 {
		return nil, errors.New("token: ttl must be positive")
	}
	return &jwtIssuer{key: key, issuer: issuer, audience: audience, ttl: ttl, now: time.Now}, nil
}

// TTL возвращает срок жизни токена.
func (i *jwtIssuer) TTL() time.Duration { return i.ttl }

// Issue возвращает подписанный токен для пользователя.
func (i *jwtIssuer) Issue(u *models.User) (string, error) {
	userID := u.ID.String()
	now := i.now().UTC().Truncate(time.Second)
	claims := Claims{
		UserID: userID,
		Email:  u.Email.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{i.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
			ID:        uuid.NewString(),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(i.key)
	if err != nil {
		return "", fmt.Errorf("token: sign: %w", err)
	}
	return signed, nil
}

// LoadRSAPrivateKey читает приватный RSA-ключ в PEM (PKCS#1 или PKCS#8) из файла.
func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("token: read private key: %w", err)
	}
	return ParseRSAPrivateKeyPEM(data)
}

// ParseRSAPrivateKeyPEM разбирает приватный RSA-ключ в PEM (PKCS#1 или PKCS#8).
func ParseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("token: no PEM block found in private key")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("token: parse PKCS#8 key: %w", err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("token: private key is not RSA")
		}
		return rk, nil
	default:
		return nil, fmt.Errorf("token: unsupported PEM block %q", block.Type)
	}
}
