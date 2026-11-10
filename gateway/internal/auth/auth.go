package auth

import (
	"crypto/rsa"
	"errors"
	"net/mail"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var ErrUnauthorized = errors.New("unauthorized")

type User struct{ ID, Email string }

type Verifier struct {
	key    *rsa.PublicKey
	parser *jwt.Parser
}

type claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

func New(publicPEM []byte) (*Verifier, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicPEM)
	if err != nil {
		return nil, errors.New("invalid RSA public key")
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("RSA public key must contain at least 2048 bits")
	}
	return &Verifier{key: key, parser: jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(),
		jwt.WithIssuer("auth"), jwt.WithAudience("secrets"),
	)}, nil
}

func (v *Verifier) Verify(header string) (User, error) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return User{}, ErrUnauthorized
	}
	var payload claims
	token, err := v.parser.ParseWithClaims(fields[1], &payload, func(*jwt.Token) (any, error) {
		return v.key, nil
	})
	if err != nil || !token.Valid {
		return User{}, ErrUnauthorized
	}
	id, idErr := uuid.Parse(payload.UserID)
	email, emailErr := mail.ParseAddress(payload.Email)
	if idErr != nil || id == uuid.Nil || emailErr != nil || email.Address != payload.Email || len(payload.Email) > 320 {
		return User{}, ErrUnauthorized
	}
	return User{ID: id.String(), Email: email.Address}, nil
}
