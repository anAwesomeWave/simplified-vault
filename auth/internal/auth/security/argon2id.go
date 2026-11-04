// Package security - реализации контрактов auth.PasswordHasher (argon2id)
// и auth.TokenIssuer (JWT RS256).
//
// Хэши паролей хранятся в строковом формате PHC:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<base64 соль>$<base64 ключ>
//
// поэтому параметры можно поменять позже, не ломая существующие хэши.
package security

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/auth"
)

// ErrInvalidHash возвращается, если сохранённый хэш не удаётся разобрать.
var ErrInvalidHash = errors.New("password: invalid argon2id hash")

// Argon2idParams — параметры стоимости argon2id.
type Argon2idParams struct {
	Memory      uint32 // КиБ
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2idParams соответствуют рекомендациям RFC 9106 / OWASP для интерактивного входа.
var DefaultArgon2idParams = Argon2idParams{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

// Верхние границы параметров при разборе сохранённого хэша: повреждённая или
// подменённая запись не должна заставить сервис выделить неограниченную память.
const (
	maxMemory     = 1024 * 1024 // 1 ГиБ
	maxIterations = 64
	maxKeyLength  = 128
)

// argon2idHasher хэширует и проверяет пароли. Каждый вызов argon2id выделяет
// Argon2idParams.Memory КиБ, поэтому число одновременных вычислений ограничено.
type argon2idHasher struct {
	params Argon2idParams
	sem    chan struct{}
	dummy  string
}

// NewArgon2idHasher создаёт хэшер, который выполняет не больше maxConcurrent
// вычислений argon2id одновременно
func NewArgon2idHasher(p Argon2idParams, maxConcurrent int) (auth.PasswordHasher, error) {
	h, err := newArgon2idHasher(p, maxConcurrent)
	if err != nil {
		return nil, err // явный nil: типизированный nil в интерфейсе не равен nil
	}
	return h, nil
}

func newArgon2idHasher(p Argon2idParams, maxConcurrent int) (*argon2idHasher, error) {
	if p.Memory == 0 || p.Iterations == 0 || p.Parallelism == 0 || p.SaltLength < 8 || p.KeyLength < 16 {
		return nil, errors.New("password: invalid argon2id parameters")
	}
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	h := &argon2idHasher{params: p, sem: make(chan struct{}, maxConcurrent)}

	// Хэш случайного пароля. С ним сверяемся, когда пользователя нет, чтобы
	// время ответа на вход не выдавало, какие email зарегистрированы.
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("password: generate dummy: %w", err)
	}
	dummy, err := h.hash(string(random))
	if err != nil {
		return nil, err
	}
	h.dummy = dummy
	return h, nil
}

// Hash возвращает argon2id-хэш пароля в формате PHC.
func (h *argon2idHasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	return h.hash(password)
}

// Verify сообщает, совпадает ли пароль с сохранённым хэшем.
func (h *argon2idHasher) Verify(ctx context.Context, password, encoded string) (bool, error) {
	p, salt, key, err := decode(encoded)
	if err != nil {
		return false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()

	other := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return subtle.ConstantTimeCompare(key, other) == 1, nil
}

// VerifyDummy тратит столько же ресурсов, сколько Verify, и всегда даёт отказ.
// Используется, когда пользователь не найден.
func (h *argon2idHasher) VerifyDummy(ctx context.Context, password string) {
	_, _ = h.Verify(ctx, password, h.dummy)
}

func (h *argon2idHasher) hash(password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.params.Memory, h.params.Iterations, h.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func (h *argon2idHasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *argon2idHasher) release() { <-h.sem }

func decode(encoded string) (Argon2idParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Argon2idParams{}, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Argon2idParams{}, nil, nil, ErrInvalidHash
	}

	var p Argon2idParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Argon2idParams{}, nil, nil, ErrInvalidHash
	}
	if p.Memory == 0 || p.Memory > maxMemory || p.Iterations == 0 || p.Iterations > maxIterations || p.Parallelism == 0 {
		return Argon2idParams{}, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return Argon2idParams{}, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > maxKeyLength {
		return Argon2idParams{}, nil, nil, ErrInvalidHash
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))
	return p, salt, key, nil
}
