package security

import (
	"context"
	"strings"
	"testing"
)

var testParams = Argon2idParams{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

func newTestHasher(t *testing.T) *argon2idHasher {
	t.Helper()
	h, err := newArgon2idHasher(testParams, 2)
	if err != nil {
		t.Fatalf("newArgon2idHasher: %v", err)
	}
	return h
}

func TestHashAndVerify(t *testing.T) {
	ctx := context.Background()
	h := newTestHasher(t)

	encoded, err := h.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Fatalf("unexpected encoding: %s", encoded)
	}

	ok, err := h.Verify(ctx, "correct horse battery staple", encoded)
	if err != nil || !ok {
		t.Fatalf("Verify(correct) = %v, %v; want true, nil", ok, err)
	}
	ok, err = h.Verify(ctx, "wrong password!!", encoded)
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v; want false, nil", ok, err)
	}
}

func TestHashUsesRandomSalt(t *testing.T) {
	ctx := context.Background()
	h := newTestHasher(t)
	a, _ := h.Hash(ctx, "same-password")
	b, _ := h.Hash(ctx, "same-password")
	if a == b {
		t.Fatal("two hashes of the same password must differ")
	}
}

func TestVerifyUsesParamsFromHash(t *testing.T) {
	ctx := context.Background()
	old := newTestHasher(t)
	encoded, _ := old.Hash(ctx, "some-password")

	newer, err := newArgon2idHasher(Argon2idParams{Memory: 2048, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := newer.Verify(ctx, "some-password", encoded); err != nil || !ok {
		t.Fatalf("Verify with changed params = %v, %v", ok, err)
	}
}

func TestVerifyInvalidHash(t *testing.T) {
	h := newTestHasher(t)
	for _, encoded := range []string{
		"",
		"plain",
		"$argon2i$v=19$m=1024,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=18$m=1024,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=1024,t=1,p=1$!!!$a2V5a2V5a2V5a2V5a2V5a2V5",
	} {
		if _, err := h.Verify(context.Background(), "x", encoded); err != ErrInvalidHash {
			t.Errorf("Verify(%q) err = %v, want ErrInvalidHash", encoded, err)
		}
	}
}

func TestHashRespectsContext(t *testing.T) {
	h, _ := newArgon2idHasher(testParams, 1)
	h.sem <- struct{}{} // занимаем единственный слот
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Hash(ctx, "password"); err == nil {
		t.Fatal("expected context error")
	}
}
