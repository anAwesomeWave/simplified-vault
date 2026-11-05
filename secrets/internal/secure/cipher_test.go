package secure

import (
	"bytes"
	"testing"
)

func TestEncryptionBindsSecretIDAndAuthenticatesCiphertext(t *testing.T) {
	c, err := New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	first, nonce, err := c.Encrypt("first", "a very private token")
	if err != nil {
		t.Fatal(err)
	}
	second, secondNonce, err := c.Encrypt("first", "a very private token")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(nonce, secondNonce) || bytes.Equal(first, second) {
		t.Fatal("nonce was reused")
	}
	if bytes.Contains(first, []byte("a very private token")) {
		t.Fatal("plaintext in ciphertext")
	}
	got, err := c.Decrypt("first", first, nonce)
	if err != nil || got != "a very private token" {
		t.Fatalf("round trip: %q, %v", got, err)
	}
	if _, err := c.Decrypt("second", first, nonce); err == nil {
		t.Fatal("ciphertext accepted for another ID")
	}
	first[0] ^= 1
	if _, err := c.Decrypt("first", first, nonce); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := c.Decrypt("first", first, nil); err == nil {
		t.Fatal("invalid nonce accepted")
	}
}

func TestMasterKeyMustBeAES256(t *testing.T) {
	for _, size := range []int{0, 16, 24, 31, 33} {
		if _, err := New(make([]byte, size)); err == nil {
			t.Fatalf("accepted %d byte key", size)
		}
	}
}
