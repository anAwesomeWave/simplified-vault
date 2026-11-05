package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Cipher encrypts secret contents and binds each ciphertext to its secret ID.
type Cipher struct{ aead cipher.AEAD }

func New(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must contain exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

func (c *Cipher) Encrypt(id, text string) ([]byte, []byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return c.aead.Seal(nil, nonce, []byte(text), []byte(id)), nonce, nil
}

func (c *Cipher) Decrypt(id string, ciphertext, nonce []byte) (string, error) {
	if len(nonce) != c.aead.NonceSize() {
		return "", fmt.Errorf("invalid nonce size")
	}
	text, err := c.aead.Open(nil, nonce, ciphertext, []byte(id))
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return string(text), nil
}
