package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func privateKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func publicPEM(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestNewAcceptsPublicKeyFormatsAndRejectsWeakKeys(t *testing.T) {
	key := privateKey(t, 2048)
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "auth test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"PKIX":        publicPEM(t, &key.PublicKey),
		"PKCS1":       pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}),
		"certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(data); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err = New([]byte("not PEM")); err == nil {
		t.Fatal("malformed key accepted")
	}
	weak := privateKey(t, 1024)
	if _, err = New(publicPEM(t, &weak.PublicKey)); err == nil {
		t.Fatal("1024-bit key accepted")
	}
}

func TestVerifySignedTokens(t *testing.T) {
	key, otherKey := privateKey(t, 2048), privateKey(t, 2048)
	verifier, err := New(publicPEM(t, &key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	now := time.Now()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"user_id": strings.ToUpper(id), "email": "user@example.com", "exp": now.Add(15 * time.Minute).Unix(), "iat": now.Add(-time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix()}
	}
	cases := []struct {
		name   string
		change func(jwt.MapClaims)
		method jwt.SigningMethod
		key    any
		valid  bool
	}{
		{name: "valid and canonical UUID", valid: true},
		{name: "iat optional", change: func(c jwt.MapClaims) { delete(c, "iat") }, valid: true},
		{name: "nbf optional", change: func(c jwt.MapClaims) { delete(c, "nbf") }, valid: true},
		{name: "expired", change: func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Hour).Unix() }},
		{name: "missing exp", change: func(c jwt.MapClaims) { delete(c, "exp") }},
		{name: "future iat", change: func(c jwt.MapClaims) { c["iat"] = now.Add(time.Hour).Unix() }},
		{name: "future nbf", change: func(c jwt.MapClaims) { c["nbf"] = now.Add(time.Hour).Unix() }},
		{name: "wrong signing key", key: otherKey},
		{name: "RS512 not allowed", method: jwt.SigningMethodRS512},
		{name: "HS256 not allowed", method: jwt.SigningMethodHS256, key: []byte("test HMAC key")},
		{name: "malformed exp", change: func(c jwt.MapClaims) { c["exp"] = "tomorrow" }},
		{name: "malformed UUID", change: func(c jwt.MapClaims) { c["user_id"] = "not-a-UUID" }},
		{name: "zero UUID", change: func(c jwt.MapClaims) { c["user_id"] = uuid.Nil.String() }},
		{name: "missing UUID", change: func(c jwt.MapClaims) { delete(c, "user_id") }},
		{name: "UUID wrong type", change: func(c jwt.MapClaims) { c["user_id"] = 42 }},
		{name: "missing email", change: func(c jwt.MapClaims) { delete(c, "email") }},
		{name: "invalid email", change: func(c jwt.MapClaims) { c["email"] = "invalid" }},
		{name: "email wrong type", change: func(c jwt.MapClaims) { c["email"] = 42 }},
		{name: "display name forbidden", change: func(c jwt.MapClaims) { c["email"] = "User <user@example.com>" }},
		{name: "oversized email", change: func(c jwt.MapClaims) { c["email"] = strings.Repeat("a", 310) + "@example.com" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			payload := base()
			if test.change != nil {
				test.change(payload)
			}
			method := test.method
			if method == nil {
				method = jwt.SigningMethodRS256
			}
			signingKey := test.key
			if signingKey == nil {
				signingKey = key
			}
			token, err := jwt.NewWithClaims(method, payload).SignedString(signingKey)
			if err != nil {
				t.Fatal(err)
			}
			user, err := verifier.Verify("Bearer " + token)
			if test.valid {
				if err != nil || user.ID != id || user.Email != "user@example.com" {
					t.Fatalf("valid token: %#v %v", user, err)
				}
			} else if err != ErrUnauthorized || user != (User{}) {
				t.Fatalf("rejected token must return generic error and no identity: %#v %v", user, err)
			}
		})
	}
	validToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, base()).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"", "Bearer", "Basic " + validToken, "Bearer invalid", "Bearer " + validToken + " extra", validToken} {
		if user, err := verifier.Verify(header); err != ErrUnauthorized || user != (User{}) {
			t.Fatalf("invalid header accepted: %#v %v", user, err)
		}
	}
}
