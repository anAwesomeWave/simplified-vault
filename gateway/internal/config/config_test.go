package config

import "testing"

func defaults(t *testing.T) {
	t.Helper()
	for name, value := range map[string]string{
		"HTTP_ADDR": ":8000", "AUTH_URL": "http://auth:8000", "SECRETS_URL": "http://secrets:8000",
		"JWT_PUBLIC_KEY_FILE": "/run/secrets/jwt_public_key", "LOGIN_REQUESTS_PER_MINUTE": "5", "TLS_CERT_FILE": "", "TLS_KEY_FILE": "",
	} {
		t.Setenv(name, value)
	}
}

func TestLoad(t *testing.T) {
	defaults(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LoginLimit != 5 || cfg.HTTPAddr != ":8000" || cfg.AuthURL.Host != "auth:8000" || cfg.SecretsURL.Host != "secrets:8000" || cfg.TLSCertFile != "" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	t.Setenv("TLS_CERT_FILE", "/run/secrets/tls_certificate")
	t.Setenv("TLS_KEY_FILE", "/run/secrets/tls_private_key")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidConfig(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"HTTP_ADDR", "8000"}, {"AUTH_URL", "file:///tmp/auth"}, {"AUTH_URL", "http://user:password@auth:8000"},
		{"SECRETS_URL", "http://secrets:8000/prefix"}, {"SECRETS_URL", "http://secrets:8000?key=value"},
		{"SECRETS_URL", "http://secrets:8000/#fragment"}, {"AUTH_URL", "http://"}, {"AUTH_URL", "http://auth:invalid"},
		{"LOGIN_REQUESTS_PER_MINUTE", "0"}, {"LOGIN_REQUESTS_PER_MINUTE", "-1"}, {"LOGIN_REQUESTS_PER_MINUTE", "five"},
		{"TLS_CERT_FILE", "certificate.pem"}, {"TLS_KEY_FILE", "private.pem"}, {"JWT_PUBLIC_KEY_FILE", ""},
	} {
		t.Run(tc.name+tc.value, func(t *testing.T) {
			defaults(t)
			t.Setenv(tc.name, tc.value)
			if _, err := Load(); err == nil {
				t.Fatal("expected invalid configuration to fail")
			}
		})
	}
}
