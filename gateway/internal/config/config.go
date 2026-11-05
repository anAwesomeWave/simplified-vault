package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
)

type Config struct {
	HTTPAddr      string
	AuthURL       *url.URL
	SecretsURL    *url.URL
	PublicKeyFile string
	LoginLimit    int
	TLSCertFile   string
	TLSKeyFile    string
}

func Load() (Config, error) {
	c := Config{
		HTTPAddr:      env("HTTP_ADDR", ":8000"),
		PublicKeyFile: env("JWT_PUBLIC_KEY_FILE", "/run/secrets/jwt_public_key"),
		TLSCertFile:   os.Getenv("TLS_CERT_FILE"), TLSKeyFile: os.Getenv("TLS_KEY_FILE"),
	}
	if _, _, err := net.SplitHostPort(c.HTTPAddr); err != nil {
		return Config{}, errors.New("HTTP_ADDR must be host:port")
	}
	var err error
	c.AuthURL, err = upstream("AUTH_URL", "http://auth:8000")
	if err != nil {
		return Config{}, err
	}
	c.SecretsURL, err = upstream("SECRETS_URL", "http://secrets:8000")
	if err != nil {
		return Config{}, err
	}
	c.LoginLimit, err = strconv.Atoi(env("LOGIN_REQUESTS_PER_MINUTE", "5"))
	if err != nil || c.LoginLimit < 1 {
		return Config{}, errors.New("LOGIN_REQUESTS_PER_MINUTE must be a positive integer")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return Config{}, errors.New("TLS_CERT_FILE and TLS_KEY_FILE must be configured together")
	}
	if c.PublicKeyFile == "" {
		return Config{}, errors.New("JWT_PUBLIC_KEY_FILE must not be empty")
	}
	return c, nil
}

func upstream(name, fallback string) (*url.URL, error) {
	u, err := url.Parse(env(name, fallback))
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("%s must be an HTTP(S) origin without credentials, path, query or fragment", name)
	}
	return u, nil
}

func env(name, fallback string) string {
	if value, exists := os.LookupEnv(name); exists {
		return value
	}
	return fallback
}
