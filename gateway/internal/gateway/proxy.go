package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"simple-vault/gateway/internal/auth"
	"simple-vault/gateway/internal/ratelimit"
)

type identityKey struct{}

type Handler struct {
	authProxy      *httputil.ReverseProxy
	secretsProxy   *httputil.ReverseProxy
	verifier       *auth.Verifier
	limiter        *ratelimit.Limiter
	logger         *slog.Logger
	transport      *http.Transport
	requestTimeout time.Duration
}

func New(authURL, secretsURL *url.URL, verifier *auth.Verifier, limiter *ratelimit.Limiter, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &Handler{
		verifier: verifier, limiter: limiter, logger: logger, requestTimeout: 15 * time.Second,
		transport: &http.Transport{
			DialContext:       (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2: true, MaxIdleConns: 100, MaxIdleConnsPerHost: 16,
			IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 3 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second, ExpectContinueTimeout: time.Second,
		},
	}
	h.authProxy = h.proxy(authURL, false)
	h.secretsProxy = h.proxy(secretsURL, true)
	return h
}

func (h *Handler) CloseIdleConnections() { h.transport.CloseIdleConnections() }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), h.requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	switch {
	case r.URL.Path == "/health/live":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case r.URL.Path == "/auth/register" || r.URL.Path == "/auth/login":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		if r.URL.Path == "/auth/login" {
			if allowed, retryAfter := h.limiter.Allow(peerIP(r)); !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retryAfter.Seconds())))))
				writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many login attempts")
				return
			}
		}
		h.authProxy.ServeHTTP(w, r)
	case r.URL.Path == "/secrets" || strings.HasPrefix(r.URL.Path, "/secrets/"):
		values := r.Header.Values("Authorization")
		if len(values) != 1 {
			unauthorized(w)
			return
		}
		user, err := h.verifier.Verify(values[0])
		if err != nil {
			unauthorized(w)
			return
		}
		ctx := context.WithValue(r.Context(), identityKey{}, user)
		h.secretsProxy.ServeHTTP(w, r.WithContext(ctx))
	default:
		writeError(w, http.StatusNotFound, "not_found", "Route not found")
	}
}

func (h *Handler) proxy(target *url.URL, secrets bool) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: h.transport,
		ErrorLog:  log.New(io.Discard, "", 0),
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(target)
			// Rewrite runs after hop-by-hop removal. Client Connection tokens
			// therefore cannot erase the verified identity installed below.
			for name := range p.Out.Header {
				lower := strings.ToLower(name)
				if lower == "x-user-id" || lower == "x-user-email" || lower == "x-real-ip" || lower == "authorization" || lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") {
					delete(p.Out.Header, name)
				}
			}
			p.Out.Header.Set("X-Real-IP", peerIP(p.In))
			if secrets {
				user := p.In.Context().Value(identityKey{}).(auth.User)
				p.Out.Header.Set("X-User-ID", user.ID)
				p.Out.Header.Set("X-User-Email", user.Email)
			}
		},
		ModifyResponse: func(response *http.Response) error {
			response.Header.Set("Cache-Control", "no-store")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var networkError net.Error
			timeout := errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout()
			// Headers, request bodies, URL queries and raw upstream errors may
			// contain credentials. Only log the failure category.
			h.logger.Warn("upstream request failed", "secrets", secrets, "timeout", timeout)
			if timeout {
				writeError(w, http.StatusGatewayTimeout, "upstream_timeout", "Upstream service timed out")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream_unavailable", "Upstream service is unavailable")
		},
	}
}

func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, "unauthorized", "A valid bearer token is required")
}

func writeError(w http.ResponseWriter, status int, kind, message string) {
	writeJSON(w, status, struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}{kind, message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
