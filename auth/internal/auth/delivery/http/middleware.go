package http

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/utils"
)

type ctxKey struct{}

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(ctxKey{}).(string)
	return id
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// logRequests логирует метод, путь, статус и длительность. Тела и заголовки
// не логируются никогда: в них пароли и токены.
func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID.MatchString(id) {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, id))

		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		if r.URL.Path == "/healthz" && rec.status == http.StatusOK {
			return
		}
		log.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", id,
		)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				log.Error("panic in handler", "panic", rec, "path", r.URL.Path)
				utils.WriteJSONError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
