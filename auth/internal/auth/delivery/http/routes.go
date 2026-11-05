package http

import (
	"log/slog"
	"net/http"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/auth"
	"github.com/anAwesomeWave/simplified-vault/auth/internal/utils"
)

// MapAuthRouter регистрирует ручки auth.
//
// Gateway проксирует /auth/ без переписывания пути, поэтому маршруты сохраняют
// префикс /auth. /healthz лежит вне /auth/, поэтому доступен только внутри docker-сети
func MapAuthRouter(m *http.ServeMux, h auth.Handler) {
	m.HandleFunc("POST /auth/register", h.Register())
	m.HandleFunc("POST /auth/login", h.Login())
	m.HandleFunc("GET /healthz", h.Health())
	m.HandleFunc("GET /auth/openapi.yaml", serveOpenAPI)
	m.HandleFunc("GET /auth/docs", serveSwaggerUI)

	// те же пути с другими методами: JSON 405 вместо текстового ответа mux
	for _, path := range []string{"/auth/register", "/auth/login"} {
		m.HandleFunc(path, methodNotAllowed(http.MethodPost))
	}
	m.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		utils.WriteJSONError(w, http.StatusNotFound, "not_found", "resource not found")
	})
}

// NewRouter собирает роутер auth со всеми middleware
func NewRouter(h auth.Handler, log *slog.Logger) http.Handler {
	m := http.NewServeMux()
	MapAuthRouter(m, h)
	return recoverer(log, logRequests(log, securityHeaders(m)))
}

func methodNotAllowed(allowed string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", allowed)
		utils.WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}
