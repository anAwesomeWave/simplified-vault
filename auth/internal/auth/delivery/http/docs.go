package http

import (
	"net/http"

	"github.com/anAwesomeWave/simplified-vault/auth/api"
)

func serveOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(api.OpenAPI)
}

func serveSwaggerUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Ресурсы Swagger UI грузятся с CDN, поэтому CSP ослабляем только для этой страницы.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'unsafe-inline' https://unpkg.com; style-src https://unpkg.com; img-src data: https://unpkg.com; connect-src 'self'")
	_, _ = w.Write(api.SwaggerUI)
}
