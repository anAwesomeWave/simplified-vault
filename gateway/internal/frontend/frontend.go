// Package frontend serves the browser UI alongside the JSON API.
package frontend

import (
	"net/http"
	"path"
	"strings"

	"github.com/google/uuid"
)

// New keeps API routing unchanged unless a browser follows a secret link.
func New(directory string, api http.Handler) http.Handler {
	files := http.FileServer(http.Dir(directory))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/secrets/")
		parsed, err := uuid.Parse(id)
		secretLink := strings.HasPrefix(r.URL.Path, "/secrets/") && err == nil && parsed.String() == id &&
			strings.Contains(r.Header.Get("Accept"), "text/html")
		page := r.URL.Path == "/" || secretLink
		asset := strings.HasPrefix(r.URL.Path, "/assets/") && path.Clean(r.URL.Path) == r.URL.Path
		if (r.Method != http.MethodGet && r.Method != http.MethodHead) || (!page && !asset) {
			api.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if page {
			http.ServeFile(w, r, path.Join(directory, "index.html"))
			return
		}
		files.ServeHTTP(w, r)
	})
}
