package frontend

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserPagesDoNotReplaceAPIRoutes(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("<!doctype html><title>simple-vault</title>"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, "assets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "assets", "app.js"), []byte("export {};"), 0600); err != nil {
		t.Fatal(err)
	}
	handler := New(directory, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	for _, test := range []struct {
		name, method, path, accept, content string
		status                              int
	}{
		{"home", "GET", "/", "text/html", "simple-vault", 200},
		{"email link", "GET", "/secrets/00000000-0000-0000-0000-000000000001", "text/html", "simple-vault", 200},
		{"script", "GET", "/assets/app.js", "*/*", "export {};", 200},
		{"API fetch", "GET", "/secrets/00000000-0000-0000-0000-000000000001", "application/json", "unauthorized", 401},
		{"API default accept", "GET", "/secrets/00000000-0000-0000-0000-000000000001", "", "unauthorized", 401},
		{"API list", "GET", "/secrets", "text/html", "unauthorized", 401},
		{"API shared list", "GET", "/secrets/shared", "application/json", "unauthorized", 401},
		{"API shared in browser", "GET", "/secrets/shared", "text/html", "unauthorized", 401},
		{"API history", "GET", "/secrets/id/requests", "text/html", "unauthorized", 401},
		{"API delete", "DELETE", "/secrets/id", "text/html", "unauthorized", 401},
		{"API login", "POST", "/auth/login", "text/html", "unauthorized", 401},
		{"unknown route", "GET", "/unknown", "text/html", "unauthorized", 401},
		{"private files", "GET", "/.env", "text/html", "unauthorized", 401},
		{"asset traversal", "GET", "/assets/../index.html", "text/html", "unauthorized", 401},
		{"missing asset", "GET", "/assets/missing.js", "*/*", "404", 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			request.Header.Set("Accept", test.accept)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.content) {
				t.Fatalf("got %d %q", response.Code, response.Body.String())
			}
			if response.Code == 200 && (response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Security-Policy") == "") {
				t.Fatal("missing browser security headers")
			}
		})
	}
}
