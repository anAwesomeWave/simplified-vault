package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"simple-vault/secrets/api"
	"simple-vault/secrets/internal/domain"
)

type userKey struct{}

type Handler struct {
	service        domain.Service
	logger         *slog.Logger
	requestTimeout time.Duration
}

func New(service domain.Service, logger *slog.Logger, requestTimeout time.Duration) http.Handler {
	h := &Handler{service: service, logger: logger, requestTimeout: requestTimeout}
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("POST /secrets", h.create)
	apiMux.HandleFunc("GET /secrets", h.owned)
	apiMux.HandleFunc("GET /secrets/shared", h.shared)
	apiMux.HandleFunc("GET /secrets/{id}", h.open)
	apiMux.HandleFunc("GET /secrets/{id}/requests", h.history)
	apiMux.HandleFunc("POST /secrets/{id}/requests/{request_id}", h.decide)
	apiMux.HandleFunc("DELETE /secrets/{id}/access/{user_id}", h.revokeAccess)
	apiMux.HandleFunc("DELETE /secrets/{id}", h.revoke)
	apiMux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "Маршрут не найден")
	})
	mux := http.NewServeMux()
	protected := h.gatewayIdentity(apiMux)
	mux.Handle("/secrets", protected)
	mux.Handle("/secrets/", protected)
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		_, _ = w.Write(api.OpenAPI)
	})
	mux.HandleFunc("GET /docs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(api.Docs)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "Маршрут не найден")
	})
	return h.middleware(mux)
}

func (h *Handler) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		defer func() {
			if recover() != nil {
				h.logger.Error("HTTP handler panic")
				writeError(w, http.StatusInternalServerError, "internal_error", "Внутренняя ошибка")
			}
		}()
		ctx, cancel := context.WithTimeout(r.Context(), h.requestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Only the trusted gateway may reach the service and set these headers.
func (h *Handler) gatewayIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids, emails := r.Header.Values("X-User-ID"), r.Header.Values("X-User-Email")
		if len(ids) != 1 || len(emails) != 1 {
			writeError(w, http.StatusUnauthorized, "gateway_identity_required", "Отсутствуют или некорректны данные пользователя")
			return
		}
		id, idErr := uuid.Parse(ids[0])
		email, emailErr := mail.ParseAddress(emails[0])
		if idErr != nil || id == uuid.Nil || emailErr != nil || email.Address != emails[0] || len(emails[0]) > 320 {
			writeError(w, http.StatusUnauthorized, "gateway_identity_required", "Отсутствуют или некорректны данные пользователя")
			return
		}
		user := domain.User{ID: id.String(), Email: email.Address}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, user)))
	})
}

func user(r *http.Request) domain.User { return r.Context().Value(userKey{}).(domain.User) }

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	if mediaType := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]); !strings.EqualFold(mediaType, "application/json") {
		writeError(w, http.StatusBadRequest, "invalid_request", "Требуется Content-Type: application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Некорректное JSON-тело запроса")
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_request", "Ожидался один JSON-объект")
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil || id == uuid.Nil {
		writeError(w, http.StatusNotFound, "not_found", "Объект не найден")
		return "", false
	}
	return id.String(), true
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var input domain.CreateInput
	if !decode(w, r, &input) {
		return
	}
	result, err := h.service.Create(r.Context(), user(r), input)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (h *Handler) owned(w http.ResponseWriter, r *http.Request) {
	result, err := h.service.ListOwned(r.Context(), user(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	if result == nil {
		result = []domain.Owned{}
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) shared(w http.ResponseWriter, r *http.Request) {
	result, err := h.service.ListShared(r.Context(), user(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	if result == nil {
		result = []domain.Shared{}
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) open(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	result, err := h.service.Open(r.Context(), user(r), id, clientIP(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	if result == nil {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) history(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	result, err := h.service.History(r.Context(), user(r), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	if result.Requests == nil {
		result.Requests = []domain.Request{}
	}
	if result.Views == nil {
		result.Views = []domain.View{}
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) decide(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	requestID, ok := pathID(w, r, "request_id")
	if !ok {
		return
	}
	var input struct {
		Decision string `json:"decision"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Decision != "approve" && input.Decision != "deny" {
		writeError(w, http.StatusBadRequest, "invalid_request", "decision должен быть approve или deny")
		return
	}
	result, err := h.service.Decide(r.Context(), user(r), id, requestID, input.Decision)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) revokeAccess(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	userID, ok := pathID(w, r, "user_id")
	if !ok {
		return
	}
	if err := h.service.RevokeAccess(r.Context(), user(r), id, userID); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := h.service.Revoke(r.Context(), user(r), id); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func clientIP(r *http.Request) string {
	if values := r.Header.Values("X-Real-IP"); len(values) == 1 {
		if ip := net.ParseIP(values[0]); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_request", "Проверьте название, текст и срок жизни секрета")
	case errors.Is(err, domain.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Объект не найден или срок его действия истёк")
	case errors.Is(err, domain.ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden", "Доступ запрещён")
	case errors.Is(err, domain.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "Запрос уже рассмотрен")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusGatewayTimeout, "timeout", "Время обработки запроса истекло")
	case errors.Is(err, context.Canceled):
		writeError(w, http.StatusServiceUnavailable, "unavailable", "Запрос отменён")
	default:
		h.logger.Error("secrets request failed")
		writeError(w, http.StatusInternalServerError, "internal_error", "Внутренняя ошибка")
	}
}

func writeError(w http.ResponseWriter, code int, kind, message string) {
	writeJSON(w, code, struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}{kind, message})
}
func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
