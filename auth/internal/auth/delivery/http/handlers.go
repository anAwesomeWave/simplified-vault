package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/auth"
	"github.com/anAwesomeWave/simplified-vault/auth/internal/models"
	serverErrors "github.com/anAwesomeWave/simplified-vault/auth/internal/server_errors"
	"github.com/anAwesomeWave/simplified-vault/auth/internal/utils"
)

// maxBodyBytes - максимальный размер тела запроса
const maxBodyBytes = 16 << 10

// healthTimeout - сколько ждём ответа БД в /healthz
const healthTimeout = 2 * time.Second

// errorMapping сопоставляет ошибки из server_errors с HTTP-ответами.
// Всё, чего нет в таблице, - внутренняя ошибка (500)
var errorMapping = []struct {
	err    error
	status int
	code   string
}{
	{serverErrors.ErrInvalidEmail, http.StatusBadRequest, "invalid_email"},
	{serverErrors.ErrPasswordTooShort, http.StatusBadRequest, "password_too_short"},
	{serverErrors.ErrPasswordTooLong, http.StatusBadRequest, "password_too_long"},
	{serverErrors.ErrEmailTaken, http.StatusConflict, "email_taken"},
	{serverErrors.ErrInvalidCredentials, http.StatusUnauthorized, "invalid_credentials"},
}

type handler struct {
	log *slog.Logger
	uc  auth.UseCase
}

func NewHandler(uc auth.UseCase, log *slog.Logger) auth.Handler {
	return &handler{
		log: log,
		uc:  uc,
	}
}

// Register - POST /auth/register: 201 {"user_id"}, 400 невалидный email или пароль, 409 email занят
func (h *handler) Register() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request models.Credentials
		if !decodeJSON(w, r, &request) {
			return
		}

		userID, err := h.uc.Register(r.Context(), request)
		if err != nil {
			h.fail(w, r, "register", err)
			return
		}

		utils.WriteJSONResponse(w, http.StatusCreated, models.RegisterResponse{UserID: userID.String()})
	}
}

// Login - POST /auth/login: 200 {"access_token", "expires_in"}, 401 одинаковый на неверный email и пароль
func (h *handler) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request models.Credentials
		if !decodeJSON(w, r, &request) {
			return
		}

		token, err := h.uc.Login(r.Context(), request)
		if err != nil {
			h.fail(w, r, "login", err)
			return
		}

		// токен не должен оседать в кэшах
		w.Header().Set("Cache-Control", "no-store")
		utils.WriteJSONResponse(w, http.StatusOK, token)
	}
}

// Health - GET /healthz: 200, если БД доступна, иначе 503
func (h *handler) Health() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
		defer cancel()

		if err := h.uc.CheckHealth(ctx); err != nil {
			h.log.Warn("health check failed", slog.String("error", err.Error()))
			utils.WriteJSONError(w, http.StatusServiceUnavailable, "unavailable", "database is unavailable")
			return
		}

		utils.WriteJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// fail пишет ответ для ошибки usecase. Подробности внутренних ошибок попадают
// только в лог, клиенту уходит общий текст
func (h *handler) fail(w http.ResponseWriter, r *http.Request, op string, err error) {
	for _, m := range errorMapping {
		if errors.Is(err, m.err) {
			utils.WriteJSONError(w, m.status, m.code, m.err.Error())
			return
		}
	}
	if errors.Is(err, context.Canceled) {
		// клиент отключился, отправлять нечего
		return
	}
	h.log.Error("request failed",
		slog.String("op", op), slog.String("error", err.Error()), slog.String("request_id", requestID(r)))
	utils.WriteJSONError(w, http.StatusInternalServerError, "internal_error", "internal server error")
}

// decodeJSON читает один JSON-объект размером не больше maxBodyBytes.
// При ошибке пишет 400 (или 413) и возвращает false
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			utils.WriteJSONError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large")
			return false
		}
		utils.WriteJSONError(w, http.StatusBadRequest, "invalid_json", "request body must be a JSON object")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		utils.WriteJSONError(w, http.StatusBadRequest, "invalid_json", "request body must contain a single JSON object")
		return false
	}
	return true
}
