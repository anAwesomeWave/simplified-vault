package utils

import (
	"encoding/json"
	"net/http"

	"github.com/anAwesomeWave/simplified-vault/auth/internal/models"
)

// WriteJSONResponse пишет ответ со статусом status и телом v в JSON
func WriteJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteJSONError пишет ошибку в едином формате {"error": "<код>", "message": "<описание>"}
func WriteJSONError(w http.ResponseWriter, status int, code, message string) {
	WriteJSONResponse(w, status, models.ErrorResponse{Error: code, Message: message})
}
