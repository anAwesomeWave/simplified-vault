package models

// Credentials - тело запросов POST /auth/register и POST /auth/login
type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterResponse - ответ POST /auth/register
type RegisterResponse struct {
	UserID string `json:"user_id"`
}

// AccessToken - ответ POST /auth/login
type AccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"` // секунды
}

// ErrorResponse - единый формат ошибок API из спецификации
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
