package auth

import (
	"net/http"
)

type Handler interface {
	Register() http.HandlerFunc
	Login() http.HandlerFunc
	Health() http.HandlerFunc
}
