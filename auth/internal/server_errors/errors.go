package server_errors

import "errors"

var (
	// ErrInvalidEmail - email не является корректным адресом
	ErrInvalidEmail = errors.New("email is not a valid address")
	// ErrPasswordTooShort - пароль короче models.MinPasswordLength символов (ФТ-1).
	// Число в тексте должно совпадать с константой, это проверяет тест в models
	ErrPasswordTooShort = errors.New("password must be at least 10 characters")
	// ErrPasswordTooLong - пароль длиннее models.MaxPasswordBytes байт
	ErrPasswordTooLong = errors.New("password must be at most 1024 bytes")
	// ErrEmailTaken - email уже зарегистрирован (ФТ-2)
	ErrEmailTaken = errors.New("email is already registered")
	// ErrUserNotFound - пользователя с таким email нет
	ErrUserNotFound = errors.New("user not found")
	// ErrInvalidCredentials - неверный email или пароль. Одна ошибка на оба случая,
	// чтобы не раскрывать, зарегистрирован ли адрес
	ErrInvalidCredentials = errors.New("invalid email or password")
)
