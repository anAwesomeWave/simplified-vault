# auth

Сервис учётных записей: регистрация, вход, выпуск JWT (RS256). Реализует ФТ-1…ФТ-3
из `Сервис_передачи_секретов_продуктовое_описание_и_архитектура.pdf`.

## API

| Ручка | Тело | Успех | Ошибки |
|---|---|---|---|
| `POST /auth/register` | `{"email","password"}` | `201 {"user_id"}` | `400` невалидный JSON/email, пароль < 10 символов (или > 1024 байт); `409` email занят |
| `POST /auth/login` | `{"email","password"}` | `200 {"access_token","token_type":"Bearer","expires_in":900}` | `400` невалидный JSON; `401` одинаковый ответ на неверный email и неверный пароль |

Ошибки: `{"error": "<код>", "message": "<описание>"}`.
Swagger UI: `GET /auth/docs`, спецификация: `GET /auth/openapi.yaml`.
`GET /healthz` — проверка БД; вне префикса `/auth/`, поэтому через gateway недоступна.

## Архитектура

Структура повторяет `cyberlocator/dashboard-backend-demo`. В корне фичи `internal/auth` лежит
слой изоляции: только интерфейсы. Реализации разложены по подпакетам и зависят друг от друга
лишь через эти интерфейсы.

```
cmd/auth/main.go                 конфиг, логгер, БД, миграции, сигналы → server.Run / Stop
internal/
  auth/                          контракты (слой изоляции)
    delivery.go                    Handler: Register(), Login(), Health() → http.HandlerFunc
    usecase.go                     UseCase: Register, Login, CheckHealth
    repository.go                  Repository: CreateUser, GetUserByEmail, Ping
    security.go                    PasswordHasher, TokenIssuer
    delivery/http/                 handler (NewHandler → auth.Handler), routes, middleware, Swagger
    usecase/                       authUC (NewAuthUC → auth.UseCase)
    repository/                    usersRepo на PostgreSQL (NewUsersRepo → auth.Repository)
    security/                      argon2id (NewArgon2idHasher), JWT RS256 (NewJWTIssuer)
  models/                        User, Email, политика пароля, тела запросов и ответов
  server_errors/                 все ошибки сервиса
  db/postgres/                   пул соединений к auth_db, миграции схемы
  server/                        сборка: security, repository → usecase → handler → http.Server
  utils/                         WriteJSONResponse, WriteJSONError
  config/                        env и файлы секретов
  archtest/                      тест правил зависимостей
```

- Конструкторы реализаций возвращают интерфейсы из `auth`, структуры не экспортируются.
- `delivery/http` знает только `auth.UseCase`, `usecase` знает `auth.Repository`,
  `auth.PasswordHasher` и `auth.TokenIssuer`. Реализации друг друга не импортируют.
- `repository` переводит ошибки pgx в `server_errors` (`23505` → `ErrEmailTaken`), так что
  SQL и драйвер не выходят за пределы слоя.
- Связывание выполняется только в `internal/server`.
- `internal/archtest` падает, если пакет импортирует то, что ему не положено. Например,
  `usecase` → `repository`, `delivery` → `usecase` или pgx в `usecase`.

## JWT

RS256, срок 15 минут, refresh-токенов нет. Claims:

```json
{"user_id": "<uuid>", "email": "anna@company.com", "sub": "<uuid>",
 "iss": "auth", "aud": ["secrets"], "iat": 0, "nbf": 0, "exp": 0, "jti": "<uuid>"}
```

Сервис secrets должен проверять: `alg == RS256` (жёстко, без доверия заголовку), подпись
публичным ключом `jwt_public_key`, `exp`, `iss == "auth"`, `aud` содержит `"secrets"`.

## Безопасность

- Пароли — argon2id (m=64 MiB, t=3, p=2, соль 16 байт), формат PHC; параметры берутся из
  хэша, так что их можно менять без миграции. Число одновременных вычислений ограничено
  числом CPU, чтобы поток логинов не съел память.
- Email нормализуется (trim + lower-case) — уникальность регистронезависимая, плюс
  уникальный индекс и CHECK в БД.
- Для несуществующего email логин всё равно считает argon2id по фиктивному хэшу:
  по времени ответа нельзя узнать, зарегистрирован ли адрес.
- Пароли, тела запросов и токены не логируются.
- Секреты читаются только из файлов (`/run/secrets/*`), не из переменных окружения.
- Rate limit на `/auth/login` — задача gateway (см. спецификацию).

## Конфигурация

| Переменная | По умолчанию |
|---|---|
| `HTTP_ADDR` | `:8000` |
| `LOG_LEVEL` | `info` |
| `DB_HOST` / `DB_PORT` | `postgres-auth` / `5432` |
| `DB_USER` / `DB_NAME` | `auth` / `auth_db` |
| `DB_SSLMODE` | `disable` (внутренняя сеть `auth-data`) |
| `DB_PASSWORD_FILE` | `/run/secrets/postgres_auth_password` |
| `JWT_PRIVATE_KEY_FILE` | `/run/secrets/jwt_private_key` (PEM, PKCS#1 или PKCS#8, RSA ≥ 2048) |
| `JWT_ISSUER` / `JWT_AUDIENCE` | `auth` / `secrets` |

Миграции встроены в бинарник и применяются при старте (идемпотентно, под advisory lock).

## Запуск

```bash
make secrets   # ./.secrets: jwt_private_key.pem, jwt_public_key.pem, postgres_auth_password
make up        # auth + postgres-auth, auth на 127.0.0.1:8000 (только для разработки)
curl -s localhost:8000/auth/register -d '{"email":"anna@company.com","password":"0123456789"}'
curl -s localhost:8000/auth/login    -d '{"email":"anna@company.com","password":"0123456789"}'
make down
```

`docker-compose.yml` здесь — для автономной разработки. В общем стеке auth подключается
только к сетям `gw-auth` и `auth-data`, без публикации порта; `jwt_public_key.pem`
отдаётся сервису secrets как Docker secret `jwt_public_key`.

## Тесты

```bash
make test
# интеграционный тест репозитория на реальном Postgres:
docker run --rm -d --name auth-it-pg -p 127.0.0.1:55432:5432 -e POSTGRES_PASSWORD=test postgres:17-alpine
AUTH_TEST_DB_HOST=127.0.0.1 AUTH_TEST_DB_PORT=55432 go test ./internal/auth/repository/...
```
