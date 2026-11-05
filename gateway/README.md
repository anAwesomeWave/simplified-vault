API gateway на Go для `simple-vault`: проверка JWT, проксирование и ограничение
частоты входа. Баз данных и других зависимостей у gateway нет.

| Маршрут | Поведение |
| --- | --- |
| `POST /auth/register` | Передача запроса в `AUTH_URL` без JWT |
| `POST /auth/login` | Передача в `AUTH_URL`, по умолчанию не более 5 запросов в минуту с IP; затем 429 |
| Восемь операций `/secrets` | Проверка JWT и передача в `SECRETS_URL` |
| Остальное | 404 |

Gateway принимает `Authorization: Bearer <JWT>` с подписью RS256, действующим `exp`,
ненулевым `user_id` (UUID) и email без отображаемого имени. Публичный RSA-ключ auth
должен быть не короче 2048 бит. Gateway удаляет клиентские `X-User-ID`,
`X-User-Email`, `X-Real-IP` и устанавливает их из проверенной личности и IP соединения.
Заголовок `Authorization` в secrets не передаётся. IP из присланных клиентом
`Forwarded` / `X-Forwarded-For` не используется для идентификации и ограничения входа.
Ошибки gateway имеют JSON-формат `{"error":"<код>","message":"<описание>"}`;
ошибки и успешные ответы upstream передаются клиенту.

Каталог `auth/` пока пуст: auth-сервис здесь не реализован. Gateway передаёт запросы
на настроенный `AUTH_URL`; для регистрации и входа нужен работающий внешний auth,
который подписывает JWT соответствующим приватным ключом. Ключи gateway не генерирует.

Для Compose нужны Docker с Compose v2 и уже существующая сеть backend
(`simple-vault_default` создаётся стеком `secrets/compose.yaml`). Передайте публичный
ключ работающего auth, доступный для чтения UID 65532 внутри контейнера:

```sh
cd gateway
cp .env.example .env
mkdir -p .secrets
chmod 700 .secrets
cp /path/to/auth-public.pem .secrets/jwt_public_key
chmod 444 .secrets/jwt_public_key
make up
```

По умолчанию gateway доступен на `http://127.0.0.1:8080`; Compose запускает только его
и подключает к внешней сети. Настройте `.env`, если адреса upstream или сеть отличаются.
`AUTH_URL` и `SECRETS_URL` — HTTP(S) origin, без пути, query, fragment и credentials.
Публичный ключ подключается Docker secret из `JWT_PUBLIC_KEY_PATH`.

```sh
curl http://127.0.0.1:8080/secrets -H "Authorization: Bearer $TOKEN"
```

В рабочем развёртывании публикуется только gateway; доступ к secrets разрешён ему
по внутренней сети. Порт `127.0.0.1:8000` в текущем Compose secrets предназначен для
отладки и должен быть отключён при таком развёртывании.
В конфигурации secrets задайте `PUBLIC_BASE_URL` внешним адресом gateway
(например, `http://localhost:8080`), чтобы ссылки на созданные секреты вели через него.

Для прямого HTTPS задайте вместе `TLS_CERT_FILE` и `TLS_KEY_FILE` — пути к сертификату
и приватному ключу, подключённым в контейнер как Docker secrets. Файлы должны читаться
UID 65532. Публикуйте `443:8000` вместо локального отладочного порта. По умолчанию
Compose использует HTTP; сертификаты, TLS-ключи и nginx здесь не создаются.

`make build` собирает `bin/gateway`; `make run` запускает с окружением вызывающего;
`make check` проверяет форматирование, `go vet` и тесты с `-race`.
Сквозной тест с запущенным secrets: `TEST_SECRETS_URL=http://127.0.0.1:8000 go test -race -count=1 ./...`.
Он использует тестовый auth-upstream, проверяет все восемь операций secrets через JWT-gateway
и удаляет созданный секрет; без переменной окружения этот тест пропускается.
`make logs`, `make down`, `make config` — логи, остановка и проверка Compose.
Go требует версии 1.26+. При SIGINT/SIGTERM HTTP-запросам даётся до 15 секунд
на завершение; Compose ожидает контейнер до 20 секунд.

Swagger UI сервиса secrets описывает внутренние заголовки gateway → secrets,
а внешний клиент передаёт gateway только Bearer JWT.
