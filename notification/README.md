# notification

Сервис уведомлений: читает события из RabbitMQ и отправляет письма по SMTP (в стенде —
Mailpit). Реализует ФТ-13 и ФТ-17 и раздел «События» из
`Сервис_передачи_секретов_продуктовое_описание_и_архитектура.pdf`.

Сервис ни к кому не обращается по HTTP и не видит ни одной базы: всё нужное для письма
(адреса, название секрета, IP) secrets кладёт в событие сам. Входящих соединений нет.

## События

secrets публикует события в topic exchange `app.events`, ключ маршрутизации совпадает с
типом события. notification читает их из durable-очереди `notification.events`.

| Событие | Поля, кроме общих | Что делает notification |
|---|---|---|
| `secret.created` | `secret_id`, `owner_id`, `expires_at` | запись в лог |
| `access.requested` | `secret_id`, `title`, `request_id`, `requester_email`, `owner_email` | письмо автору: кто пытается открыть секрет, ссылка на `/secrets/{id}/requests` |
| `access.decided` | `secret_id`, `title`, `decision`, `requester_email` | письмо пользователю: решение и ссылка на `/secrets/{id}` |
| `secret.viewed` | `secret_id`, `title`, `viewer_email`, `ip`, `owner_email` | письмо автору: кто, когда (`occurred_at`) и с какого IP открыл |
| `access.revoked` | `secret_id`, `title`, `user_emails` | по письму каждому адресу из списка |

Общие поля: `event_id` (UUID), `type`, `occurred_at` (RFC 3339). `decision` принимается
как `approved`/`denied` или `approve`/`deny`. Пустой `user_emails` допустим (отозван
секрет без одобренных пользователей) — писем нет. Пример:

```json
{"event_id": "7f3e2a10-4c1b-4d7e-9a55-0b8e1f6c2d91", "type": "access.requested",
 "occurred_at": "2026-11-03T10:15:00Z", "secret_id": "c2a9e5d4-1f0b-4b8e-8d3a-6e7f9a1b2c3d",
 "title": "Доступ к админке CRM", "request_id": "41d0b6e2-9c7a-4f3e-b1d5-2a8c6e4f0b97",
 "requester_email": "ivan@company.com", "owner_email": "anna@company.com"}
```

### Что должен делать secrets при публикации

- Объявлять exchange с теми же параметрами: `app.events`, `topic`, durable, не auto-delete.
  Очередь `notification.events` объявляет только notification.
- Публиковать с `delivery_mode = 2` (persistent), иначе события пропадут при рестарте брокера.
- Не класть текст секрета ни в одно событие. notification в любом случае разбирает только
  известные поля, так что лишнее поле в письмо не попадёт.

## Доставка и подтверждение

- Сообщение подтверждается (`ack`) **только после отправки всех писем** по событию.
- Временные ошибки SMTP (сеть, таймаут, ответ 4xx) — повтор с паузой 1s → 2s → … → 30s,
  без ограничения числа попыток: пока SMTP лежит, сообщения ждут в durable-очереди.
  Уже отправленные письма `access.revoked` при повторе не переотправляются.
- Окончательные ошибки — битый JSON, нет обязательных полей, некорректный email или IP,
  неизвестный тип, ответ SMTP 5xx, паника в обработчике — `nack` без возврата в очередь:
  сообщение уходит через `notification.dlx` в `notification.events.dead`. Так одно битое
  событие не блокирует очередь и не теряется — его можно разобрать вручную.
- При остановке (SIGTERM) consumer перестаёт брать новые сообщения и до `DRAIN_TIMEOUT`
  дообрабатывает полученные; остальные возвращаются в очередь (`nack requeue`).
- При обрыве соединения с RabbitMQ — переподключение с паузой 1s → … → 30s.
- Гарантия «хотя бы один раз»: если сервис упадёт между отправкой письма и `ack`, после
  рестарта письмо уйдёт повторно. Дедупликации по `event_id` нет — у notification нет
  хранилища, а лишнее письмо безопаснее пропущенного.

## Безопасность

- В письмах только поля событий: название, адреса, IP, время, ссылки. Тест
  `TestSecretTextNeverInMail` проверяет, что даже поле `text` в событии в письмо не попадает.
- Email проверяется (`net/mail`, голый addr-spec, без CR/LF), название очищается от
  управляющих и невидимых символов и обрезается до 200 символов: через данные события
  нельзя внедрить SMTP-команды или заголовки (`Bcc:` и т.п.). Тема кодируется по RFC 2047,
  тело — quoted-printable.
- Ссылки строятся только из `PUBLIC_BASE_URL` и `secret_id`, проверенного как UUID.
- В лог пишутся `event_id`, тип, `secret_id`, число адресатов. Адреса и IP не пишутся.
- Тело сообщения ограничено 256 КБ, `user_emails` — 1000 адресами.
- Пароль RabbitMQ читается только из файла (`/run/secrets/rabbitmq_password`).
- Контейнер: distroless, non-root, `read_only`, `cap_drop: ALL`, `no-new-privileges`.
  `/healthz` слушает только `127.0.0.1:8000` внутри контейнера, для `HEALTHCHECK`.

## Архитектура

Та же схема, что в auth: в корне фичи `internal/notification` — только интерфейсы,
реализации в подпакетах, связывание в `internal/server`.

```
cmd/notification/main.go         конфиг, логгер, сигналы → server.Run / Stop; `healthcheck`
internal/
  notification/                  контракты (слой изоляции)
    delivery.go                    Consumer: Run, Ready
    usecase.go                     UseCase: Handle(body)
    mailer.go                      Mailer: Send(message)
    delivery/amqp/                 consumer: prefetch, воркеры, ack/nack, реконнект, drain
    usecase/                       разбор события → письма, повтор при временных ошибках, тексты писем
    mailer/smtp/                   SMTP-клиент: таймауты, STARTTLS, MIME, 4xx/5xx
  broker/rabbitmq/               подключение и топология (exchange, очередь, DLX, привязки)
  models/                        Event (разбор и проверка), Email, Message
  server_errors/                 ошибки и IsPermanent
  server/                        сборка: mailer → usecase → consumer, /healthz
  config/                        env и файлы секретов
```

Топология (объявляется идемпотентно при каждом подключении):

```
app.events (topic) ──[secret.created, access.requested, access.decided,
                      secret.viewed, access.revoked]──▶ notification.events
                                                          │ x-dead-letter-exchange
                                                          ▼
                              notification.dlx (fanout) ──▶ notification.events.dead
```

## Конфигурация

| Переменная | По умолчанию |
|---|---|
| `LOG_LEVEL` | `info` |
| `HEALTH_ADDR` | `127.0.0.1:8000` |
| `RABBITMQ_HOST` / `RABBITMQ_PORT` | `rabbitmq` / `5672` |
| `RABBITMQ_USER` / `RABBITMQ_VHOST` | `vault` / `/` |
| `RABBITMQ_PASSWORD_FILE` | `/run/secrets/rabbitmq_password` |
| `WORKERS` | `4` — параллельная обработка, он же prefetch |
| `DRAIN_TIMEOUT` | `10s` — дообработка при остановке |
| `SMTP_HOST` / `SMTP_PORT` | `mailpit` / `1025` |
| `SMTP_HELO` | `notification` |
| `SMTP_STARTTLS` | `false` — Mailpit во внутренней сети `mail` без TLS; `true` требует STARTTLS |
| `SMTP_TIMEOUT` | `30s` на одно письмо |
| `MAIL_FROM` | `Сервис передачи секретов <no-reply@vault.local>` |
| `PUBLIC_BASE_URL` | `https://localhost` — адрес gateway для ссылок в письмах |

## Запуск

```bash
make secrets   # ./.secrets/rabbitmq_password
make up        # notification + rabbitmq + mailpit
open http://127.0.0.1:8025     # Mailpit UI
open http://127.0.0.1:15672    # RabbitMQ UI, пользователь vault
make down
```

`docker-compose.yml` здесь — для автономной разработки: RabbitMQ и Mailpit дополнительно
подключены к сети `dev` и опубликованы на 127.0.0.1. В общем стеке notification подключается
только к сетям `events` (с rabbitmq и secrets) и `mail` (с mailpit), обе `internal: true`;
Docker secret `rabbitmq_password` — общий для rabbitmq, secrets и notification.

Официальный образ RabbitMQ больше не поддерживает `RABBITMQ_DEFAULT_PASS_FILE`, поэтому
entrypoint брокера читает пароль из Docker secret в окружение только процесса брокера —
в compose-файле и `docker inspect` его нет.

## Тесты

```bash
make test   # unit: разбор событий, тексты писем, повторы, SMTP против фейкового сервера
make up && make it   # интеграционный: настоящие RabbitMQ и Mailpit
```

Интеграционный тест проверяет: письмо приходит в Mailpit и сообщение подтверждается;
битые события уходят в DLQ; при недоступном SMTP сообщение не теряется при остановке
и доставляется после восстановления. Перед `make it` остановите контейнер notification
(`docker compose stop notification`), иначе он заберёт часть сообщений теста.
