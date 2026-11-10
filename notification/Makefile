export GOTOOLCHAIN := local

.PHONY: build test it vet secrets up down logs

build:
	go build -o bin/notification ./cmd/notification

test:
	go test -race ./...

# Интеграционный тест consumer на RabbitMQ и Mailpit из docker-compose.yml (нужен `make up`)
it:
	NOTIFICATION_IT_RABBITMQ_URL="amqp://vault:$$(cat .secrets/rabbitmq_password)@127.0.0.1:5672/" \
	NOTIFICATION_IT_SMTP_ADDR=127.0.0.1:1025 \
	NOTIFICATION_IT_MAILPIT_URL=http://127.0.0.1:8025 \
	go test -race -count=1 -v -run Integration ./internal/notification/delivery/amqp/

vet:
	go vet ./...

secrets:
	./scripts/gen-secrets.sh

up: secrets
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f notification
