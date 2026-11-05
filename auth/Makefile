export GOTOOLCHAIN := local

.PHONY: build test vet secrets up down logs

build:
	go build -o bin/auth ./cmd/auth

test:
	go test -race ./...

vet:
	go vet ./...

secrets:
	./scripts/gen-secrets.sh

up: secrets
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f auth
