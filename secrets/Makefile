.DEFAULT_GOAL := help
COMPOSE ?= $(shell if docker compose version >/dev/null 2>&1; then echo 'docker compose'; else echo docker-compose; fi)
GO ?= go

.PHONY: help init build run test integration check up down logs config

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "%-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

init: ## Generate local key/password files and .env without overwriting
	@sh scripts/init.sh

build: ## Build bin/secrets
	@mkdir -p bin
	$(GO) build -trimpath -o bin/secrets ./cmd/secrets

run: ## Run with environment configured by the caller
	$(GO) run ./cmd/secrets

test: ## Run tests with the race detector
	$(GO) test -race ./...

integration: up ## Run all tests against the real Compose infrastructure
	@sh scripts/integration.sh

check: ## Check formatting, static analysis and tests
	@test -z "$$(gofmt -l api cmd internal)" || { gofmt -l api cmd internal; exit 1; }
	$(GO) vet ./...
	$(GO) test -race ./...

up: init ## Build and start service and dependencies
	$(COMPOSE) up -d --build --wait

down: ## Stop stack, preserving database and broker volumes
	$(COMPOSE) down

logs: ## Follow service logs
	$(COMPOSE) logs -f secrets

config: ## Validate Compose configuration
	$(COMPOSE) config --quiet

