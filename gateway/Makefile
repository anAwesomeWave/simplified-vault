.DEFAULT_GOAL := help
COMPOSE ?= $(shell if docker compose version >/dev/null 2>&1; then echo 'docker compose'; else echo docker-compose; fi)
GO ?= go

.PHONY: help build run check up down logs config

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "%-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build bin/gateway
	@mkdir -p bin
	$(GO) build -trimpath -o bin/gateway ./cmd/gateway

run: ## Run with environment configured by the caller
	$(GO) run ./cmd/gateway

check: ## Check formatting, static analysis and tests
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }
	$(GO) vet ./...
	$(GO) test -race ./...

up: ## Build and start gateway
	$(COMPOSE) up -d --build --wait

down: ## Stop gateway
	$(COMPOSE) down

logs: ## Follow gateway logs
	$(COMPOSE) logs -f gateway

config: ## Validate Compose configuration
	$(COMPOSE) config --quiet
