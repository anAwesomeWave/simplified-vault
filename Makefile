.DEFAULT_GOAL := help
COMPOSE ?= $(shell if docker compose version >/dev/null 2>&1; then echo 'docker compose'; else echo docker-compose; fi)
GO ?= go
SERVICES := gateway auth secrets notification

.PHONY: help init config build up down restart ps logs test smoke

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "%-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

init: ## Generate missing local keys, passwords, certificate and .env
	@sh scripts/init.sh

config: init ## Validate the unified Compose configuration
	$(COMPOSE) config --quiet

build: init ## Build all four application images
	$(COMPOSE) build

up: init ## Build and start all nine components, waiting for healthchecks
	$(COMPOSE) up -d --build --wait --wait-timeout 180

down: ## Stop the unified stack, preserving volumes and keys
	$(COMPOSE) down

restart: ## Restart the unified stack
	$(COMPOSE) restart

ps: ## Show all components and healthchecks
	$(COMPOSE) ps

logs: ## Follow logs; optionally pass SERVICE=gateway
	$(COMPOSE) logs -f $(SERVICE)

test: ## Run vet and race tests in each Go module
	@set -e; for service in $(SERVICES); do \
		(cd "$$service" && $(GO) vet ./... && env NOTIFICATION_IT_RABBITMQ_URL= $(GO) test -race ./...); \
	done

smoke: up ## Check real registration, secrets, access decisions and email delivery
	python3 scripts/smoke.py

