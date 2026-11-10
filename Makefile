.DEFAULT_GOAL := help
COMPOSE ?= $(shell if docker compose version >/dev/null 2>&1; then echo 'docker compose'; else echo docker-compose; fi)
GO ?= go
SERVICES := gateway auth secrets notification

.PHONY: help init config build up down restart ps logs test smoke \
	db-status db-promote db-rejoin backup restore demo-db-failover demo-mq-failover demo-backup

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "%-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

init: ## Generate missing local keys, passwords, certificate and .env
	@sh scripts/init.sh

config: init ## Validate the unified Compose configuration
	$(COMPOSE) config --quiet

build: init ## Build all four application images
	$(COMPOSE) build

up: init ## Build and start all twelve components, waiting for healthchecks
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


db-status: ## Show secrets_db node roles and replication state
	@COMPOSE='$(COMPOSE)' sh scripts/db.sh status

db-promote: ## Fail over secrets_db: promote the standby and fence the old primary
	@COMPOSE='$(COMPOSE)' sh scripts/db.sh promote

db-rejoin: ## Return the fenced secrets_db node to the cluster as a standby
	@COMPOSE='$(COMPOSE)' sh scripts/db.sh rejoin

backup: ## Dump both databases into backups/ with verification and retention
	@COMPOSE='$(COMPOSE)' sh scripts/backup.sh

restore: ## Restore a database from a dump: make restore FILE=backups/secrets_db-....dump
	@COMPOSE='$(COMPOSE)' sh scripts/restore.sh '$(FILE)'

demo-db-failover: ## Demo: kill the secrets_db primary, promote the standby, rejoin
	@COMPOSE='$(COMPOSE)' python3 scripts/reliability_demo.py db

demo-mq-failover: ## Demo: kill the RabbitMQ queue leader, deliver through the rest
	@COMPOSE='$(COMPOSE)' python3 scripts/reliability_demo.py mq

demo-backup: ## Demo: back up, lose data, restore from the backup
	@COMPOSE='$(COMPOSE)' python3 scripts/reliability_demo.py backup
