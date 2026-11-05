#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

# Run against the Compose network without publishing database or broker ports.
docker run --rm \
  --network "${COMPOSE_PROJECT_NAME:-simple-vault}_default" \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  --workdir /src --env CGO_ENABLED=0 \
  golang:1.26.4-alpine sh -ec '
    export TEST_DATABASE_URL="postgres://secrets:$(cat .secrets/postgres_password)@postgres:5432/secrets_db?sslmode=disable"
    export TEST_AMQP_URL="amqp://secrets:$(cat .secrets/rabbitmq_password)@rabbitmq:5672/%2F"
    export TEST_REDIS_ADDR=redis:6379 TEST_HTTP_URL=http://secrets:8000
    go test -count=1 -timeout=3m -v ./...
  '
