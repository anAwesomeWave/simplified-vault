#!/usr/bin/env bash
# Генерирует локальные Docker secrets для notification в ./.secrets (в .gitignore).
# Существующие файлы не перезаписываются.
#
#   rabbitmq_password -> Docker secret rabbitmq_password (rabbitmq, secrets, notification)
set -euo pipefail

dir="${1:-$(dirname "$0")/../.secrets}"
mkdir -p "$dir"
chmod 700 "$dir"   # защищает файлы на хосте

if [[ ! -f "$dir/rabbitmq_password" ]]; then
  # Только [A-Za-z0-9]: пароль подставляется в AMQP URI и конфиг RabbitMQ
  openssl rand -base64 48 | tr -d '\n/+=' | head -c 40 > "$dir/rabbitmq_password"
  echo "generated rabbitmq_password"
fi

# docker compose монтирует файловые секреты с правами хоста; контейнер
# notification работает под uid 65532, поэтому файлы должны быть доступны на
# чтение всем. Каталог с правами 0700 выше закрывает их от других пользователей хоста.
chmod 644 "$dir"/*
