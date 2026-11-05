#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p .secrets
chmod 700 .secrets
if [ ! -f .secrets/master_key ]; then
  openssl rand -out .secrets/master_key 32
fi
for name in postgres_password rabbitmq_password; do
  if [ ! -f ".secrets/$name" ]; then
    openssl rand -hex 32 > ".secrets/$name"
  fi
done
# Compose mounts files as-is; the container runs without root.
chmod 444 .secrets/master_key .secrets/postgres_password .secrets/rabbitmq_password
if [ ! -f .env ]; then
  cp .env.example .env
fi
