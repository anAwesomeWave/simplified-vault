#!/usr/bin/env bash
# Генерирует локальные Docker secrets для auth в ./.secrets (в .gitignore).
# Существующие файлы не перезаписываются, поэтому токены и БД остаются рабочими между запусками.
#
#   jwt_private_key.pem      -> Docker secret jwt_private_key (auth)
#   jwt_public_key.pem       -> Docker secret jwt_public_key  (gateway)
#   postgres_auth_password   -> Docker secret postgres_auth_password
set -euo pipefail

dir="${1:-$(dirname "$0")/../.secrets}"
mkdir -p "$dir"
chmod 700 "$dir"   # защищает файлы на хосте

if [[ ! -f "$dir/jwt_private_key.pem" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$dir/jwt_private_key.pem" 2>/dev/null
  rm -f "$dir/jwt_public_key.pem"
  echo "generated jwt_private_key.pem"
fi
if [[ ! -f "$dir/jwt_public_key.pem" ]]; then
  openssl pkey -in "$dir/jwt_private_key.pem" -pubout -out "$dir/jwt_public_key.pem"
  echo "generated jwt_public_key.pem"
fi
if [[ ! -f "$dir/postgres_auth_password" ]]; then
  openssl rand -base64 48 | tr -d '\n/+=' | head -c 40 > "$dir/postgres_auth_password"
  echo "generated postgres_auth_password"
fi

# docker compose монтирует файловые секреты с правами хоста; контейнер auth
# работает под uid 65532, поэтому файлы должны быть доступны на чтение всем.
# Каталог с правами 0700 выше закрывает их от других пользователей хоста.
chmod 644 "$dir"/*
