#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p .secrets
chmod 700 .secrets

private=.secrets/jwt_private_key.pem
public=.secrets/jwt_public_key.pem
if [ ! -f "$private" ]; then
  if [ -f "$public" ]; then
    echo 'Restore jwt_private_key.pem: an existing public key will not be replaced.' >&2
    exit 1
  fi
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$private" 2>/dev/null
fi
derived=$(mktemp .secrets/public.XXXXXX)
trap 'rm -f "$derived"' EXIT HUP INT TERM
openssl pkey -in "$private" -pubout -out "$derived"
if [ -f "$public" ]; then
  actual=$(openssl pkey -pubin -in "$public" -pubout)
  expected=$(cat "$derived")
  if [ "$actual" != "$expected" ]; then
    echo 'JWT private and public keys do not match; existing files were preserved.' >&2
    exit 1
  fi
else
  cp "$derived" "$public"
fi

if [ ! -f .secrets/master_key ]; then
  openssl rand -out .secrets/master_key 32
fi
if [ "$(wc -c < .secrets/master_key | tr -d ' ')" != 32 ]; then
  echo 'master_key must contain exactly 32 raw bytes.' >&2
  exit 1
fi
for name in postgres_auth_password postgres_secrets_password rabbitmq_password rabbitmq_erlang_cookie; do
  if [ ! -f ".secrets/$name" ]; then
    openssl rand -hex 32 > ".secrets/$name"
  fi
  if [ ! -s ".secrets/$name" ]; then
    echo "$name must not be empty." >&2
    exit 1
  fi
done

certificate=.secrets/tls_certificate.pem
tls_key=.secrets/tls_private_key.pem
if [ ! -f "$certificate" ] && [ ! -f "$tls_key" ]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
    -keyout "$tls_key" -out "$certificate" -subj /CN=localhost \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>/dev/null
elif [ ! -f "$certificate" ] || [ ! -f "$tls_key" ]; then
  echo 'Restore the missing TLS certificate/key; existing files were preserved.' >&2
  exit 1
fi
# Compose bind-mounts secret files as-is; applications run as UID 65532.
# The containing host directory remains private (0700).
chmod 444 "$private" "$public" .secrets/master_key \
  .secrets/postgres_auth_password .secrets/postgres_secrets_password \
  .secrets/rabbitmq_password .secrets/rabbitmq_erlang_cookie "$certificate" "$tls_key"
if [ ! -f .env ]; then
  cp .env.example .env
fi
