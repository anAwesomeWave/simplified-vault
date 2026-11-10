#!/bin/sh
# Обёртка над штатным entrypoint образа postgres для пары primary + standby.
#
# Узел клонирует соседа (pg_basebackup) и стартует как hot standby, если:
#   - его каталог данных пуст и INITIAL_ROLE=standby (первый запуск реплики);
#   - в каталоге лежит метка .clone-from-peer: её ставит `scripts/db.sh promote`
#     на старом primary, чтобы тот не поднялся вторым мастером (split-brain).
# Во всех остальных случаях управление сразу передаётся образу.
set -eu

PGDATA=${PGDATA:-/var/lib/postgresql/data}
marker="$PGDATA/.clone-from-peer"
peer=${PEER_HOST:?PEER_HOST is required}
role=${INITIAL_ROLE:-primary}

with_password() {
  PGPASSWORD=$(cat "$POSTGRES_PASSWORD_FILE") PGCONNECT_TIMEOUT=3 "$@"
}

peer_is_primary() {
  [ "$(with_password psql -h "$peer" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc 'SELECT pg_is_in_recovery()' 2>/dev/null)" = f ]
}

wipe() {
  find "$PGDATA" -mindepth 1 -delete
}

if [ -e "$marker" ] || { [ ! -s "$PGDATA/PG_VERSION" ] && [ "$role" = standby ]; }; then
  mkdir -p "$PGDATA"
  # Метка переживает перезапуск контейнера посреди клонирования.
  touch "$marker"
  echo "ha-entrypoint: waiting for primary $peer to clone from"
  until peer_is_primary; do sleep 2; done
  wipe
  chown postgres:postgres "$PGDATA"
  chmod 700 "$PGDATA"
  echo "ha-entrypoint: cloning $peer"
  # -R создаёт standby.signal и primary_conninfo; -X stream забирает WAL,
  # накопленный за время копирования.
  if ! with_password gosu postgres pg_basebackup -h "$peer" -U "$POSTGRES_USER" \
      -D "$PGDATA" -R -X stream -c fast; then
    echo "ha-entrypoint: clone failed, will retry" >&2
    wipe
    touch "$marker"
    exit 1
  fi
  echo "ha-entrypoint: clone complete, starting as standby"
fi

exec docker-entrypoint.sh "$@"
