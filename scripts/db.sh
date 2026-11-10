#!/bin/sh
# Управление парой узлов secrets_db (primary + standby).
#   status   роли узлов и состояние репликации
#   primary  имя сервиса, который сейчас принимает запись
#   promote  переключение: standby становится primary, старый primary изолируется
#   rejoin   вернуть изолированный узел в кластер как standby
set -eu
cd "$(dirname "$0")/.."

COMPOSE=${COMPOSE:-docker compose}
NODES="postgres-secrets postgres-secrets-replica"

sql() { # sql <service> <query>
  $COMPOSE exec -T "$1" psql -U secrets -d secrets_db -X -At -c "$2"
}

role() { # primary | standby | down
  if [ -z "$($COMPOSE ps -q --status running "$1" 2>/dev/null)" ]; then
    echo down
  elif [ "$(sql "$1" 'SELECT pg_is_in_recovery()' 2>/dev/null)" = f ]; then
    echo primary
  elif [ "$(sql "$1" 'SELECT pg_is_in_recovery()' 2>/dev/null)" = t ]; then
    echo standby
  else
    echo down
  fi
}

find_role() { # first node with the given role
  for node in $NODES; do
    if [ "$(role "$node")" = "$1" ]; then
      echo "$node"
      return 0
    fi
  done
  return 1
}

case "${1:-status}" in
  status)
    for node in $NODES; do
      state=$(role "$node")
      printf '%-26s %s\n' "$node" "$state"
      case "$state" in
        primary)
          sql "$node" "SELECT '  -> standby ' || host(client_addr) || ': ' || state || ', ' || sync_state || ', отставание ' || pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) || ' байт' FROM pg_stat_replication" ;;
        standby)
          sql "$node" "SELECT '  <- WAL receiver: ' || coalesce((SELECT status FROM pg_stat_wal_receiver), 'нет соединения с primary') || ', применено до ' || coalesce(pg_last_wal_replay_lsn()::text, '-')" ;;
      esac
    done
    ;;
  primary)
    find_role primary || { echo 'нет работающего primary' >&2; exit 1; }
    ;;
  promote)
    new=$(find_role standby) || { echo 'нет работающего standby для переключения' >&2; exit 1; }
    for node in $NODES; do [ "$node" = "$new" ] || old=$node; done
    # Старый primary не должен принимать запись одновременно с новым.
    $COMPOSE stop "$old" >/dev/null 2>&1 || true
    echo "promote: $new становится primary"
    [ "$(sql "$new" 'SELECT pg_promote(true, 60)')" = t ] || { echo 'pg_promote не завершился' >&2; exit 1; }
    # Изоляция (fencing): данные старого primary сбрасываются, при следующем
    # запуске он клонирует новый primary. Иначе `make up` поднял бы второй
    # мастер с устаревшими данными (split-brain).
    echo "promote: $old изолирован, вернуть его в кластер: make db-rejoin"
    $COMPOSE run --rm --no-deps -T --entrypoint sh "$old" -c \
      'find "$PGDATA" -mindepth 1 -delete; touch "$PGDATA/.clone-from-peer"' >/dev/null
    ;;
  rejoin)
    $COMPOSE up -d --wait --wait-timeout 180 $NODES
    ;;
  *)
    echo "usage: $0 [status|primary|promote|rejoin]" >&2
    exit 2
    ;;
esac
