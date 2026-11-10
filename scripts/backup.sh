#!/bin/sh
# Полная логическая резервная копия (pg_dump, custom format) обеих баз.
# Шаги повторяют процедуру резервного копирования: проверка возможности ->
# копирование -> проверка статуса -> перемещение -> проверка копии ->
# пробное восстановление -> политика хранения.
#
#   BACKUP_DIR  каталог копий (по умолчанию ./backups)
#   KEEP        сколько последних копий каждой базы хранить (по умолчанию 7)
set -eu
cd "$(dirname "$0")/.."
umask 077

COMPOSE=${COMPOSE:-docker compose}
BACKUP_DIR=${BACKUP_DIR:-backups}
KEEP=${KEEP:-7}
stamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$BACKUP_DIR"

backup() { # backup <service> <user> <database>
  service=$1 user=$2 db=$3
  file="$BACKUP_DIR/$db-$stamp.dump"
  check_db="restore_check_$(echo "$stamp" | tr 'A-Z' 'a-z')"
  echo "== $db (узел $service)"

  echo '1/6 проверка доступности базы'
  $COMPOSE exec -T "$service" pg_isready -q -U "$user" -d "$db"

  echo '2/6 копирование: pg_dump -Fc'
  if ! $COMPOSE exec -T "$service" pg_dump -U "$user" -d "$db" -Fc > "$file.partial" || [ ! -s "$file.partial" ]; then
    rm -f "$file.partial"
    echo "pg_dump для $db завершился с ошибкой" >&2
    return 1
  fi

  echo '3/6 перемещение копии и контрольная сумма'
  mv "$file.partial" "$file"
  (cd "$BACKUP_DIR" && sha256sum "$(basename "$file")" > "$(basename "$file").sha256")

  echo '4/6 проверка копии: pg_restore --list'
  $COMPOSE exec -T "$service" pg_restore --list < "$file" > /dev/null

  echo '5/6 пробное восстановление во временную базу'
  $COMPOSE exec -T "$service" createdb -U "$user" "$check_db"
  restored=''
  if $COMPOSE exec -T "$service" pg_restore -U "$user" -d "$check_db" --exit-on-error < "$file"; then
    restored=$($COMPOSE exec -T "$service" psql -U "$user" -d "$check_db" -X -At -c \
      "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")
  fi
  $COMPOSE exec -T "$service" dropdb -U "$user" "$check_db"
  expected=$($COMPOSE exec -T "$service" psql -U "$user" -d "$db" -X -At -c \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")
  if [ -z "$restored" ] || [ "$restored" != "$expected" ]; then
    echo "пробное восстановление $db не удалось: таблиц ${restored:-0} из $expected" >&2
    return 1
  fi

  echo "6/6 политика хранения: последние $KEEP копий"
  ls -1 "$BACKUP_DIR" | grep "^$db-.*\.dump$" | sort -r | tail -n "+$((KEEP + 1))" | while read -r stale; do
    rm -f "$BACKUP_DIR/$stale" "$BACKUP_DIR/$stale.sha256"
  done
  echo "готово: $file ($(wc -c < "$file" | tr -d ' ') байт, таблиц: $restored)"
}

# Копия снимается с узла, который сейчас принимает запись.
backup "$(COMPOSE="$COMPOSE" sh scripts/db.sh primary)" secrets secrets_db
backup postgres-auth auth auth_db
