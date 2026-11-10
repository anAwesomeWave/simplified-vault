#!/bin/sh
# Восстановление базы из копии scripts/backup.sh:
#   scripts/restore.sh backups/secrets_db-20260101T000000Z.dump
# Имя файла определяет базу. Текущее содержимое базы заменяется содержимым копии.
set -eu
cd "$(dirname "$0")/.."

COMPOSE=${COMPOSE:-docker compose}
file=${1:?usage: restore.sh <backup file>}
[ -s "$file" ] || { echo "нет файла $file" >&2; exit 1; }

case "$(basename "$file")" in
  secrets_db-*.dump) db=secrets_db user=secrets service=$(COMPOSE="$COMPOSE" sh scripts/db.sh primary) ;;
  auth_db-*.dump)    db=auth_db user=auth service=postgres-auth ;;
  *) echo 'имя файла должно начинаться с secrets_db- или auth_db-' >&2; exit 1 ;;
esac

if [ -f "$file.sha256" ]; then
  echo '1/3 проверка контрольной суммы'
  (cd "$(dirname "$file")" && sha256sum -c --quiet "$(basename "$file").sha256")
else
  echo '1/3 контрольной суммы нет, проверка пропущена'
fi

echo "2/3 восстановление $db на узле $service"
# Одна транзакция: либо база целиком соответствует копии, либо не меняется.
$COMPOSE exec -T "$service" pg_restore -U "$user" -d "$db" \
  --clean --if-exists --single-transaction --exit-on-error < "$file"

if [ "$db" = secrets_db ]; then
  echo '3/3 сброс кэша Redis: в нём могли остаться данные новее копии'
  $COMPOSE restart redis > /dev/null
else
  echo '3/3 кэша у auth нет'
fi
echo "готово: $db восстановлена из $file"
