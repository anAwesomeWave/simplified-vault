#!/bin/sh
# Готовит узел кластера RabbitMQ: учётные данные и общий Erlang cookie берутся
# из файлов Docker secrets, список узлов - из RABBITMQ_CLUSTER_NODES.
set -eu
umask 077

password=$(cat /run/secrets/rabbitmq_password)
cookie=$(cat /run/secrets/rabbitmq_erlang_cookie)
for value in "$password" "$cookie"; do
  case "$value" in ''|*[!a-fA-F0-9]*) echo 'cluster-entrypoint: secrets must be hex strings' >&2; exit 1 ;; esac
done

{
  printf 'default_user = secrets\ndefault_pass = %s\n' "$password"
  # Узлы находят друг друга по заранее известному списку имён.
  echo 'cluster_formation.peer_discovery_backend = classic_config'
  index=1
  for node in ${RABBITMQ_CLUSTER_NODES:?RABBITMQ_CLUSTER_NODES is required}; do
    echo "cluster_formation.classic_config.nodes.$index = rabbit@$node"
    index=$((index + 1))
  done
  # При сетевом разделении меньшинство останавливается: двух «лидеров» не будет.
  echo 'cluster_partition_handling = pause_minority'
} > /etc/rabbitmq/secrets.conf
chown rabbitmq:rabbitmq /etc/rabbitmq/secrets.conf

# Узлы одного кластера обязаны иметь одинаковый cookie.
printf '%s' "$cookie" > /var/lib/rabbitmq/.erlang.cookie
chmod 600 /var/lib/rabbitmq/.erlang.cookie
chown rabbitmq:rabbitmq /var/lib/rabbitmq/.erlang.cookie
unset password cookie

export RABBITMQ_CONFIG_FILE=/etc/rabbitmq/secrets.conf
exec docker-entrypoint.sh rabbitmq-server
