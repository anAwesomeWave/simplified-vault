#!/usr/bin/env python3
"""Reliability demos against the running stack: db | mq | backup.

Each scenario goes through the public gateway like a real client and prints
the measured recovery time, which docs/reliability.md refers to.
"""
import json
import os
from pathlib import Path
import shlex
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = shlex.split(os.getenv("COMPOSE", "docker compose"))
MQ_NODES = ["rabbitmq-1", "rabbitmq-2", "rabbitmq-3"]
QUEUE = "notification.events"


def settings():
    values = {}
    if (ROOT / ".env").exists():
        for line in (ROOT / ".env").read_text().splitlines():
            if line.strip() and not line.lstrip().startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip("\"'")
    return values


ENV = settings()
BASE = (os.getenv("PUBLIC_BASE_URL") or ENV.get("PUBLIC_BASE_URL", "https://localhost")).rstrip("/")
MAILPIT = "http://127.0.0.1:" + os.getenv("MAILPIT_PORT", ENV.get("MAILPIT_PORT", "8025"))
TLS = ssl.create_default_context(cafile=str(ROOT / ".secrets/tls_certificate.pem"))


def step(text):
    print(f"\n=== {text}", flush=True)


def run(*args, check=True, quiet=False):
    """Run a command from the repository root, echoing it and its output."""
    if not quiet:
        print("$ " + " ".join(args), flush=True)
    result = subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if not quiet and result.stdout.strip():
        print(result.stdout.rstrip(), flush=True)
    if check and result.returncode != 0:
        if quiet:
            print(result.stdout.rstrip(), file=sys.stderr)
        raise SystemExit(f"FAIL команда завершилась с кодом {result.returncode}: {' '.join(args)}")
    return result.stdout


def compose(*args, **kwargs):
    return run(*COMPOSE, *args, **kwargs)


def api(method, path, token=None, body=None, base=BASE):
    """Return (HTTP status, decoded JSON or None); status 0 means no response."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(request, context=TLS, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    except (urllib.error.URLError, OSError):
        return 0, None
    with response:
        raw = response.read()
        try:
            return response.status, json.loads(raw) if raw else None
        except ValueError:
            return response.status, None


def expect(result, status, what):
    if result[0] != status:
        raise SystemExit(f"FAIL {what}: ожидался HTTP {status}, получен {result[0]}")
    return result[1]


def new_user():
    suffix = uuid.uuid4().hex[:12]
    email, password = f"demo-{suffix}@example.test", "demo-password-" + suffix
    expect(api("POST", "/auth/register", body={"email": email, "password": password}), 201, "регистрация")
    token = expect(api("POST", "/auth/login", body={"email": email, "password": password}), 200, "вход")["access_token"]
    print(f"пользователь {email} зарегистрирован и вошёл")
    return token


def create_secret(token, label):
    title, text = f"Demo-{label}-{uuid.uuid4().hex[:8]}", "demo-value-" + uuid.uuid4().hex
    secret = expect(api("POST", "/secrets", token, {"title": title, "text": text, "ttl_seconds": 3600}), 201, "создание секрета")
    print(f"секрет «{title}» создан: {secret['id']}")
    return secret["id"], title, text


def read_secret(token, secret_id, text):
    body = expect(api("GET", "/secrets/" + secret_id, token), 200, "чтение секрета")
    if body["text"] != text:
        raise SystemExit("FAIL текст секрета не совпал с исходным")
    print(f"секрет {secret_id} прочитан, текст совпадает")


def delete_secret(token, secret_id):
    api("DELETE", "/secrets/" + secret_id, token)


def mail_count(title):
    query = urllib.parse.quote(f'subject:"{title}"')
    status, body = api("GET", "/api/v1/search?query=" + query, base=MAILPIT)
    return len(body["messages"]) if status == 200 else 0


def wait_mail(title, count, timeout=120):
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if mail_count(title) >= count:
            return time.monotonic() - started
        time.sleep(0.5)
    raise SystemExit(f"FAIL письмо №{count} по секрету «{title}» не пришло за {timeout} с")


def demo_db():
    step("1. Исходное состояние: primary принимает запись, standby получает WAL")
    run("sh", "scripts/db.sh", "status")
    old = run("sh", "scripts/db.sh", "primary", quiet=True).strip()
    token = new_user()
    secret_id, _, text = create_secret(token, "db")
    read_secret(token, secret_id, text)
    time.sleep(2)  # Асинхронная репликация: даём standby получить запись.

    step(f"2. Некорректное завершение primary: SIGKILL контейнера {old}")
    compose("kill", "-s", "SIGKILL", old)
    failed_at = time.monotonic()
    run("sh", "scripts/db.sh", "status")

    step("3. До переключения запись недоступна (standby работает только на чтение)")
    status, _ = api("POST", "/secrets", token, {"title": "Demo-no-primary", "text": "value", "ttl_seconds": 3600})
    if 200 <= status < 500:
        raise SystemExit(f"FAIL без primary ожидалась ошибка сервера, получен HTTP {status}")
    print(f"POST /secrets -> HTTP {status}")

    step("4. Переключение на standby")
    run("sh", "scripts/db.sh", "promote")
    while True:
        status, body = api("POST", "/secrets", token, {"title": "Demo-after-failover", "text": "after", "ttl_seconds": 3600})
        if status == 201:
            break
        if time.monotonic() - failed_at > 120:
            raise SystemExit("FAIL сервис не восстановился за 120 с после переключения")
        time.sleep(0.5)
    downtime = time.monotonic() - failed_at
    print("POST /secrets -> HTTP 201: запись снова работает")
    run("sh", "scripts/db.sh", "status")

    step("5. Данные, записанные до отказа, сохранились")
    read_secret(token, secret_id, text)

    step(f"6. Возврат узла {old} в кластер как standby")
    run("sh", "scripts/db.sh", "rejoin", quiet=True)
    time.sleep(2)
    run("sh", "scripts/db.sh", "status")

    delete_secret(token, secret_id)
    delete_secret(token, body["id"])
    print(f"\nPASS переключение СУБД; запись была недоступна {downtime:.1f} с (от SIGKILL до первого успешного POST)")


def mq_exec(node, *args, **kwargs):
    return compose("exec", "-T", node, *args, **kwargs)


def live_mq_node():
    running = compose("ps", "--status", "running", "--services", quiet=True).split()
    return next(node for node in MQ_NODES if node in running)


def mq_leader():
    rows = json.loads(mq_exec(live_mq_node(), "rabbitmqctl", "-q", "--formatter", "json",
                              "list_queues", "name", "type", "leader", "online", quiet=True))
    row = next(item for item in rows if item["name"] == QUEUE)
    if row["type"] != "quorum":
        raise SystemExit(f"FAIL очередь {QUEUE} имеет тип {row['type']}, а не quorum")
    leader = row["leader"].split("@", 1)[1]
    online = sorted(member.split("@", 1)[1] for member in row["online"])
    return leader, online


def show_quorum(node):
    print(f"$ rabbitmq-queues quorum_status {QUEUE}   (узел {node})")
    rows = json.loads(mq_exec(node, "rabbitmq-queues", "-q", "--formatter", "json", "quorum_status", QUEUE, quiet=True))
    for row in rows:
        print(f"{row['Node Name']:<20} {row['Raft State']:<10} журнал до {row['Last Log Index']}, применено до {row['Last Applied']}, срок {row['Term']}")


def wait_mq_leader(exclude=None, members=None, timeout=90):
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        try:
            leader, online = mq_leader()
            if leader and leader != exclude and (members is None or len(online) == members):
                return leader, online
        except (SystemExit, StopIteration, ValueError, KeyError, IndexError):
            pass
        time.sleep(1)
    raise SystemExit("FAIL кластер RabbitMQ не пришёл в ожидаемое состояние")


def demo_mq():
    step("1. Исходное состояние: три узла, quorum-очередь с лидером и двумя репликами")
    leader, online = wait_mq_leader(members=3)
    show_quorum(leader)
    print(f"лидер очереди {QUEUE}: {leader}; реплики в сети: {', '.join(online)}")
    token = new_user()
    secret_id, title, text = create_secret(token, "mq")
    read_secret(token, secret_id, text)
    print(f"письмо о чтении пришло через {wait_mail(title, 1):.1f} с")

    step(f"2. Некорректное завершение узла-лидера: SIGKILL контейнера {leader}")
    compose("kill", "-s", "SIGKILL", leader)
    failed_at = time.monotonic()

    step("3. API продолжает работать, событие доставляется через оставшиеся узлы")
    read_secret(token, secret_id, text)
    wait_mail(title, 2)
    delay = time.monotonic() - failed_at
    print(f"второе письмо пришло через {delay:.1f} с после отказа лидера")
    new_leader, online = wait_mq_leader(exclude=leader)
    print(f"новый лидер очереди: {new_leader}; реплики в сети: {', '.join(online)}")

    step(f"4. Возврат узла {leader}: он догоняет журнал очереди как реплика")
    compose("start", leader)
    new_leader, online = wait_mq_leader(members=3, timeout=180)
    show_quorum(new_leader)
    if mail_count(title) != 2:
        raise SystemExit("FAIL после возврата узла письма потерялись или продублировались")

    delete_secret(token, secret_id)
    print(f"\nPASS отказ лидера RabbitMQ; уведомление доставлено через {delay:.1f} с, сообщения не потеряны")


def demo_backup():
    step("1. Данные до резервного копирования")
    token = new_user()
    secret_id, _, text = create_secret(token, "backup")
    read_secret(token, secret_id, text)

    step("2. Резервное копирование")
    before = set((ROOT / "backups").glob("secrets_db-*.dump")) if (ROOT / "backups").exists() else set()
    run("sh", "scripts/backup.sh")
    created = sorted(set((ROOT / "backups").glob("secrets_db-*.dump")) - before)
    if not created:
        raise SystemExit("FAIL резервная копия не появилась")
    backup = created[-1].relative_to(ROOT)

    step("3. Потеря данных: TRUNCATE (репликация повторит его и на standby)")
    primary = run("sh", "scripts/db.sh", "primary", quiet=True).strip()
    compose("exec", "-T", primary, "psql", "-U", "secrets", "-d", "secrets_db", "-c", "TRUNCATE secrets CASCADE")
    compose("restart", "redis", quiet=True)
    expect(api("GET", "/secrets/" + secret_id, token), 404, "чтение удалённого секрета")
    print(f"GET /secrets/{secret_id} -> HTTP 404: секрет потерян")

    step(f"4. Восстановление из {backup}")
    started = time.monotonic()
    run("sh", "scripts/restore.sh", str(backup))
    while api("GET", "/secrets/" + secret_id, token)[0] != 200:
        if time.monotonic() - started > 120:
            raise SystemExit("FAIL секрет не читается после восстановления")
        time.sleep(0.5)
    elapsed = time.monotonic() - started

    step("5. Данные вернулись")
    read_secret(token, secret_id, text)
    delete_secret(token, secret_id)
    print(f"\nPASS резервное копирование и восстановление; восстановление заняло {elapsed:.1f} с")


if __name__ == "__main__":
    demos = {"db": demo_db, "mq": demo_mq, "backup": demo_backup}
    if len(sys.argv) != 2 or sys.argv[1] not in demos:
        raise SystemExit("usage: reliability_demo.py db|mq|backup")
    demos[sys.argv[1]]()
