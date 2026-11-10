#!/usr/bin/env python3
"""Exercise the deployed gateway, auth, secrets and notification through real APIs."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[1]


def settings():
    values = {}
    if (ROOT / ".env").exists():
        for line in (ROOT / ".env").read_text().splitlines():
            if line.strip() and not line.lstrip().startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip("\"'")
    return values


class Smoke:
    def __init__(self):
        env = settings()
        self.base = (os.getenv("SMOKE_BASE_URL") or os.getenv("PUBLIC_BASE_URL") or env.get("PUBLIC_BASE_URL", "https://localhost")).rstrip("/")
        self.mailpit = os.getenv("SMOKE_MAILPIT_URL", "http://127.0.0.1:" + os.getenv("MAILPIT_PORT", env.get("MAILPIT_PORT", "8025"))).rstrip("/")
        self.tls = ssl.create_default_context(cafile=str(ROOT / ".secrets/tls_certificate.pem"))
        self.deadline = time.monotonic() + 85  # Reserve five seconds for API cleanup.
        self.cleanup_deadline = self.deadline + 5
        self.suffix = uuid.uuid4().hex
        self.title, self.plaintext = "Smoke-" + self.suffix, "private-smoke-value-" + self.suffix
        self.emails = {role: f"smoke-{role}-{self.suffix}@example.test" for role in ("owner", "reader", "denied")}
        self.tokens, self.users, self.created, self.messages = {}, {}, set(), {}

    def request(self, method, path, status=200, token=None, body=None, base=None):
        remaining = self.deadline - time.monotonic()
        assert remaining > 0, "Smoke test exceeded its 90-second deadline"
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request((base or self.base) + path, data=data, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(req, context=self.tls, timeout=min(10, remaining))
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            assert response.status == status, f"{method} {path}: expected HTTP {status}, got {response.status}"
            if status == 204:
                assert not raw, "HTTP 204 response contained a body"
                return None
            assert response.headers.get_content_type() == "application/json", "Response is not JSON"
            value = json.loads(raw)
            if status >= 400:
                assert set(value) == {"error", "message"} and all(isinstance(v, str) and v for v in value.values()), "Invalid error shape"
            return value

    def mail_counts(self):
        # Mailpit API schema: https://mailpit.axllent.org/docs/api-v1/
        counts, start = Counter(), 0
        while True:
            page = self.request("GET", f"/api/v1/messages?limit=200&start={start}", base=self.mailpit)["messages"]
            for summary in page:
                if self.title not in summary.get("Subject", ""):
                    continue
                recipients = {item["Address"] for item in summary.get("To", [])}
                assert recipients and recipients <= set(self.emails.values()), "Unexpected notification recipient"
                assert self.plaintext not in json.dumps(summary, ensure_ascii=False), "Plaintext leaked into mail preview"
                mail_id = summary["ID"]
                if mail_id not in self.messages:
                    self.messages[mail_id] = self.request("GET", "/api/v1/message/" + urllib.parse.quote(mail_id, safe=""), base=self.mailpit)
                message = self.messages[mail_id]
                assert self.plaintext not in json.dumps(message, ensure_ascii=False), "Plaintext leaked into mail body"
                assert message.get("Text"), "Notification has an empty text body"
                if not summary["Subject"].endswith("закрыт"):
                    assert self.base + self.path in message["Text"], "Email link does not point to the public gateway"
                for recipient in recipients:
                    counts[recipient, summary["Subject"]] += 1
            if len(page) < 200:
                return counts
            start += len(page)

    def wait_mail(self, expected):
        until = min(self.deadline, time.monotonic() + 30)
        while time.monotonic() < until:
            counts = self.mail_counts()
            assert all(counts[key] <= count for key, count in expected.items()), "Duplicate notification emails"
            if all(counts[key] == count for key, count in expected.items()):
                return counts
            time.sleep(0.2)
        raise AssertionError("Timed out waiting for notification → RabbitMQ → SMTP emails")

    def run(self):
        password = "smoke-password-" + self.suffix
        owner_email, reader_email, denied_email = (self.emails[role] for role in ("owner", "reader", "denied"))
        self.request("POST", "/auth/register", 400, body={"email": owner_email, "password": "short"})
        for role, email in self.emails.items():
            self.users[role] = self.request("POST", "/auth/register", 201, body={"email": email, "password": password})["user_id"]
            uuid.UUID(self.users[role])
            login = self.request("POST", "/auth/login", body={"email": email, "password": password})
            assert login["expires_in"] == 900 and login["access_token"], "Invalid auth token response"
            self.tokens[role] = login["access_token"]
        self.request("POST", "/auth/register", 409, body={"email": owner_email, "password": password})
        self.request("POST", "/auth/login", 401, body={"email": owner_email, "password": "incorrect-password"})
        self.request("GET", "/secrets", 401)
        self.request("GET", "/secrets", 401, "invalid-token")
        print("PASS auth registration/login, duplicate registration and JWT rejection", flush=True)

        owner, reader, denied = (self.tokens[role] for role in ("owner", "reader", "denied"))
        secret = self.request("POST", "/secrets", 201, owner, {"title": self.title, "text": self.plaintext, "ttl_seconds": 300})
        sid = secret["id"]
        self.created.add(sid)
        path = "/secrets/" + sid
        self.path = path
        assert secret["link"] == self.base + path, "Created link does not point to the public gateway"
        assert self.request("GET", path, token=owner)["text"] == self.plaintext
        with ThreadPoolExecutor(max_workers=8) as pool:
            attempts = list(pool.map(lambda _: self.request("GET", path, 202, reader), range(8)))
        assert all(value == {"status": "pending"} for value in attempts)
        history = self.request("GET", path + "/requests", token=owner)
        assert len(history["requests"]) == 1 and history["requests"][0]["status"] == "pending", "Concurrent reads created duplicate access requests"
        self.request("GET", path + "/requests", 403, reader)
        owned = next(item for item in self.request("GET", "/secrets", token=owner) if item["id"] == sid)
        assert owned["pending_requests"] == 1
        requested, viewed = f"Запрос доступа к секрету «{self.title}»", f"Секрет «{self.title}» открыт"
        self.wait_mail({(owner_email, requested): 1, (owner_email, viewed): 1})
        print("PASS concurrent pending reads: one access request and one request email", flush=True)

        rid = history["requests"][0]["id"]
        decision = self.request("POST", path + "/requests/" + rid, token=owner, body={"decision": "approve"})
        assert decision == {"request_id": rid, "status": "approved"}
        self.request("POST", path + "/requests/" + rid, 409, owner, {"decision": "approve"})
        assert self.request("GET", path, token=reader)["text"] == self.plaintext
        shared = next(item for item in self.request("GET", "/secrets/shared", token=reader) if item["id"] == sid)
        assert shared["owner_email"] == owner_email
        history = self.request("GET", path + "/requests", token=owner)
        assert len(history["views"]) == 2 and {v["email"] for v in history["views"]} == {owner_email, reader_email}
        self.request("DELETE", path + "/access/" + self.users["reader"], 204, owner)
        self.request("GET", path, 403, reader)
        assert all(item["id"] != sid for item in self.request("GET", "/secrets/shared", token=reader))
        self.request("GET", path, 202, denied)
        self.request("GET", path, 202, denied)
        history = self.request("GET", path + "/requests", token=owner)
        denial = next(item for item in history["requests"] if item["requester_email"] == denied_email)
        decision = self.request("POST", path + "/requests/" + denial["id"], token=owner, body={"decision": "deny"})
        assert decision == {"request_id": denial["id"], "status": "denied"}
        self.request("GET", path, 403, denied)
        self.request("GET", path, 403, denied)
        self.request("DELETE", path, 403, reader)
        self.request("DELETE", path, 204, owner)
        self.created.remove(sid)
        self.request("GET", path, 404, owner)
        self.request("GET", path, 404, reader)
        print("PASS approvals, read audit, shared list, denial, access revocation and secret deletion", flush=True)

        expected = {(owner_email, requested): 2, (owner_email, viewed): 2,
                    (reader_email, f"Доступ к секрету «{self.title}» одобрен"): 1,
                    (reader_email, f"Доступ к секрету «{self.title}» закрыт"): 1,
                    (denied_email, f"Доступ к секрету «{self.title}» отклонён"): 1}
        assert self.wait_mail(expected) == Counter(expected), "Unexpected notification emails"
        time.sleep(min(1.5, max(0, self.deadline - time.monotonic())))
        assert self.mail_counts() == Counter(expected), "Unexpected or duplicate notification emails"
        texts = [m["Text"] for m in self.messages.values() if m["Subject"] == requested]
        assert all(any(email in text for text in texts) for email in (reader_email, denied_email)), "Request email omitted requester identity"
        print("PASS notification emails through RabbitMQ/SMTP; no plaintext in previews or bodies", flush=True)
        print("PASS secret cleanup; three unique test accounts remain (no account deletion API)", flush=True)

    def cleanup(self):
        self.deadline = self.cleanup_deadline
        for sid in self.created:
            try:
                self.request("DELETE", "/secrets/" + sid, 204, self.tokens["owner"])
            except Exception as error:
                print(f"Cleanup failed for test secret {sid}: {error}", file=sys.stderr)


if __name__ == "__main__":
    test = None
    try:
        test = Smoke()
        test.run()
    except Exception as error:
        print("FAIL " + str(error), file=sys.stderr)
        sys.exit(1)
    finally:
        if test is not None:
            test.cleanup()
