#!/usr/bin/env python3
"""Isolated transaction tests for bootstrap administrator rotation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SCRIPT = Path(__file__).with_name("rotate-bootstrap-admin.py")
ADMIN_EMAIL = "admin@example.com"
CURRENT_PASSWORD = "old-test-password"
NEW_PASSWORD = "new-test-password-123!"


class Handler(BaseHTTPRequestHandler):
    password = CURRENT_PASSWORD
    bootstrap_enabled = True
    fail_change = False
    calls: list[tuple[str, str, dict | None]] = []

    def log_message(self, *_args: object) -> None:
        return

    def body(self) -> dict | None:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length)) if length else None

    def send_json(self, status: int, payload: object | None = None, cookie: str | None = None) -> None:
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if body:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def authenticated(self) -> bool:
        return "session=accepted" in self.headers.get("Cookie", "")

    def do_GET(self) -> None:
        type(self).calls.append(("GET", self.path, None))
        if self.path == "/api/auth/default-credentials-status":
            self.send_json(200, {"enabled": type(self).bootstrap_enabled})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        payload = self.body()
        type(self).calls.append(("POST", self.path, payload))
        if self.path == "/api/auth/sign-in/email":
            if (
                isinstance(payload, dict)
                and payload.get("email") == ADMIN_EMAIL
                and payload.get("password") == type(self).password
            ):
                self.send_json(200, {"ok": True}, "session=accepted; Path=/; HttpOnly")
            else:
                self.send_json(401, {"message": "Unauthorized"})
        elif self.path == "/api/auth/change-password":
            if not self.authenticated():
                self.send_json(401, {"message": "Unauthorized"})
            elif type(self).fail_change:
                self.send_json(500, {"message": "injected failure"})
            elif not isinstance(payload, dict) or payload.get("currentPassword") != type(self).password:
                self.send_json(400, {"message": "bad current password"})
            else:
                if payload.get("revokeOtherSessions") is not True:
                    self.send_json(400, {"message": "sessions were not revoked"})
                    return
                type(self).password = payload["newPassword"]
                type(self).bootstrap_enabled = False
                self.send_json(200, {"status": True})
        else:
            self.send_json(404, {"error": "not found"})


def run(base: str, *args: str, stdin: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "ARCHESTRA_ACCEPTANCE_URL": base,
            "ARCHESTRA_ACCEPTANCE_ORIGIN": base,
            "ARCHESTRA_ACCEPTANCE_ADMIN_EMAIL": ADMIN_EMAIL,
        }
    )
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        env=env,
        input=stdin,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def assert_no_secret(result: subprocess.CompletedProcess[str]) -> None:
    output = result.stdout + result.stderr
    for secret in (CURRENT_PASSWORD, NEW_PASSWORD):
        if secret in output:
            raise AssertionError("password leaked to process output")


def main() -> None:
    Handler.password = CURRENT_PASSWORD
    Handler.bootstrap_enabled = True
    Handler.fail_change = False
    Handler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        preflight = run(base, "--preflight-only", stdin=CURRENT_PASSWORD)
        assert_no_secret(preflight)
        if preflight.returncode != 0:
            raise AssertionError(preflight.stderr or preflight.stdout)
        if json.loads(preflight.stdout)["bootstrap_credential_enabled"] is not True:
            raise AssertionError(preflight.stdout)

        rotation = run(
            base,
            "--confirm",
            "ROTATE_BOOTSTRAP_ADMIN",
            stdin=json.dumps(
                {"current_password": CURRENT_PASSWORD, "new_password": NEW_PASSWORD}
            ),
        )
        assert_no_secret(rotation)
        if rotation.returncode != 0:
            raise AssertionError(rotation.stderr or rotation.stdout)
        result = json.loads(rotation.stdout)
        if (
            result["bootstrap_credential_enabled"] is not False
            or result["new_password_verified"] is not True
            or Handler.password != NEW_PASSWORD
        ):
            raise AssertionError(result)

        repeated = run(base, "--preflight-only", stdin=NEW_PASSWORD)
        assert_no_secret(repeated)
        if repeated.returncode == 0 or "already rotated" not in repeated.stderr:
            raise AssertionError(repeated.stderr or repeated.stdout)

        Handler.password = CURRENT_PASSWORD
        Handler.bootstrap_enabled = True
        Handler.fail_change = True
        failed = run(
            base,
            "--confirm",
            "ROTATE_BOOTSTRAP_ADMIN",
            stdin=json.dumps(
                {"current_password": CURRENT_PASSWORD, "new_password": NEW_PASSWORD}
            ),
        )
        assert_no_secret(failed)
        if failed.returncode == 0 or "HTTP 500" not in failed.stderr:
            raise AssertionError(failed.stderr or failed.stdout)
        if Handler.password != CURRENT_PASSWORD or Handler.bootstrap_enabled is not True:
            raise AssertionError("failed change altered credential state")

        same = run(
            base,
            "--confirm",
            "ROTATE_BOOTSTRAP_ADMIN",
            stdin=json.dumps(
                {"current_password": CURRENT_PASSWORD, "new_password": CURRENT_PASSWORD}
            ),
        )
        assert_no_secret(same)
        if same.returncode == 0 or "must differ" not in same.stderr:
            raise AssertionError(same.stderr or same.stdout)

        print("ROTATE_BOOTSTRAP_ADMIN_TRANSACTION_TEST_OK")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


if __name__ == "__main__":
    main()
