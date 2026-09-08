#!/usr/bin/env python3
"""Isolated tests for idempotent end-user access management."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


SCRIPT = Path(__file__).with_name("manage-end-user.py")
DEFAULT_HELPER = Path(__file__).with_name("test-support") / "fake-member-default-helper.py"
TEAM_ID = "00000000-0000-4000-8000-000000001004"
USER_ID = "00000000-0000-4000-8000-000000000111"
EMAIL = "poc.user@example.com"


class Handler(BaseHTTPRequestHandler):
    role = "ai_gateway_user"
    membership: dict | None = None
    calls: list[tuple[str, str, dict | None]] = []

    def log_message(self, *_args: object) -> None:
        return

    def body(self) -> dict | None:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length)) if length else None

    def send_json(self, status: int, payload: object | None = None) -> None:
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        if body:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        self.calls.append(("GET", self.path, None))
        parsed = urlparse(self.path)
        if parsed.path == "/api/members":
            self.send_json(
                200,
                {
                    "data": [
                        {
                            "id": "membership-id",
                            "userId": USER_ID,
                            "name": "POC User",
                            "email": EMAIL,
                            "role": type(self).role,
                        }
                    ]
                },
            )
        elif parsed.path == "/api/teams":
            self.send_json(200, {"data": [{"id": TEAM_ID, "name": "AI Gateway Users"}]})
        elif parsed.path == f"/api/teams/{TEAM_ID}/members":
            membership = type(self).membership
            self.send_json(200, [] if membership is None else [membership])
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        payload = self.body()
        self.calls.append(("POST", self.path, payload))
        if self.path == "/api/auth/sign-in/email":
            if isinstance(payload, dict) and payload.get("password") == "test-password":
                self.send_json(200, {"ok": True})
            else:
                self.send_json(401, {"message": "Unauthorized"})
        elif self.path == f"/api/teams/{TEAM_ID}/members":
            type(self).membership = {
                "id": "team-membership-id",
                "teamId": TEAM_ID,
                "userId": payload["userId"],
                "role": payload["role"],
                "syncedFromSso": False,
                "email": EMAIL,
            }
            self.send_json(200, type(self).membership)
        else:
            self.send_json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        self.calls.append(("DELETE", self.path, None))
        if self.path == f"/api/teams/{TEAM_ID}/members/{USER_ID}":
            type(self).membership = None
            self.send_json(204)
        else:
            self.send_json(404, {"error": "not found"})


def run(
    action: str, base: str, *, password_stdin: bool = False
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update({"ARCHESTRA_ACCEPTANCE_URL": base, "ARCHESTRA_ACCEPTANCE_ORIGIN": base})
    env["ARCHESTRA_MEMBER_DEFAULT_HELPER"] = str(DEFAULT_HELPER)
    command = [sys.executable, str(SCRIPT)]
    input_text = None
    if password_stdin:
        env.pop("ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD", None)
        command.append("--password-stdin")
        input_text = "test-password"
    else:
        env["ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD"] = "test-password"
    command.extend((action, EMAIL))
    return subprocess.run(
        command,
        env=env,
        input=input_text,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def expect_pass(
    result: subprocess.CompletedProcess[str], action: str, access: bool
) -> dict[str, object]:
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    payload = json.loads(result.stdout)
    if payload["action"] != action or payload["team_access"] is not access:
        raise AssertionError(payload)
    if payload["managed_default"] is not (action == "grant"):
        raise AssertionError(payload)
    return payload


def main() -> None:
    Handler.role = "ai_gateway_user"
    Handler.membership = None
    Handler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        expect_pass(run("status", base), "status", False)
        stdin_status = run("status", base, password_stdin=True)
        expect_pass(stdin_status, "status", False)
        if "test-password" in stdin_status.stdout + stdin_status.stderr:
            raise AssertionError("standard-input password leaked to process output")
        expect_pass(run("grant", base), "grant", True)
        post_count = sum(method == "POST" and path.endswith("/members") for method, path, _ in Handler.calls)
        expect_pass(run("grant", base), "grant", True)
        if sum(method == "POST" and path.endswith("/members") for method, path, _ in Handler.calls) != post_count:
            raise AssertionError("idempotent grant created a duplicate membership")
        expect_pass(run("revoke", base), "revoke", False)
        delete_count = sum(method == "DELETE" for method, _path, _ in Handler.calls)
        expect_pass(run("revoke", base), "revoke", False)
        if sum(method == "DELETE" for method, _path, _ in Handler.calls) != delete_count:
            raise AssertionError("idempotent revoke repeated the delete")

        Handler.role = "admin"
        wrong_role = run("grant", base)
        if wrong_role.returncode == 0 or "refusing to change organization roles" not in wrong_role.stderr:
            raise AssertionError(wrong_role.stderr or wrong_role.stdout)

        Handler.role = "ai_gateway_user"
        Handler.membership = {
            "id": "sso-membership-id",
            "teamId": TEAM_ID,
            "userId": USER_ID,
            "role": "member",
            "syncedFromSso": True,
            "email": EMAIL,
        }
        sso_revoke = run("revoke", base)
        if sso_revoke.returncode == 0 or "identity provider" not in sso_revoke.stderr:
            raise AssertionError(sso_revoke.stderr or sso_revoke.stdout)

        print("MANAGE_END_USER_TRANSACTION_TEST_OK")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


if __name__ == "__main__":
    main()
