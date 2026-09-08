#!/usr/bin/env python3
"""Isolated create/idempotency/rollback tests for Entra OIDC commissioning."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import threading


SCRIPT = Path(__file__).with_name("configure-gateway-entra.py")
CLIENT_ID = "00000000-1111-4222-8333-444444444444"


class Handler(BaseHTTPRequestHandler):
    provider: dict | None = None
    publish = True
    deletes = 0

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
        if self.path == "/api/identity-providers":
            self.send_json(
                200,
                [] if type(self).provider is None else [type(self).provider],
            )
        elif self.path == "/api/identity-providers/public":
            provider = type(self).provider
            visible = bool(provider and type(self).publish)
            self.send_json(
                200,
                []
                if not visible
                else [
                    {"providerId": "gateway-entra"}
                ],
            )
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        payload = self.body()
        if self.path == "/api/auth/sign-in/email":
            self.send_json(
                200 if payload.get("password") == "admin-test" else 401,
                {"ok": True},
            )
        elif self.path == "/api/identity-providers":
            type(self).provider = {"id": "provider-1", **payload}
            self.send_json(201, type(self).provider)
        else:
            self.send_json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        if self.path == "/api/identity-providers/provider-1":
            type(self).provider = None
            type(self).deletes += 1
            self.send_json(204)
        else:
            self.send_json(404, {"error": "not found"})


def run(base: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update({"ARCHESTRA_AUTH_BASE_URL": base, "ARCHESTRA_AUTH_ORIGIN": base})
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--tenant-id",
            "00000000-0000-4000-8000-000000000999",
            "--domain",
            "example.com",
            "--client-id",
            CLIENT_ID,
            "--confirmation",
            "CONFIGURE_GATEWAY_ENTRA",
        ],
        input=json.dumps(
            {"admin_password": "admin-test", "client_secret": "secret-test"}
        ),
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def main() -> None:
    Handler.provider = None
    Handler.publish = True
    Handler.deletes = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        first = run(base)
        if first.returncode != 0:
            raise AssertionError(first.stderr or first.stdout)
        payload = json.loads(first.stdout)
        assert payload["created"] is True
        assert "secret-test" not in first.stdout + first.stderr
        assert Handler.provider["roleMapping"]["defaultRole"] == "ai_gateway_user"
        assert Handler.provider["teamSyncConfig"] == {
            "enabled": True,
            "groupsExpression": "{{json groups}}",
        }

        second = run(base)
        if second.returncode != 0:
            raise AssertionError(second.stderr or second.stdout)
        assert json.loads(second.stdout)["created"] is False

        Handler.provider = None
        Handler.publish = False
        failed = run(base)
        assert failed.returncode != 0
        assert Handler.provider is None
        assert Handler.deletes == 1
        assert "secret-test" not in failed.stdout + failed.stderr
        print("CONFIGURE_GATEWAY_ENTRA_TRANSACTION_TEST_OK")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


if __name__ == "__main__":
    main()
