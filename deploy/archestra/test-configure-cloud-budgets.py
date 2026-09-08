#!/usr/bin/env python3
"""Isolated success and rollback tests for cloud-budget activation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SCRIPT = Path(__file__).with_name("configure-cloud-budgets.py")
ORG_ID = "00000000-0000-4000-8000-000000000001"


class Handler(BaseHTTPRequestHandler):
    fail_default = False
    calls: list[tuple[str, str, dict | None]] = []
    limits: list[dict] = []
    defaults: list[dict] = []

    def log_message(self, *_args: object) -> None:
        return

    def body(self) -> dict | None:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length)) if length else None

    def send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.calls.append(("GET", self.path, None))
        if self.path == "/api/auth/get-session":
            self.send_json(200, {"session": {"activeOrganizationId": ORG_ID}})
        elif self.path == "/readyz":
            self.send_json(
                200,
                {
                    "status": "ready",
                    "guardrail_database": "connected",
                    "policy_auth": "configured",
                    "upstream": "configured",
                    "signed_identity": "configured",
                },
            )
        elif self.path == "/api/auth/default-credentials-status":
            self.send_json(200, {"enabled": False})
        elif self.path == "/api/llm-provider-api-keys":
            self.send_json(
                200,
                [
                    {
                        "provider": "openai",
                        "baseUrl": "http://192.0.2.10:4201/v1",
                        "secretStorageType": "database",
                        "isChatgptSubscription": False,
                        "scope": "team",
                        "teamId": "00000000-0000-4000-8000-000000001004",
                    }
                ],
            )
        elif self.path == "/api/llm-models":
            self.send_json(
                200,
                [
                    {
                        "provider": "openai",
                        "modelId": "approved-model",
                        "pricePerMillionInput": "1.00",
                        "pricePerMillionOutput": "2.00",
                    }
                ],
            )
        elif self.path.startswith("/api/limits?"):
            self.send_json(200, self.limits)
        elif self.path == "/api/default-user-limits":
            self.send_json(200, self.defaults)
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        payload = self.body()
        self.calls.append(("POST", self.path, payload))
        if self.path == "/api/auth/sign-in/email":
            self.send_json(200, {"ok": True})
        elif self.path == "/api/limits":
            row = {"id": "org-limit", **payload}
            self.limits.append(row)
            self.send_json(200, row)
        elif self.path == "/api/default-user-limits":
            if self.fail_default:
                self.send_json(500, {"error": "injected failure"})
            else:
                row = {"id": "user-limit", "environmentId": None, **payload}
                self.defaults.append(row)
                self.send_json(200, row)
        else:
            self.send_json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        self.calls.append(("DELETE", self.path, None))
        if self.path == "/api/limits/org-limit":
            self.limits.clear()
        elif self.path == "/api/default-user-limits/user-limit":
            self.defaults.clear()
        self.send_json(200, {"success": True})


def run_case(fail_default: bool) -> subprocess.CompletedProcess[str]:
    Handler.fail_default = fail_default
    Handler.calls = []
    Handler.limits = []
    Handler.defaults = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            env = os.environ.copy()
            env.update(
                {
                    "ARCHESTRA_ACCEPTANCE_URL": (
                        f"http://127.0.0.1:{server.server_address[1]}"
                    ),
                    "ARCHESTRA_ACCEPTANCE_ORIGIN": "http://127.0.0.1:3000",
                    "ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD": "test-password",
                    "ARCHESTRA_CLOUD_MODEL": "approved-model",
                    "ARCHESTRA_CLOUD_DLP_HEALTH_URL": (
                        f"http://127.0.0.1:{server.server_address[1]}/readyz"
                    ),
                    "DLP_MANAGED_GROUP_ID": (
                        "00000000-0000-4000-8000-000000001004"
                    ),
                    "ARCHESTRA_ORGANIZATION_LIMIT_DOLLARS": "100",
                    "ARCHESTRA_DEFAULT_USER_LIMIT_DOLLARS": "20",
                    "ARCHESTRA_CLOUD_LIMIT_INTERVAL": "calendar_month",
                    "ARCHESTRA_CONFIRM_BUDGETS": "APPLY_CLOUD_BUDGETS",
                }
            )
            return subprocess.run(
                [sys.executable, str(SCRIPT)],
                cwd=directory,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def main() -> None:
    success = run_case(False)
    if success.returncode != 0 or '"status":"PASS"' not in success.stdout:
        raise AssertionError(success.stderr or success.stdout)
    if not Handler.limits or not Handler.defaults:
        raise AssertionError("successful run did not persist both limits")

    failure = run_case(True)
    if failure.returncode == 0:
        raise AssertionError("injected default-user failure unexpectedly passed")
    if Handler.limits:
        raise AssertionError("organization limit was not rolled back")
    if ("DELETE", "/api/limits/org-limit", None) not in Handler.calls:
        raise AssertionError("rollback delete was not called")

    print("CLOUD_BUDGET_TRANSACTION_TEST_OK")


if __name__ == "__main__":
    main()
