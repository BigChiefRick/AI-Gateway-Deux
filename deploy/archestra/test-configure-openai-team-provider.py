#!/usr/bin/env python3
"""Isolated success and rollback tests for signed cloud-provider setup."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


SCRIPT = Path(__file__).with_name("configure-openai-team-provider.py")
TEAM_ID = "00000000-0000-4000-8000-000000001004"
POLICY_GROUP = f"openai:{TEAM_ID}"


class Handler(BaseHTTPRequestHandler):
    fail_sync = False
    calls: list[tuple[str, str, dict | None]] = []
    provider: dict | None = None
    model_teams: list[str] = []

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
        parsed = urlparse(self.path)
        if parsed.path == "/readyz":
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
        elif parsed.path == "/admin/api/effective":
            groups = parse_qs(parsed.query).get("groups", [])
            self.send_json(
                200,
                {"profile_id": "archestra-openai" if groups == [POLICY_GROUP] else "default"},
            )
        elif parsed.path == "/api/teams":
            self.send_json(200, {"data": [{"id": TEAM_ID, "name": "AI Gateway Users"}]})
        elif parsed.path == "/api/llm-provider-api-keys":
            provider = type(self).provider
            self.send_json(200, [] if provider is None else [provider])
        elif parsed.path == "/api/llm-models/available":
            self.send_json(
                200,
                [
                    {
                        "id": "approved-model",
                        "dbId": "00000000-0000-4000-8000-000000000099",
                        "capabilities": {
                            "pricePerMillionInput": "1.00",
                            "pricePerMillionOutput": "2.00",
                        },
                    }
                ],
            )
        elif parsed.path == "/api/llm-models":
            self.send_json(
                200,
                [
                    {
                        "id": "00000000-0000-4000-8000-000000000099",
                        "teams": [{"id": value} for value in type(self).model_teams],
                    }
                ],
            )
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        payload = self.body()
        self.calls.append(("POST", self.path, payload))
        if self.path == "/api/auth/sign-in/email":
            self.send_json(200, {"ok": True})
        elif self.path == "/api/llm-provider-api-keys":
            type(self).provider = {
                "id": "00000000-0000-4000-8000-000000000088",
                "secretStorageType": "database",
                **payload,
            }
            type(self).provider.pop("apiKey", None)
            self.send_json(200, type(self).provider)
        elif self.path == "/api/llm-models/sync":
            if self.fail_sync:
                self.send_json(500, {"error": "injected failure"})
            else:
                self.send_json(200, {"success": True})
        else:
            self.send_json(404, {"error": "not found"})

    def do_PATCH(self) -> None:
        payload = self.body()
        self.calls.append(("PATCH", self.path, payload))
        if self.path.startswith("/api/llm-models/"):
            type(self).model_teams = payload["teamIds"]
            self.send_json(200, {"id": self.path.rsplit("/", 1)[-1]})
        else:
            self.send_json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        self.calls.append(("DELETE", self.path, None))
        if self.path.startswith("/api/llm-provider-api-keys/"):
            type(self).provider = None
        self.send_json(200, {"success": True})


def run_case(fail_sync: bool) -> subprocess.CompletedProcess[str]:
    Handler.fail_sync = fail_sync
    Handler.calls = []
    Handler.provider = None
    Handler.model_teams = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with tempfile.TemporaryDirectory() as directory:
            env = os.environ.copy()
            env.update(
                {
                    "ARCHESTRA_ACCEPTANCE_URL": base,
                    "ARCHESTRA_ACCEPTANCE_ORIGIN": base,
                    "ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD": "test-password",
                    "ARCHESTRA_CLOUD_MODEL": "approved-model",
                    "OPENAI_DLP_ADMIN_URL": base,
                    "OPENAI_DLP_PROVIDER_URL": base + "/v1",
                    "OPENAI_DLP_POLICY_API_KEY": "test-policy-key",
                    "DLP_ADMIN_API_KEY": "test-admin-key",
                    "DLP_IDENTITY_HMAC_KEY": "test-identity-key",
                    "DLP_MANAGED_GROUP_ID": TEAM_ID,
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
    if Handler.provider is None or Handler.model_teams != [TEAM_ID]:
        raise AssertionError("provider or model team restriction was not persisted")
    headers = Handler.provider.get("extraHeaders", {})
    if headers.get("X-AI-Gateway-Groups") != POLICY_GROUP:
        raise AssertionError("provider did not use route-qualified group identity")
    if "X-AI-Gateway-Identity-Signature" not in headers:
        raise AssertionError("provider did not include a signed identity")

    failure = run_case(True)
    if failure.returncode == 0:
        raise AssertionError("injected model-sync failure unexpectedly passed")
    if Handler.provider is not None:
        raise AssertionError("new provider was not rolled back")
    if not any(
        method == "DELETE" and path.startswith("/api/llm-provider-api-keys/")
        for method, path, _payload in Handler.calls
    ):
        raise AssertionError("provider rollback delete was not called")

    print("OPENAI_TEAM_PROVIDER_TRANSACTION_TEST_OK")


if __name__ == "__main__":
    main()
