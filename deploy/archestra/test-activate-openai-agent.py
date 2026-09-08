#!/usr/bin/env python3
"""Isolated success and rollback tests for guarded cloud-agent activation."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


SCRIPT = Path(__file__).with_name("activate-openai-agent.py")
TEAM_ID = "00000000-0000-4000-8000-000000001004"
ORG_ID = "00000000-0000-4000-8000-000000000001"
SOURCE_AGENT_ID = "00000000-0000-4000-8000-000000001003"
CLOUD_AGENT_ID = "00000000-0000-4000-8000-000000000077"
PROVIDER_ID = "00000000-0000-4000-8000-000000000088"
MODEL_DB_ID = "00000000-0000-4000-8000-000000000099"
IDENTITY_KEY = "test-identity-key"
POLICY_GROUP = f"openai:{TEAM_ID}"
SIGNATURE = hmac.new(
    IDENTITY_KEY.encode(),
    f"user=\ngroups={POLICY_GROUP}".encode(),
    hashlib.sha256,
).hexdigest()
TOOLS = [{"id": f"web-tool-{index}"} for index in range(6)]


class Handler(BaseHTTPRequestHandler):
    fail_chat = False
    cloud_agent: dict | None = None
    audit: list[dict] = []
    calls: list[tuple[str, str, dict | None]] = []

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

    def source_agent(self) -> dict:
        return {
            "id": SOURCE_AGENT_ID,
            "name": "AI Gateway POC",
            "scope": "team",
            "teams": [{"id": TEAM_ID, "name": "AI Gateway Users"}],
            "tools": TOOLS,
            "modelId": "local-model",
            "llmApiKeyId": "local-provider",
        }

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
        elif parsed.path == "/admin/api/audit":
            self.send_json(200, type(self).audit)
        elif parsed.path == "/api/auth/get-session":
            self.send_json(200, {"session": {"activeOrganizationId": ORG_ID}})
        elif parsed.path == "/api/auth/default-credentials-status":
            self.send_json(200, {"enabled": False})
        elif parsed.path == "/api/teams":
            self.send_json(200, {"data": [{"id": TEAM_ID, "name": "AI Gateway Users"}]})
        elif parsed.path == "/api/llm-provider-api-keys":
            self.send_json(
                200,
                [
                    {
                        "id": PROVIDER_ID,
                        "provider": "openai",
                        "scope": "team",
                        "teamId": TEAM_ID,
                        "baseUrl": self.server.base_url + "/v1",
                        "secretStorageType": "database",
                        "isChatgptSubscription": False,
                        "isPrimary": False,
                        "extraHeaders": {
                            "X-AI-Gateway-Groups": POLICY_GROUP,
                            "X-AI-Gateway-Identity-Signature": SIGNATURE,
                        },
                    }
                ],
            )
        elif parsed.path == "/api/llm-models":
            self.send_json(
                200,
                [
                    {
                        "id": MODEL_DB_ID,
                        "provider": "openai",
                        "modelId": "approved-model",
                        "pricePerMillionInput": "1.00",
                        "pricePerMillionOutput": "2.00",
                        "teams": [{"id": TEAM_ID}],
                    }
                ],
            )
        elif parsed.path == "/api/limits":
            self.send_json(
                200,
                [
                    {
                        "entityType": "organization",
                        "entityId": ORG_ID,
                        "limitType": "token_cost",
                        "limitValue": 100,
                        "model": ["approved-model"],
                        "cleanupInterval": "calendar_month",
                    }
                ],
            )
        elif parsed.path == "/api/default-user-limits":
            self.send_json(
                200,
                [
                    {
                        "environmentId": None,
                        "limitValue": 20,
                        "model": ["approved-model"],
                        "cleanupInterval": "calendar_month",
                    }
                ],
            )
        elif parsed.path == f"/api/agents/{SOURCE_AGENT_ID}":
            self.send_json(200, self.source_agent())
        elif parsed.path == "/api/agents/all":
            agents = [] if type(self).cloud_agent is None else [type(self).cloud_agent]
            self.send_json(200, agents)
        elif parsed.path == f"/api/agents/{CLOUD_AGENT_ID}":
            if type(self).cloud_agent is None:
                self.send_json(404, {"error": "not found"})
            else:
                self.send_json(200, type(self).cloud_agent)
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        payload = self.body()
        self.calls.append(("POST", self.path, payload))
        if self.path == "/api/auth/sign-in/email":
            self.send_json(200, {"ok": True})
        elif self.path == f"/api/agents/{SOURCE_AGENT_ID}/clone":
            type(self).cloud_agent = {
                **self.source_agent(),
                "id": CLOUD_AGENT_ID,
                "name": "AI Gateway POC (Copy)",
            }
            self.send_json(200, type(self).cloud_agent)
        elif self.path == "/api/chat/conversations":
            self.send_json(200, {"id": "conversation-1"})
        elif self.path == "/api/chat":
            if self.fail_chat:
                self.send_json(500, {"error": "injected failure"})
            else:
                type(self).audit.append(
                    {
                        "id": 1,
                        "profile_id": "archestra-openai",
                        "decision": "allow",
                        "stage": "output",
                    }
                )
                body = b"OPENAI_GATEWAY_OK"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        else:
            self.send_json(404, {"error": "not found"})

    def do_PUT(self) -> None:
        payload = self.body()
        self.calls.append(("PUT", self.path, payload))
        if self.path == f"/api/agents/{CLOUD_AGENT_ID}" and type(self).cloud_agent:
            type(self).cloud_agent.update(payload)
            type(self).cloud_agent["teams"] = [
                {"id": value, "name": "AI Gateway Users"}
                for value in payload.get("teams", [])
            ]
            self.send_json(200, type(self).cloud_agent)
        else:
            self.send_json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        self.calls.append(("DELETE", self.path, None))
        if self.path == f"/api/agents/{CLOUD_AGENT_ID}":
            type(self).cloud_agent = None
        self.send_json(200, {"success": True})


def run_case(fail_chat: bool) -> subprocess.CompletedProcess[str]:
    Handler.fail_chat = fail_chat
    Handler.cloud_agent = None
    Handler.audit = []
    Handler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            env = os.environ.copy()
            env.update(
                {
                    "ARCHESTRA_ACCEPTANCE_URL": server.base_url,
                    "ARCHESTRA_ACCEPTANCE_ORIGIN": server.base_url,
                    "ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD": "test-password",
                    "ARCHESTRA_CLOUD_MODEL": "approved-model",
                    "ARCHESTRA_EXPECTED_CLOUD_BASE_URL": server.base_url + "/v1",
                    "OPENAI_DLP_ADMIN_URL": server.base_url,
                    "DLP_ADMIN_API_KEY": "test-admin-key",
                    "DLP_IDENTITY_HMAC_KEY": IDENTITY_KEY,
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
    if not Handler.cloud_agent or Handler.cloud_agent.get("llmApiKeyId") != PROVIDER_ID:
        raise AssertionError("cloud agent was not retained on successful acceptance")

    failure = run_case(True)
    if failure.returncode == 0:
        raise AssertionError("injected cloud-chat failure unexpectedly passed")
    if Handler.cloud_agent is not None:
        raise AssertionError("failed cloud agent was not removed")
    if ("DELETE", f"/api/agents/{CLOUD_AGENT_ID}", None) not in Handler.calls:
        raise AssertionError("cloud-agent rollback delete was not called")

    print("OPENAI_AGENT_ACTIVATION_TRANSACTION_TEST_OK")


if __name__ == "__main__":
    main()
