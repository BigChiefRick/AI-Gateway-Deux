#!/usr/bin/env python3
"""Isolated success, idempotency, and rollback tests for the subscription canary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


SCRIPT = Path(__file__).with_name("configure-chatgpt-subscription-canary.py")
SOURCE_AGENT_ID = "00000000-0000-4000-8000-000000001003"
CANARY_AGENT_ID = "00000000-0000-4000-8000-000000000077"
PROVIDER_ID = "00000000-0000-4000-8000-000000000088"
MODEL_DB_ID = "00000000-0000-4000-8000-000000000099"
TEAM_ID = "00000000-0000-4000-8000-000000001004"
CANARY_NAME = "Personal ChatGPT Subscription (No Content DLP)"
TOOLS = [{"id": f"web-tool-{index}"} for index in range(6)]


def source_agent() -> dict[str, Any]:
    return {
        "id": SOURCE_AGENT_ID,
        "name": "AI Gateway POC",
        "description": "managed local agent",
        "systemPrompt": "managed local prompt",
        "scope": "team",
        "teams": [{"id": TEAM_ID, "name": "AI Gateway Users"}],
        "tools": TOOLS,
        "modelId": "local-model",
        "llmApiKeyId": "local-provider",
    }


def stale_canary() -> dict[str, Any]:
    return {
        **source_agent(),
        "id": CANARY_AGENT_ID,
        "name": CANARY_NAME,
        "description": "old description",
        "systemPrompt": "old prompt",
        "scope": "personal",
        "teams": [],
        "modelId": "old-model",
        "llmApiKeyId": "old-provider",
    }


class Handler(BaseHTTPRequestHandler):
    fail_chat = False
    canary: dict[str, Any] | None = None
    calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def log_message(self, *_args: object) -> None:
        return

    def body(self) -> dict[str, Any] | None:
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
        path = urlparse(self.path).path
        if path == "/api/llm-provider-api-keys":
            self.send_json(
                200,
                [
                    {
                        "id": PROVIDER_ID,
                        "provider": "openai",
                        "isChatgptSubscription": True,
                        "scope": "personal",
                        "isPrimary": True,
                        "secretStorageType": "database",
                    }
                ],
            )
        elif path == "/api/llm-models":
            self.send_json(
                200,
                [
                    {
                        "id": MODEL_DB_ID,
                        "provider": "openai",
                        "modelId": "gpt-5.6-terra",
                    }
                ],
            )
        elif path == f"/api/agents/{SOURCE_AGENT_ID}":
            self.send_json(200, source_agent())
        elif path == "/api/agents/all":
            self.send_json(200, [] if type(self).canary is None else [type(self).canary])
        elif path == f"/api/agents/{CANARY_AGENT_ID}":
            if type(self).canary is None:
                self.send_json(404, {"error": "not found"})
            else:
                self.send_json(200, type(self).canary)
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        payload = self.body()
        self.calls.append(("POST", self.path, payload))
        if self.path == "/api/auth/sign-in/email":
            self.send_json(200, {"ok": True})
        elif self.path == f"/api/agents/{SOURCE_AGENT_ID}/clone":
            type(self).canary = {
                **source_agent(),
                "id": CANARY_AGENT_ID,
                "name": "AI Gateway POC (Copy)",
                "scope": "personal",
                "teams": [],
            }
            self.send_json(200, type(self).canary)
        elif self.path == "/api/chat/conversations":
            self.send_json(200, {"id": "acceptance-conversation"})
        elif self.path == "/api/chat":
            if self.fail_chat:
                self.send_json(500, {"error": "injected failure"})
            else:
                body = b"CHATGPT_SUBSCRIPTION_OK"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        else:
            self.send_json(404, {"error": "not found"})

    def do_PUT(self) -> None:
        payload = self.body() or {}
        self.calls.append(("PUT", self.path, payload))
        if self.path == f"/api/agents/{CANARY_AGENT_ID}" and type(self).canary:
            type(self).canary.update(payload)
            type(self).canary["teams"] = [
                {"id": team_id, "name": "AI Gateway Users"}
                for team_id in payload.get("teams", [])
            ]
            self.send_json(200, type(self).canary)
        else:
            self.send_json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        self.calls.append(("DELETE", self.path, None))
        if self.path == f"/api/agents/{CANARY_AGENT_ID}":
            type(self).canary = None
        self.send_json(200, {"success": True})


def run_case(*, existing: bool, fail_chat: bool) -> tuple[subprocess.CompletedProcess[str], str]:
    Handler.fail_chat = fail_chat
    Handler.canary = stale_canary() if existing else None
    Handler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / ".env"
            env_path.write_text("EXISTING=value\n", encoding="utf-8")
            env = os.environ.copy()
            env.update(
                {
                    "ARCHESTRA_ACCEPTANCE_URL": base_url,
                    "ARCHESTRA_ACCEPTANCE_ORIGIN": base_url,
                    "ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD": "test-password",
                    "ARCHESTRA_DEPLOYMENT_ENV": str(env_path),
                }
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT)],
                cwd=directory,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            persisted = env_path.read_text(encoding="utf-8")
            return result, persisted
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def main() -> None:
    success, persisted = run_case(existing=False, fail_chat=False)
    if success.returncode != 0 or '"status":"PASS"' not in success.stdout:
        raise AssertionError(success.stderr or success.stdout)
    if not Handler.canary or Handler.canary.get("llmApiKeyId") != PROVIDER_ID:
        raise AssertionError("successful canary was not retained with the subscription provider")
    if Handler.canary.get("scope") != "personal" or Handler.canary.get("teams") != []:
        raise AssertionError("successful canary was not private and personal")
    if len(Handler.canary.get("tools", [])) != 6:
        raise AssertionError("successful canary did not retain the six research tools")
    if f"CHATGPT_SUBSCRIPTION_CANARY_AGENT_ID={CANARY_AGENT_ID}" not in persisted:
        raise AssertionError("successful canary ID was not persisted")
    if ("DELETE", "/api/chat/conversations/acceptance-conversation", None) not in Handler.calls:
        raise AssertionError("successful acceptance conversation was not removed")

    created_failure, persisted = run_case(existing=False, fail_chat=True)
    if created_failure.returncode == 0:
        raise AssertionError("injected new-canary chat failure unexpectedly passed")
    if Handler.canary is not None:
        raise AssertionError("new canary was not deleted after acceptance failure")
    if "CHATGPT_SUBSCRIPTION_CANARY_AGENT_ID=" in persisted:
        raise AssertionError("failed canary ID was persisted")

    expected_old = stale_canary()
    existing_failure, persisted = run_case(existing=True, fail_chat=True)
    if existing_failure.returncode == 0:
        raise AssertionError("injected existing-canary chat failure unexpectedly passed")
    if Handler.canary != expected_old:
        raise AssertionError("existing canary configuration was not restored after failure")
    if "CHATGPT_SUBSCRIPTION_CANARY_AGENT_ID=" in persisted:
        raise AssertionError("failed existing canary ID was persisted")

    idempotent, _ = run_case(existing=True, fail_chat=False)
    if idempotent.returncode != 0 or '"status":"PASS"' not in idempotent.stdout:
        raise AssertionError(idempotent.stderr or idempotent.stdout)
    clone_calls = [
        call for call in Handler.calls if call[0] == "POST" and call[1].endswith("/clone")
    ]
    if clone_calls:
        raise AssertionError("idempotent canary update created a duplicate agent")

    print("CHATGPT_SUBSCRIPTION_CANARY_TRANSACTION_TEST_OK")


if __name__ == "__main__":
    main()
