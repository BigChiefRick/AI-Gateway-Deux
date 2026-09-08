#!/usr/bin/env python3
"""Isolated regression test for the staged OpenAI DLP profile configurator."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


GROUP_ID = "00000000-0000-4000-8000-000000001004"
POLICY_GROUP_ID = f"openai:{GROUP_ID}"
SCRIPT = Path(__file__).with_name("configure-openai-dlp-profile.py")


class Handler(BaseHTTPRequestHandler):
    calls: list[tuple[str, str, dict | None]] = []

    def log_message(self, *_args: object) -> None:
        return

    def send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.calls.append(("GET", self.path, None))
        if self.path == "/admin/api/profiles":
            self.send_json(
                200,
                [
                    {
                        "id": "default",
                        "settings": {
                            "allowed_models": [],
                            "allowed_tools": [],
                            "blocked_categories": ["us_ssn"],
                            "memory_read": False,
                            "memory_write": False,
                        },
                    }
                ],
            )
        elif self.path == "/admin/api/assignments":
            self.send_json(
                200,
                [
                    {
                        "id": "legacy-assignment",
                        "subject_type": "agent",
                        "subject_id": "archestra-openai-chat",
                        "profile_id": "archestra-openai",
                    }
                ],
            )
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length)) if length else None
        self.calls.append(("POST", self.path, payload))
        if self.path == "/admin/api/profiles":
            self.send_json(200, payload)
        elif self.path == "/admin/api/assignments":
            self.send_json(200, {"id": "group-assignment", **payload})
        else:
            self.send_json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        self.calls.append(("DELETE", self.path, None))
        self.send_response(204)
        self.end_headers()


def main() -> None:
    Handler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            env = os.environ.copy()
            env.update(
                {
                    "DLP_ADMIN_API_KEY": "test-admin-key",
                    "OPENAI_DLP_ADMIN_URL": (
                        f"http://127.0.0.1:{server.server_address[1]}"
                    ),
                    "OPENAI_DLP_ALLOWED_MODELS": "approved-model",
                    "DLP_MANAGED_GROUP_ID": GROUP_ID,
                }
            )
            completed = subprocess.run(
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

    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    if f"subject=group:{POLICY_GROUP_ID}" not in completed.stdout:
        raise AssertionError(completed.stdout)

    profile = next(
        payload
        for method, path, payload in Handler.calls
        if method == "POST" and path == "/admin/api/profiles"
    )
    if profile["settings"]["allowed_models"] != ["approved-model"]:
        raise AssertionError("approved model was not preserved")
    if not profile["settings"]["memory_read"] or not profile["settings"]["memory_write"]:
        raise AssertionError("shared-team middleware memory must remain enabled")
    assignment = next(
        payload
        for method, path, payload in Handler.calls
        if method == "POST" and path == "/admin/api/assignments"
    )
    if assignment != {
        "subject_type": "group",
        "subject_id": POLICY_GROUP_ID,
        "profile_id": "archestra-openai",
        "priority": 100,
    }:
        raise AssertionError(f"unexpected assignment: {assignment}")
    if (
        "DELETE",
        "/admin/api/assignments/legacy-assignment",
        None,
    ) not in Handler.calls:
        raise AssertionError("legacy agent assignment was not removed")

    print("OPENAI_DLP_GROUP_PROFILE_TEST_OK")


if __name__ == "__main__":
    main()
