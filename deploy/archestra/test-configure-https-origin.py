#!/usr/bin/env python3
"""Isolated transaction test for the HTTPS-origin environment update."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("configure-https-origin.py")
COMPOSE = Path(__file__).with_name("compose.yaml")


with tempfile.TemporaryDirectory() as directory:
    env_file = Path(directory) / ".env"
    env_file.write_text(
        "ARCHESTRA_FRONTEND_URL=http://192.0.2.10:3000\n"
        "ARCHESTRA_API_BASE_URL=http://192.0.2.10:9000\n"
        "ARCHESTRA_AUTH_ADDITIONAL_TRUSTED_ORIGINS=http://192.0.2.10:9000\n"
        "DLP_POLICY_API_KEY=preserve-this-secret-reference\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--env-file", str(env_file)],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    content = env_file.read_text(encoding="utf-8")
    assert payload["status"] == "PASS"
    assert "ARCHESTRA_FRONTEND_URL=https://gateway.example.com\n" in content
    assert (
        "ARCHESTRA_API_BASE_URL=https://gateway.example.com,https://192.0.2.10,"
        "http://192.0.2.10:9000\n"
    ) in content
    assert (
        "ARCHESTRA_AUTH_ADDITIONAL_TRUSTED_ORIGINS=https://gateway.example.com,"
        "https://192.0.2.10,http://192.0.2.10:3000,http://192.0.2.10:9000\n"
    ) in content
    assert "ARCHESTRA_SESSION_ORIGIN=https://gateway.example.com\n" in content
    assert "http://192.0.2.10:3000" in content
    assert content.count("DLP_POLICY_API_KEY=preserve-this-secret-reference") == 1
    if os.name != "nt":
        assert stat.S_IMODE(env_file.stat().st_mode) == 0o600

compose = COMPOSE.read_text(encoding="utf-8")
assert '${ARCHESTRA_BIND_ADDRESS:-192.0.2.10}:80:80' in compose
assert '${ARCHESTRA_BIND_ADDRESS:-192.0.2.10}:443:443' in compose

print("CONFIGURE_HTTPS_ORIGIN_TEST_OK")
