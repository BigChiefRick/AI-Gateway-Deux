#!/usr/bin/env python3
"""Transactionally stage company OpenAI behind a side-by-side router canary.

The API key is read only from standard input. The canary proves the credential
and selected model without changing the proven live route on port 4200.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any
import urllib.error
import urllib.request


DEFAULT_ENV_PATH = Path("/opt/ai-gateway/archestra/.env")
MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
KEY_PATTERN = re.compile(r"^sk-[A-Za-z0-9_-]{20,4093}$")


def parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def updated_env(text: str, updates: dict[str, str]) -> str:
    output: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            name = line.split("=", 1)[0]
            if name in updates:
                output.append(f"{name}={updates[name]}")
                seen.add(name)
                continue
        output.append(line)
    for name, value in updates.items():
        if name not in seen:
            output.append(f"{name}={value}")
    return "\n".join(output) + "\n"


def atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".env.openai.", dir=str(path.parent), text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )


def request_json(url: str, admin_key: str, method: str = "GET") -> Any:
    request = urllib.request.Request(
        url,
        data=b"{}" if method == "POST" else None,
        headers={
            "Authorization": f"Bearer {admin_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method=method,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def validate_runtime(bind_address: str, admin_key: str, model: str) -> int:
    ready_url = f"http://{bind_address}:4202/readyz"
    provider_test_url = (
        f"http://{bind_address}:4202/admin/api/providers/external/test"
    )
    last_error = "not started"
    for _attempt in range(45):
        try:
            with urllib.request.urlopen(ready_url, timeout=5) as response:
                readiness = json.load(response)
            if response.status == 200 and readiness.get("status") == "ready":
                payload = request_json(provider_test_url, admin_key, "POST")
                if not isinstance(payload, dict) or payload.get("model") != model:
                    raise RuntimeError(
                        "approved model did not pass the guarded provider test"
                    )
                return int(payload.get("models_visible", 0))
        except (OSError, urllib.error.URLError, json.JSONDecodeError, RuntimeError) as error:
            last_error = f"{type(error).__name__}: {error}"
        time.sleep(2)
    raise RuntimeError(f"guarded OpenAI route did not validate: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stage a company OpenAI key behind the side-by-side router canary."
    )
    parser.add_argument("--model", required=True, help="Exact approved OpenAI model ID")
    args = parser.parse_args()
    if not MODEL_PATTERN.fullmatch(args.model):
        raise SystemExit("--model contains unsupported characters or is too long")

    secret = sys.stdin.read(4097).strip()
    if not KEY_PATTERN.fullmatch(secret):
        raise SystemExit("standard input does not contain a validly shaped OpenAI API key")

    env_path = Path(os.environ.get("AI_GATEWAY_ENV_PATH", str(DEFAULT_ENV_PATH)))
    if not env_path.is_file():
        raise SystemExit(f"gateway environment file was not found: {env_path}")
    original_text = env_path.read_text(encoding="utf-8")
    original_mode = stat.S_IMODE(env_path.stat().st_mode)
    values = parse_env(original_text)
    for required in ("DLP_ADMIN_API_KEY", "DLP_DB_PASSWORD", "DLP_IDENTITY_HMAC_KEY", "DLP_MANAGED_GROUP_ID"):
        if not values.get(required):
            raise SystemExit(f"{required} must be configured before OpenAI staging")

    updates = {
        "OPENAI_API_KEY": secret,
        "OPENAI_DLP_ALLOWED_MODELS": args.model,
        "OPENAI_DLP_DEFAULT_MODEL": args.model,
    }
    staged_text = updated_env(original_text, updates)
    test_mode = os.environ.get("AI_GATEWAY_STAGE_TEST_MODE") == "true"
    inject_failure = os.environ.get("AI_GATEWAY_STAGE_INJECT_FAILURE") == "after_env"
    compose_dir = env_path.parent
    was_running = False

    try:
        if not test_mode:
            inspected = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", "ai-gateway-dlp-router-canary"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            was_running = inspected.returncode == 0 and inspected.stdout.strip() == "true"
        atomic_write(env_path, staged_text, 0o600)
        secret = ""
        if inject_failure:
            raise RuntimeError("injected failure after environment staging")
        if test_mode:
            model_count = 1
        else:
            run(
                ["docker", "compose", "--profile", "router-canary", "up", "-d", "dlp-router-canary"],
                compose_dir,
            )
            bind_address = values.get("DLP_BIND_ADDRESS") or values.get(
                "ARCHESTRA_BIND_ADDRESS", "192.0.2.10"
            )
            model_count = validate_runtime(
                bind_address, values["DLP_ADMIN_API_KEY"], args.model
            )
    except BaseException as error:
        atomic_write(env_path, original_text, original_mode)
        if not test_mode:
            try:
                if was_running:
                    run(
                        ["docker", "compose", "--profile", "router-canary", "up", "-d", "--force-recreate", "dlp-router-canary"],
                        compose_dir,
                    )
                else:
                    subprocess.run(
                        ["docker", "compose", "--profile", "router-canary", "rm", "-s", "-f", "dlp-router-canary"],
                        cwd=compose_dir,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
            except BaseException as rollback_error:
                raise RuntimeError(
                    f"OpenAI staging failed and runtime rollback also failed: {rollback_error}"
                ) from error
        raise

    print(
        json.dumps(
            {
                "status": "PASS",
                "action": "stage-company-openai",
                "model": args.model,
                "guarded_models_visible": model_count,
                "router_canary_validated": True,
                "local_route_changed": False,
                "provider_published": False,
                "budget_configured": False,
                "environment_mode": oct(stat.S_IMODE(env_path.stat().st_mode)),
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
