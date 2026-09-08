#!/usr/bin/env python3
"""Commission the guarded company OpenAI route without exposing secrets.

Preflight mode reads only the gateway administrator password from stdin and
proves that the bootstrap credential has already been rotated. Full mode reads
a small JSON object containing the OpenAI key and administrator password from
stdin, then runs the existing fail-closed transactions in their required order.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import http.cookiejar
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any
import urllib.error
import urllib.request


SCRIPT_DIR = Path(__file__).resolve().parent
ENV_PATH = Path(
    os.environ.get("AI_GATEWAY_ENV_PATH", "/opt/ai-gateway/archestra/.env")
)
BASE_URL = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_URL", "https://192.0.2.10"
).rstrip("/")
ORIGIN = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_ORIGIN", "https://192.0.2.10"
).rstrip("/")
ADMIN_EMAIL = os.environ.get("ARCHESTRA_ACCEPTANCE_ADMIN_EMAIL", "admin@example.com")
TEST_MODE = os.environ.get("AI_GATEWAY_COMMISSION_TEST_MODE") == "true"
MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
KEY_PATTERN = re.compile(r"^sk-[A-Za-z0-9_-]{20,4093}$")
CONFIRMATION = "COMMISSION_COMPANY_OPENAI"


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def positive_decimal(name: str, raw: str | None) -> str:
    if raw is None:
        raise SystemExit(f"{name} is required")
    try:
        value = Decimal(raw)
    except InvalidOperation as error:
        raise SystemExit(f"{name} must be a positive decimal") from error
    if not value.is_finite() or value <= 0:
        raise SystemExit(f"{name} must be a positive decimal")
    return format(value, "f")


class Client:
    def __init__(self) -> None:
        cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookies)
        )

    def call(self, path: str, method: str = "GET", payload: dict | None = None) -> tuple[int, Any]:
        body = None if payload is None else json.dumps(payload).encode()
        headers = {"Accept": "application/json", "Origin": ORIGIN, "Referer": ORIGIN + "/"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            BASE_URL + path, data=body, headers=headers, method=method
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read().decode(errors="replace")
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raw = error.read().decode(errors="replace")
            try:
                data = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                data = None
            return error.code, data


def preflight_admin(password: str) -> None:
    if TEST_MODE:
        if os.environ.get("AI_GATEWAY_COMMISSION_TEST_BOOTSTRAP_ROTATED", "true") != "true":
            raise RuntimeError("bootstrap administrator password must be rotated first")
        return
    client = Client()
    status, _ = client.call(
        "/api/auth/sign-in/email",
        "POST",
        {"email": ADMIN_EMAIL, "password": password},
    )
    if status not in (200, 201):
        raise RuntimeError(f"administrator login failed with HTTP {status}")
    status, credential = client.call("/api/auth/default-credentials-status")
    if (
        status != 200
        or not isinstance(credential, dict)
        or credential.get("enabled") is not False
    ):
        raise RuntimeError("bootstrap administrator password must be rotated first")


def validate_environment() -> None:
    if not ENV_PATH.is_file():
        raise RuntimeError(f"gateway environment file was not found: {ENV_PATH}")
    if os.name != "nt" and stat.S_IMODE(ENV_PATH.stat().st_mode) != 0o600:
        raise RuntimeError("gateway environment file must have mode 0600")
    values = parse_env(ENV_PATH)
    required = (
        "DLP_ADMIN_API_KEY",
        "DLP_DB_PASSWORD",
        "DLP_IDENTITY_HMAC_KEY",
        "DLP_MANAGED_GROUP_ID",
    )
    missing = [name for name in required if not values.get(name)]
    if missing:
        raise RuntimeError("gateway environment is missing required guarded-route settings")


def redacted(value: str, secrets: tuple[str, ...]) -> str:
    output = value
    for secret in secrets:
        if secret:
            output = output.replace(secret, "[REDACTED]")
    output = re.sub(r"sk-[A-Za-z0-9_-]{20,}", "[REDACTED]", output)
    return output


def run_step(
    name: str,
    command: list[str],
    environment: dict[str, str],
    *,
    stdin_text: str | None = None,
    secrets: tuple[str, ...] = (),
) -> dict[str, Any]:
    if TEST_MODE:
        if os.environ.get("AI_GATEWAY_COMMISSION_INJECT_FAILURE") == name:
            raise RuntimeError(f"{name} failed in test mode")
        return {"status": "PASS", "action": name}
    completed = subprocess.run(
        command,
        cwd=SCRIPT_DIR,
        env=environment,
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    if completed.returncode != 0:
        detail = redacted(completed.stderr.strip(), secrets)[-1000:]
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"{name} failed with exit code {completed.returncode}{suffix}")
    for line in reversed(completed.stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return {"status": "PASS", "action": name}


def read_full_payload() -> tuple[str, str]:
    raw = sys.stdin.read(16385)
    if len(raw) > 16384:
        raise SystemExit("commissioning input is too large")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SystemExit("standard input must be a commissioning JSON object") from error
    if not isinstance(payload, dict):
        raise SystemExit("standard input must be a commissioning JSON object")
    api_key = payload.get("openai_api_key")
    password = payload.get("archestra_admin_password")
    payload.clear()
    if not isinstance(api_key, str) or not KEY_PATTERN.fullmatch(api_key.strip()):
        raise SystemExit("commissioning input does not contain a validly shaped OpenAI API key")
    if not isinstance(password, str) or not password.strip():
        raise SystemExit("commissioning input does not contain an administrator password")
    return api_key.strip(), password


def main() -> int:
    parser = argparse.ArgumentParser(description="Commission the guarded company OpenAI route.")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--model")
    parser.add_argument("--monthly-budget")
    parser.add_argument("--input-price-per-million")
    parser.add_argument("--output-price-per-million")
    parser.add_argument("--confirm")
    args = parser.parse_args()

    if not TEST_MODE and os.geteuid() != 0:
        raise SystemExit("run commission-company-openai.py with sudo")

    if args.preflight_only:
        password = sys.stdin.read(4097)
        if len(password) > 4096 or not password.strip():
            raise SystemExit("standard input does not contain an administrator password")
        validate_environment()
        preflight_admin(password.strip())
        password = ""
        print(json.dumps({"status": "PASS", "action": "company-openai-preflight", "bootstrap_admin_rotated": True}, separators=(",", ":")))
        return 0

    if not isinstance(args.model, str) or not MODEL_PATTERN.fullmatch(args.model):
        raise SystemExit("--model is required and contains unsupported characters")
    monthly_budget = positive_decimal("--monthly-budget", args.monthly_budget)
    input_price = positive_decimal(
        "--input-price-per-million", args.input_price_per_million
    )
    output_price = positive_decimal(
        "--output-price-per-million", args.output_price_per_million
    )
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"--confirm must equal {CONFIRMATION}")

    validate_environment()
    api_key, password = read_full_payload()
    preflight_admin(password)

    temporary_dir = os.environ.get("AI_GATEWAY_SECRET_TMPDIR", "/run")
    descriptor, password_path_text = tempfile.mkstemp(
        prefix="ai-gateway-admin.", dir=temporary_dir, text=True
    )
    password_path = Path(password_path_text)
    steps: list[str] = []
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(password + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(password_path, 0o600)

        environment = os.environ.copy()
        environment.update(
            {
                "ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD_FILE": str(password_path),
            }
        )

        commands = [
            ("stage-company-openai", [sys.executable, "stage-company-openai.py", "--model", args.model], api_key),
            (
                "activate-managed-routing",
                [
                    sys.executable,
                    "activate-managed-routing.py",
                    "--monthly-budget",
                    monthly_budget,
                    "--input-price-per-million",
                    input_price,
                    "--output-price-per-million",
                    output_price,
                    "--confirm",
                    "ENABLE_LOCAL_FIRST_ROUTING",
                ],
                None,
            ),
        ]
        for name, command, stdin_text in commands:
            run_step(
                name,
                command,
                environment,
                stdin_text=stdin_text,
                secrets=(api_key, password),
            )
            steps.append(name)
            if name == "stage-company-openai":
                api_key = ""
    finally:
        password = ""
        api_key = ""
        try:
            password_path.unlink(missing_ok=True)
        except OSError:
            pass

    print(
        json.dumps(
            {
                "status": "PASS",
                "action": "commission-company-openai",
                "model": args.model,
                "monthly_external_budget_usd": monthly_budget,
                "input_price_per_million_usd": input_price,
                "output_price_per_million_usd": output_price,
                "completed_steps": steps,
                "test_mode": TEST_MODE,
                "existing_client_route_activated": not TEST_MODE,
                "local_and_external_routes_verified": not TEST_MODE,
                "secret_input_retained": False,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
