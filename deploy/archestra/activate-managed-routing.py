#!/usr/bin/env python3
"""Atomically activate the existing gateway endpoint as a local-first router.

The paid-provider secret/model must already have passed stage-company-openai.py.
This transaction persists only non-secret routing controls, restarts the live
policy service, verifies the protected stack, then proves local and external
routes through configure-managed-routing.py. Any failure restores the original
environment and local-only runtime.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


SCRIPT_DIR = Path(__file__).resolve().parent
ENV_PATH = Path(
    os.environ.get("AI_GATEWAY_ENV_PATH", "/opt/ai-gateway/archestra/.env")
)
CONFIRMATION = "ENABLE_LOCAL_FIRST_ROUTING"
TEST_MODE = os.environ.get("AI_GATEWAY_ACTIVATE_TEST_MODE") == "true"


def load_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def updated_env(text: str, updates: dict[str, str]) -> str:
    remaining = dict(updates)
    output: list[str] = []
    for line in text.splitlines():
        if line and not line.lstrip().startswith("#") and "=" in line:
            key = line.split("=", 1)[0]
            if key in remaining:
                output.append(f"{key}={remaining.pop(key)}")
                continue
        output.append(line)
    if remaining and output and output[-1]:
        output.append("")
    output.extend(f"{key}={value}" for key, value in remaining.items())
    return "\n".join(output) + "\n"


def atomic_write(path: Path, text: str, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".", dir=path.parent, text=True
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def positive_decimal(name: str, raw: str) -> str:
    try:
        value = Decimal(raw)
    except InvalidOperation as error:
        raise SystemExit(f"{name} must be a positive decimal") from error
    if not value.is_finite() or value <= 0:
        raise SystemExit(f"{name} must be a positive decimal")
    return format(value, "f")


def run_step(name: str, command: list[str]) -> None:
    if TEST_MODE:
        if os.environ.get("AI_GATEWAY_ACTIVATE_INJECT_FAILURE") == name:
            raise RuntimeError(f"{name} failed in test mode")
        return
    completed = subprocess.run(
        command,
        cwd=SCRIPT_DIR,
        capture_output=True,
        text=True,
        timeout=1200,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip()[-1000:]
        raise RuntimeError(
            f"{name} failed with exit code {completed.returncode}"
            + (f": {detail}" if detail else "")
        )


def wait_ready(bind_address: str) -> None:
    if TEST_MODE:
        return
    url = f"http://{bind_address}:4200/readyz"
    last_error = "not started"
    for _attempt in range(60):
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                body = json.load(response)
            if response.status == 200 and body.get("status") == "ready":
                inspected = subprocess.run(
                    [
                        "docker",
                        "inspect",
                        "--format",
                        "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                        "ai-gateway-dlp",
                    ],
                    cwd=SCRIPT_DIR,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                container_health = inspected.stdout.strip()
                if inspected.returncode == 0 and container_health == "healthy":
                    return
                last_error = (
                    "HTTP readiness passed but Docker health is "
                    f"{container_health or 'unavailable'}"
                )
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
            last_error = f"{type(error).__name__}: {error}"
        time.sleep(2)
    raise RuntimeError(f"live DLP service did not become ready: {last_error}")


def restart_live(bind_address: str) -> None:
    run_step(
        "restart-live-router",
        [
            "docker",
            "compose",
            "up",
            "-d",
            "--force-recreate",
            "dlp-policy",
        ],
    )
    wait_ready(bind_address)


def main() -> int:
    parser = argparse.ArgumentParser(description="Activate managed local-first routing.")
    parser.add_argument("--monthly-budget", required=True)
    parser.add_argument("--input-price-per-million", required=True)
    parser.add_argument("--output-price-per-million", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"--confirm must equal {CONFIRMATION}")

    budget = positive_decimal("--monthly-budget", args.monthly_budget)
    input_price = positive_decimal(
        "--input-price-per-million", args.input_price_per_million
    )
    output_price = positive_decimal(
        "--output-price-per-million", args.output_price_per_million
    )
    if not ENV_PATH.is_file():
        raise RuntimeError(f"gateway environment file was not found: {ENV_PATH}")
    original_text = ENV_PATH.read_text(encoding="utf-8")
    original_mode = stat.S_IMODE(ENV_PATH.stat().st_mode)
    values = load_env(original_text)
    required = (
        "DLP_ADMIN_API_KEY",
        "DLP_POLICY_API_KEY",
        "DLP_IDENTITY_HMAC_KEY",
        "DLP_MANAGED_GROUP_ID",
        "OPENAI_API_KEY",
        "OPENAI_DLP_DEFAULT_MODEL",
    )
    missing = [name for name in required if not values.get(name)]
    if missing:
        raise RuntimeError("Missing managed routing prerequisites: " + ", ".join(missing))

    updates = {
        "DLP_EXTERNAL_ENABLED": "true",
        "DLP_MANAGED_ROUTING_MODE": "local_first",
        "DLP_EXTERNAL_MONTHLY_BUDGET_USD": budget,
        "DLP_EXTERNAL_INPUT_PRICE_PER_MILLION_USD": input_price,
        "DLP_EXTERNAL_OUTPUT_PRICE_PER_MILLION_USD": output_price,
    }
    bind_address = values.get("DLP_BIND_ADDRESS") or values.get(
        "ARCHESTRA_BIND_ADDRESS", "192.0.2.10"
    )

    atomic_write(ENV_PATH, updated_env(original_text, updates), original_mode)
    try:
        restart_live(bind_address)
        run_step("verify-protected-stack", ["bash", "./verify.sh"])
        run_step(
            "configure-managed-routing",
            [
                sys.executable,
                "configure-managed-routing.py",
                "--monthly-budget",
                budget,
                "--input-price-per-million",
                input_price,
                "--output-price-per-million",
                output_price,
                "--confirm",
                CONFIRMATION,
            ],
        )
    except BaseException:
        atomic_write(ENV_PATH, original_text, original_mode)
        try:
            restart_live(bind_address)
        except Exception as rollback_error:
            print(
                f"WARNING: environment restored but local runtime restart failed: {rollback_error}",
                file=sys.stderr,
            )
        raise

    if not TEST_MODE:
        subprocess.run(
            [
                "docker",
                "compose",
                "--profile",
                "router-canary",
                "rm",
                "-s",
                "-f",
                "dlp-router-canary",
            ],
            cwd=SCRIPT_DIR,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    print(
        json.dumps(
            {
                "status": "PASS",
                "action": "activate-managed-routing",
                "routing_mode": "local_first",
                "external_provider_enabled": True,
                "monthly_budget_usd": budget,
                "local_and_external_canaries": True,
                "rollback_armed": True,
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
