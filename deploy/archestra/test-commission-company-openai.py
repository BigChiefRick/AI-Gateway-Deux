#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


SCRIPT = Path(__file__).with_name("commission-company-openai.py")
API_KEY = "sk-test_commission_key_1234567890"  # gitleaks:allow -- synthetic transaction fixture
PASSWORD = "commission-admin-password"


def run_case(
    environment: dict[str, str],
    arguments: list[str],
    stdin_text: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        env=environment,
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    env_path = root / ".env"
    env_path.write_text(
        "DLP_ADMIN_API_KEY=test-admin\n"
        "DLP_DB_PASSWORD=test-db\n"
        "DLP_IDENTITY_HMAC_KEY=test-identity\n"
        "DLP_MANAGED_GROUP_ID=test-team\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    environment = os.environ.copy()
    environment.update(
        {
            "AI_GATEWAY_COMMISSION_TEST_MODE": "true",
            "AI_GATEWAY_ENV_PATH": str(env_path),
            "AI_GATEWAY_SECRET_TMPDIR": str(root),
        }
    )

    preflight = run_case(environment, ["--preflight-only"], PASSWORD)
    if preflight.returncode != 0:
        raise AssertionError(preflight.stderr)
    preflight_output = json.loads(preflight.stdout)
    if preflight_output.get("bootstrap_admin_rotated") is not True:
        raise AssertionError("preflight did not prove bootstrap rotation")

    arguments = [
        "--model",
        "gpt-test",
        "--monthly-budget",
        "20.00",
        "--input-price-per-million",
        "1.25",
        "--output-price-per-million",
        "10.00",
        "--confirm",
        "COMMISSION_COMPANY_OPENAI",
    ]
    payload = json.dumps(
        {"openai_api_key": API_KEY, "archestra_admin_password": PASSWORD}
    )
    success = run_case(environment, arguments, payload)
    if success.returncode != 0:
        raise AssertionError(success.stderr)
    output = json.loads(success.stdout)
    expected_steps = [
        "stage-company-openai",
        "activate-managed-routing",
    ]
    if output.get("completed_steps") != expected_steps:
        raise AssertionError("commissioning steps ran in the wrong order")
    if (
        output.get("test_mode") is not True
        or output.get("existing_client_route_activated") is not False
        or output.get("local_and_external_routes_verified") is not False
    ):
        raise AssertionError("test mode overstated live commissioning results")
    if API_KEY in success.stdout + success.stderr or PASSWORD in success.stdout + success.stderr:
        raise AssertionError("commissioning output exposed a secret")
    if any(root.glob("ai-gateway-admin.*")):
        raise AssertionError("temporary administrator password file was retained")
    if os.name != "nt" and stat.S_IMODE(env_path.stat().st_mode) != 0o600:
        raise AssertionError("gateway environment mode changed")

    failed_environment = environment.copy()
    failed_environment["AI_GATEWAY_COMMISSION_INJECT_FAILURE"] = "activate-managed-routing"
    failed = run_case(failed_environment, arguments, payload)
    if failed.returncode == 0 or "activate-managed-routing failed" not in failed.stderr:
        raise AssertionError("injected commissioning failure did not fail closed")
    if API_KEY in failed.stdout + failed.stderr or PASSWORD in failed.stdout + failed.stderr:
        raise AssertionError("failure output exposed a secret")
    if any(root.glob("ai-gateway-admin.*")):
        raise AssertionError("failure retained the temporary password file")

    unrotated_environment = environment.copy()
    unrotated_environment["AI_GATEWAY_COMMISSION_TEST_BOOTSTRAP_ROTATED"] = "false"
    unrotated = run_case(unrotated_environment, ["--preflight-only"], PASSWORD)
    if unrotated.returncode == 0 or "must be rotated first" not in unrotated.stderr:
        raise AssertionError("unrotated bootstrap credential passed preflight")

    invalid = run_case(environment, arguments, json.dumps({"openai_api_key": "bad", "archestra_admin_password": PASSWORD}))
    if invalid.returncode == 0 or API_KEY in invalid.stdout + invalid.stderr or PASSWORD in invalid.stdout + invalid.stderr:
        raise AssertionError("invalid secret input was not rejected safely")

print("COMPANY_OPENAI_COMMISSION_TRANSACTION_TEST_OK")
