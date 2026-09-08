#!/usr/bin/env python3
"""Secret-safe transaction tests for company OpenAI staging."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


SCRIPT = Path(__file__).with_name("stage-company-openai.py")
TEST_KEY = "sk-" + "test_" + "abcdefghijklmnopqrstuvwxyz0123456789"
BASE_ENV = """ARCHESTRA_BIND_ADDRESS=192.0.2.10
DLP_ADMIN_API_KEY=admin-test-only
DLP_DB_PASSWORD=db-test-only
DLP_IDENTITY_HMAC_KEY=identity-test-only
DLP_MANAGED_GROUP_ID=00000000-0000-4000-8000-000000001004
OPENAI_API_KEY=
OPENAI_DLP_POLICY_API_KEY=
OPENAI_DLP_ALLOWED_MODELS=
OPENAI_DLP_DEFAULT_MODEL=
OPENAI_DLP_POLICY_GROUP=
"""


def run(env_path: Path, *, inject: bool = False, key: str = TEST_KEY) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "AI_GATEWAY_ENV_PATH": str(env_path),
            "AI_GATEWAY_STAGE_TEST_MODE": "true",
        }
    )
    if inject:
        env["AI_GATEWAY_STAGE_INJECT_FAILURE"] = "after_env"
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--model", "gpt-approved-test"],
        input=key,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        env_path = Path(directory) / ".env"
        env_path.write_text(BASE_ENV, encoding="utf-8")
        os.chmod(env_path, 0o600)

        success = run(env_path)
        if success.returncode != 0:
            raise AssertionError(success.stderr or success.stdout)
        payload = json.loads(success.stdout)
        if payload["status"] != "PASS" or payload["local_route_changed"] is not False:
            raise AssertionError(payload)
        if payload["router_canary_validated"] is not True:
            raise AssertionError(payload)
        if TEST_KEY in success.stdout or TEST_KEY in success.stderr:
            raise AssertionError("OpenAI secret leaked to process output")
        staged = env_path.read_text(encoding="utf-8")
        for expected in (
            f"OPENAI_API_KEY={TEST_KEY}",
            "OPENAI_DLP_ALLOWED_MODELS=gpt-approved-test",
            "OPENAI_DLP_DEFAULT_MODEL=gpt-approved-test",
        ):
            if expected not in staged:
                raise AssertionError(f"missing staged value: {expected.split('=', 1)[0]}")
        if os.name != "nt" and stat.S_IMODE(env_path.stat().st_mode) != 0o600:
            raise AssertionError("staged environment mode is not 0600")

        env_path.write_text(BASE_ENV, encoding="utf-8")
        os.chmod(env_path, 0o640)
        failure = run(env_path, inject=True)
        if failure.returncode == 0:
            raise AssertionError("injected staging failure unexpectedly passed")
        if env_path.read_text(encoding="utf-8") != BASE_ENV:
            raise AssertionError("failed staging did not restore the original environment")
        if os.name != "nt" and stat.S_IMODE(env_path.stat().st_mode) != 0o640:
            raise AssertionError("failed staging did not restore the original mode")

        invalid = run(env_path, key="not-an-api-key")
        if invalid.returncode == 0 or env_path.read_text(encoding="utf-8") != BASE_ENV:
            raise AssertionError("invalid key changed the environment")

    print("STAGE_COMPANY_OPENAI_TRANSACTION_TEST_OK")


if __name__ == "__main__":
    main()
