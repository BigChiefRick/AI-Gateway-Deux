#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


SCRIPT = Path(__file__).with_name("activate-managed-routing.py")


def run_case(
    environment: dict[str, str], inject_failure: str | None = None
) -> subprocess.CompletedProcess[str]:
    selected = environment.copy()
    if inject_failure:
        selected["AI_GATEWAY_ACTIVATE_INJECT_FAILURE"] = inject_failure
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--monthly-budget",
            "25.50",
            "--input-price-per-million",
            "1.25",
            "--output-price-per-million",
            "10.00",
            "--confirm",
            "ENABLE_LOCAL_FIRST_ROUTING",
        ],
        env=selected,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


with tempfile.TemporaryDirectory() as directory:
    env_path = Path(directory) / ".env"
    baseline = (
        "DLP_ADMIN_API_KEY=test-admin\n"
        "DLP_POLICY_API_KEY=test-policy\n"
        "DLP_IDENTITY_HMAC_KEY=test-hmac\n"
        "DLP_MANAGED_GROUP_ID=test-group\n"
        "OPENAI_API_KEY=sk-test-activation-secret\n"
        "OPENAI_DLP_DEFAULT_MODEL=gpt-test\n"
        "DLP_EXTERNAL_ENABLED=false\n"
        "DLP_MANAGED_ROUTING_MODE=local_only\n"
    )
    env_path.write_text(baseline, encoding="utf-8")
    env_path.chmod(0o600)
    environment = os.environ.copy()
    environment.update(
        {
            "AI_GATEWAY_ACTIVATE_TEST_MODE": "true",
            "AI_GATEWAY_ENV_PATH": str(env_path),
        }
    )

    success = run_case(environment)
    if success.returncode != 0:
        raise AssertionError(success.stderr)
    payload = json.loads(success.stdout)
    if payload.get("routing_mode") != "local_first":
        raise AssertionError(payload)
    activated = env_path.read_text(encoding="utf-8")
    for expected in (
        "DLP_EXTERNAL_ENABLED=true",
        "DLP_MANAGED_ROUTING_MODE=local_first",
        "DLP_EXTERNAL_MONTHLY_BUDGET_USD=25.50",
        "DLP_EXTERNAL_INPUT_PRICE_PER_MILLION_USD=1.25",
        "DLP_EXTERNAL_OUTPUT_PRICE_PER_MILLION_USD=10.00",
    ):
        if expected not in activated:
            raise AssertionError(f"missing activated setting: {expected}")
    if "sk-test-activation-secret" in success.stdout + success.stderr:
        raise AssertionError("activation output exposed the provider secret")
    if os.name != "nt" and stat.S_IMODE(env_path.stat().st_mode) != 0o600:
        raise AssertionError("activation changed environment mode")

    env_path.write_text(baseline, encoding="utf-8")
    env_path.chmod(0o600)
    failed = run_case(environment, "configure-managed-routing")
    if failed.returncode == 0 or "configure-managed-routing failed" not in failed.stderr:
        raise AssertionError("injected activation failure did not fail")
    if env_path.read_text(encoding="utf-8") != baseline:
        raise AssertionError("activation failure did not restore environment")
    if "sk-test-activation-secret" in failed.stdout + failed.stderr:
        raise AssertionError("activation failure exposed the provider secret")


spec = importlib.util.spec_from_file_location("activate_managed_routing", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load activate-managed-routing.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.TEST_MODE = False


class ReadyResponse:
    status = 200

    def __enter__(self) -> "ReadyResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return b'{"status":"ready"}'


health_states = iter(["starting", "healthy"])
inspect_calls = 0


def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
    global inspect_calls
    inspect_calls += 1
    state = next(health_states)
    return subprocess.CompletedProcess(command, 0, stdout=state + "\n", stderr="")


module.urllib.request.urlopen = lambda *_args, **_kwargs: ReadyResponse()
module.subprocess.run = fake_run
module.time.sleep = lambda _seconds: None
module.wait_ready("127.0.0.1")
if inspect_calls != 2:
    raise AssertionError("readiness returned before Docker health became healthy")

print("MANAGED_ROUTING_ACTIVATION_TRANSACTION_TEST_OK")
