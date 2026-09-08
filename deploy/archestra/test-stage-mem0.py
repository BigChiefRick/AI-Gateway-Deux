#!/usr/bin/env python3
"""Regression test for secret-safe Mem0 staging."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


script = Path(__file__).with_name("stage-mem0.py")
with tempfile.TemporaryDirectory() as directory:
    target = Path(directory) / ".env"
    target.write_text("EXISTING=value\nMEM0_API_KEY=old-value\n", encoding="utf-8")
    target.chmod(0o600)
    secret = "mem0-test-value-that-must-not-be-printed"
    environment = os.environ.copy()
    environment["ARCHESTRA_DEPLOYMENT_ENV"] = str(target)
    completed = subprocess.run(
        [sys.executable, str(script)],
        input=secret,
        text=True,
        capture_output=True,
        env=environment,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    if secret in completed.stdout or secret in completed.stderr:
        raise AssertionError("Mem0 staging disclosed its credential")
    if os.name != "nt" and target.stat().st_mode & 0o777 != 0o600:
        raise AssertionError("Mem0 staging changed the environment mode")
    if target.read_text(encoding="utf-8") != (
        "EXISTING=value\nMEM0_API_KEY=" + secret + "\n"
    ):
        raise AssertionError("Mem0 staging did not atomically replace the value")

print("STAGE_MEM0_TRANSACTION_TEST_OK")
