#!/usr/bin/env python3
"""Atomically stage the existing Mem0 key from stdin without disclosing it."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile


path = Path(os.environ.get("ARCHESTRA_DEPLOYMENT_ENV", ".env")).resolve()
key = sys.stdin.read().strip()
if len(key) < 20 or "\n" in key or "\r" in key:
    raise SystemExit("Invalid Mem0 credential input")
if not path.is_file():
    raise SystemExit("Deployment environment does not exist")
if os.name != "nt" and path.stat().st_mode & 0o777 != 0o600:
    raise SystemExit("Deployment environment must be mode 0600")

lines = path.read_text(encoding="utf-8").splitlines()
replacement = "MEM0_API_KEY=" + key
for index, line in enumerate(lines):
    if line.startswith("MEM0_API_KEY="):
        lines[index] = replacement
        break
else:
    lines.append(replacement)

descriptor, temporary_name = tempfile.mkstemp(
    prefix=".env.mem0.", dir=path.parent
)
temporary = Path(temporary_name)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        target.write("\n".join(lines) + "\n")
        target.flush()
        os.fsync(target.fileno())
    os.replace(temporary, path)
finally:
    temporary.unlink(missing_ok=True)

print("PASS: Mem0 credential staged in mode-0600 deployment environment")
