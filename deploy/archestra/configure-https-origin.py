#!/usr/bin/env python3
"""Atomically configure the non-secret HTTPS and recovery origins in .env."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_HTTPS_ORIGIN = "https://gateway.example.com"
DEFAULT_HTTPS_RECOVERY_ORIGIN = "https://192.0.2.10"
DEFAULT_HTTP_UI = "http://192.0.2.10:3000"
DEFAULT_HTTP_API = "http://192.0.2.10:9000"


def validated_origin(value: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError("HTTPS origin must be an origin without credentials, path, query, or fragment")
    return value.rstrip("/")


def update_env(path: Path, values: dict[str, str]) -> None:
    original = path.read_text(encoding="utf-8")
    lines = original.splitlines()
    written: set[str] = set()
    output: list[str] = []
    for line in lines:
        if line and not line.lstrip().startswith("#") and "=" in line:
            key = line.split("=", 1)[0]
            if key in values:
                if key not in written:
                    output.append(f"{key}={values[key]}")
                    written.add(key)
                continue
        output.append(line)
    for key, value in values.items():
        if key not in written:
            output.append(f"{key}={value}")

    mode = stat.S_IMODE(path.stat().st_mode)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".https-origin.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(output) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument(
        "--https-origin",
        default=os.environ.get("AI_GATEWAY_HTTPS_ORIGIN", DEFAULT_HTTPS_ORIGIN),
    )
    args = parser.parse_args()
    origin = validated_origin(args.https_origin)
    if not args.env_file.is_file():
        raise SystemExit(f"Environment file does not exist: {args.env_file}")

    values = {
        "ARCHESTRA_FRONTEND_URL": origin,
        "ARCHESTRA_API_BASE_URL": (
            f"{origin},{DEFAULT_HTTPS_RECOVERY_ORIGIN},{DEFAULT_HTTP_API}"
        ),
        "ARCHESTRA_AUTH_ADDITIONAL_TRUSTED_ORIGINS": (
            f"{origin},{DEFAULT_HTTPS_RECOVERY_ORIGIN},{DEFAULT_HTTP_UI},{DEFAULT_HTTP_API}"
        ),
        "ARCHESTRA_SESSION_ORIGIN": origin,
    }
    update_env(args.env_file, values)
    print(json.dumps({"status": "PASS", "https_origin": origin, "http_recovery": True}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
