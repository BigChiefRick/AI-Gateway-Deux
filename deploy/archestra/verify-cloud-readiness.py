#!/usr/bin/env python3
"""Read-only acceptance gate for a guarded, metered cloud-provider route.

The script never prints provider credentials, cookies, or the administrator
password. It deliberately exits non-zero until every required control is live.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any


BASE_URL = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_URL", "https://192.0.2.10"
).rstrip("/")
ORIGIN = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_ORIGIN", "https://192.0.2.10"
).rstrip("/")
ADMIN_EMAIL = os.environ.get("ARCHESTRA_ACCEPTANCE_ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD", "")
ADMIN_PASSWORD_FILE = os.environ.get("ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD_FILE", "")
PROVIDER = os.environ.get("ARCHESTRA_CLOUD_PROVIDER", "openai").strip()
MODEL = os.environ.get("ARCHESTRA_CLOUD_MODEL", "").strip()
EXPECTED_BASE_URL = os.environ.get(
    "ARCHESTRA_EXPECTED_CLOUD_BASE_URL", "http://192.0.2.10:4201/v1"
).rstrip("/")
DLP_HEALTH_URL = os.environ.get(
    "ARCHESTRA_CLOUD_DLP_HEALTH_URL", "http://192.0.2.10:4201/readyz"
)


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


env = load_env(Path(".env"))
MANAGED_GROUP_ID = os.environ.get("DLP_MANAGED_GROUP_ID") or env.get(
    "DLP_MANAGED_GROUP_ID", ""
)


if not ADMIN_PASSWORD and ADMIN_PASSWORD_FILE:
    ADMIN_PASSWORD = Path(ADMIN_PASSWORD_FILE).read_text(encoding="utf-8").strip()
if not ADMIN_PASSWORD:
    raise SystemExit("ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD is required")


@dataclass
class Result:
    status: int
    data: Any
    text: str


class Client:
    def __init__(self) -> None:
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )

    def call(self, path: str, method: str = "GET", payload: dict | None = None) -> Result:
        body = None if payload is None else json.dumps(payload).encode()
        headers = {
            "Accept": "application/json",
            "Origin": ORIGIN,
            "Referer": ORIGIN + "/",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            BASE_URL + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=60) as response:
                text = response.read().decode(errors="replace")
                try:
                    data = json.loads(text) if text else None
                except json.JSONDecodeError:
                    data = None
                return Result(response.status, data, text)
        except urllib.error.HTTPError as error:
            text = error.read().decode(errors="replace")
            try:
                data = json.loads(text) if text else None
            except json.JSONDecodeError:
                data = None
            return Result(error.code, data, text)


def require_list(client: Client, path: str) -> list[dict[str, Any]]:
    result = client.call(path)
    if result.status != 200 or not isinstance(result.data, list):
        raise RuntimeError(f"{path} returned HTTP {result.status}, expected a JSON list")
    return [item for item in result.data if isinstance(item, dict)]


def positive_price(value: Any) -> bool:
    try:
        return Decimal(str(value or "0")) > 0
    except InvalidOperation:
        return False


def model_applies(configured: Any, model: str) -> bool:
    if not model:
        return True
    return configured is None or configured == [] or model in configured


def check_dlp() -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(DLP_HEALTH_URL, timeout=15) as response:
            payload = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        return False, f"unavailable ({type(error).__name__})"
    ready = (
        response.status == 200
        and isinstance(payload, dict)
        and payload.get("status") == "ready"
        and payload.get("guardrail_database") == "connected"
        and payload.get("policy_auth") == "configured"
        and payload.get("upstream") == "configured"
        and payload.get("signed_identity") == "configured"
    )
    return ready, "ready" if ready else "degraded"


client = Client()
login = client.call(
    "/api/auth/sign-in/email",
    "POST",
    {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
)
if login.status not in (200, 201):
    raise SystemExit(f"administrator login failed with HTTP {login.status}")

provider_keys = require_list(client, "/api/llm-provider-api-keys")
models = require_list(client, "/api/llm-models")
limits = require_list(client, "/api/limits?limitType=token_cost")
default_limits = require_list(client, "/api/default-user-limits")

credential_status = client.call("/api/auth/default-credentials-status")
if credential_status.status != 200 or not isinstance(credential_status.data, dict):
    raise RuntimeError(
        "default credential status returned "
        f"HTTP {credential_status.status}, expected a JSON object"
    )

matching_providers = [
    item
    for item in provider_keys
    if item.get("provider") == PROVIDER
    and item.get("isChatgptSubscription") is not True
    and item.get("secretStorageType") not in (None, "none")
    and (item.get("baseUrl") or "").rstrip("/") == EXPECTED_BASE_URL
    and item.get("scope") == "team"
    and bool(MANAGED_GROUP_ID)
    and item.get("teamId") == MANAGED_GROUP_ID
]

matching_models = [
    item
    for item in models
    if item.get("provider") == PROVIDER
    and (not MODEL or item.get("modelId") == MODEL)
    and positive_price(item.get("pricePerMillionInput"))
    and positive_price(item.get("pricePerMillionOutput"))
]

org_limits = [
    item
    for item in limits
    if item.get("entityType") == "organization"
    and item.get("limitType") == "token_cost"
    and isinstance(item.get("limitValue"), int)
    and item["limitValue"] > 0
    and model_applies(item.get("model"), MODEL)
]

org_default_user_limits = [
    item
    for item in default_limits
    if item.get("environmentId") is None
    and isinstance(item.get("limitValue"), int)
    and item["limitValue"] > 0
    and model_applies(item.get("model"), MODEL)
]

dlp_ready, dlp_detail = check_dlp()
checks = {
    "bootstrap_admin_rotated": credential_status.data.get("enabled") is False,
    "guarded_provider_credential": bool(matching_providers),
    "cloud_dlp_ready": dlp_ready,
    "priced_cloud_model": bool(matching_models),
    "organization_cost_limit": bool(org_limits),
    "default_user_cost_limit": bool(org_default_user_limits),
}
pending = [name for name, passed in checks.items() if not passed]

output = {
    "status": "PASS" if not pending else "NOT_READY",
    "provider": PROVIDER,
    "model": MODEL or "any-priced-model",
    "expected_guarded_base_url": EXPECTED_BASE_URL,
    "checks": checks,
    "pending": pending,
    "observed": {
        "matching_provider_credentials": len(matching_providers),
        "matching_priced_models": len(matching_models),
        "organization_cost_limits": len(org_limits),
        "default_user_cost_limits": len(org_default_user_limits),
        "cloud_dlp": dlp_detail,
    },
}
print(json.dumps(output, separators=(",", ":")))
sys.exit(0 if not pending else 2)
