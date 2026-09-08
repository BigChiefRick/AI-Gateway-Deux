#!/usr/bin/env python3
"""Transactionally apply approved cloud-model spend limits in Archestra.

The script changes only the model-specific organization token-cost limit and
the organization-wide default-user limit. It verifies the guarded provider,
reviewed non-zero pricing, and bootstrap-password rotation before mutation.
If the second write or final verification fails, completed writes are restored.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
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
ORG_LIMIT_RAW = os.environ.get("ARCHESTRA_ORGANIZATION_LIMIT_DOLLARS", "")
USER_LIMIT_RAW = os.environ.get("ARCHESTRA_DEFAULT_USER_LIMIT_DOLLARS", "")
CLEANUP_INTERVAL = os.environ.get(
    "ARCHESTRA_CLOUD_LIMIT_INTERVAL", "calendar_month"
).strip()
CONFIRMATION = os.environ.get("ARCHESTRA_CONFIRM_BUDGETS", "")
EXPECTED_CONFIRMATION = "APPLY_CLOUD_BUDGETS"
VALID_INTERVALS = {
    "1h",
    "12h",
    "24h",
    "1w",
    "1m",
    "calendar_day",
    "calendar_week_sunday",
    "calendar_week_monday",
    "calendar_month",
}


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


def positive_integer(name: str, value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise SystemExit(f"{name} must be a positive whole-dollar integer") from error
    if parsed <= 0 or str(parsed) != value.strip():
        raise SystemExit(f"{name} must be a positive whole-dollar integer")
    return parsed


if not ADMIN_PASSWORD and ADMIN_PASSWORD_FILE:
    ADMIN_PASSWORD = Path(ADMIN_PASSWORD_FILE).read_text(encoding="utf-8").strip()
if not ADMIN_PASSWORD:
    raise SystemExit("ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD is required")
if not MODEL:
    raise SystemExit("ARCHESTRA_CLOUD_MODEL is required")
if not MANAGED_GROUP_ID:
    raise SystemExit(
        "DLP_MANAGED_GROUP_ID is required; run configure-team-dlp-identity.py first"
    )
if CLEANUP_INTERVAL not in VALID_INTERVALS:
    raise SystemExit("ARCHESTRA_CLOUD_LIMIT_INTERVAL is invalid")
if CONFIRMATION != EXPECTED_CONFIRMATION:
    raise SystemExit(
        f"ARCHESTRA_CONFIRM_BUDGETS must equal {EXPECTED_CONFIRMATION}"
    )

ORG_LIMIT = positive_integer("ARCHESTRA_ORGANIZATION_LIMIT_DOLLARS", ORG_LIMIT_RAW)
USER_LIMIT = positive_integer("ARCHESTRA_DEFAULT_USER_LIMIT_DOLLARS", USER_LIMIT_RAW)
if USER_LIMIT > ORG_LIMIT:
    raise SystemExit(
        "ARCHESTRA_DEFAULT_USER_LIMIT_DOLLARS cannot exceed the organization limit"
    )


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

    def call(
        self,
        path: str,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
    ) -> Result:
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
                return Result(
                    response.status,
                    json.loads(text) if text else None,
                    text,
                )
        except urllib.error.HTTPError as error:
            text = error.read().decode(errors="replace")
            try:
                data = json.loads(text) if text else None
            except json.JSONDecodeError:
                data = None
            return Result(error.code, data, text)


def require(result: Result, expected: tuple[int, ...], action: str) -> Any:
    if result.status not in expected:
        raise RuntimeError(f"{action} returned HTTP {result.status}")
    return result.data


def require_list(client: Client, path: str, action: str) -> list[dict[str, Any]]:
    data = require(client.call(path), (200,), action)
    if not isinstance(data, list):
        raise RuntimeError(f"{action} did not return a JSON list")
    return [item for item in data if isinstance(item, dict)]


def positive_price(value: Any) -> bool:
    try:
        return Decimal(str(value or "0")) > 0
    except InvalidOperation:
        return False


def model_set(value: Any) -> list[str]:
    return sorted(item for item in (value or []) if isinstance(item, str))


def require_dlp_ready() -> None:
    try:
        with urllib.request.urlopen(DLP_HEALTH_URL, timeout=15) as response:
            payload = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise RuntimeError("guarded cloud DLP is unavailable") from error
    if not (
        response.status == 200
        and isinstance(payload, dict)
        and payload.get("status") == "ready"
        and payload.get("guardrail_database") == "connected"
        and payload.get("policy_auth") == "configured"
        and payload.get("upstream") == "configured"
        and payload.get("signed_identity") == "configured"
    ):
        raise RuntimeError("guarded cloud DLP is not ready with signed identity")


client = Client()
require_dlp_ready()
require(
    client.call(
        "/api/auth/sign-in/email",
        "POST",
        {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    ),
    (200, 201),
    "administrator login",
)

session = require(client.call("/api/auth/get-session"), (200,), "get session")
session_state = session.get("session") if isinstance(session, dict) else None
organization_id = (
    session_state.get("activeOrganizationId")
    if isinstance(session_state, dict)
    else None
)
if not isinstance(organization_id, str) or not organization_id:
    raise RuntimeError("administrator session has no active organization")

credential_status = require(
    client.call("/api/auth/default-credentials-status"),
    (200,),
    "read bootstrap credential status",
)
if not isinstance(credential_status, dict) or credential_status.get("enabled") is not False:
    raise RuntimeError("bootstrap administrator password must be rotated first")

providers = require_list(client, "/api/llm-provider-api-keys", "list providers")
provider = next(
    (
        item
        for item in providers
        if item.get("provider") == PROVIDER
        and item.get("isChatgptSubscription") is not True
        and item.get("secretStorageType") not in (None, "none")
        and (item.get("baseUrl") or "").rstrip("/") == EXPECTED_BASE_URL
        and item.get("scope") == "team"
        and item.get("teamId") == MANAGED_GROUP_ID
    ),
    None,
)
if provider is None:
    raise RuntimeError("guarded cloud provider credential was not found")

models = require_list(client, "/api/llm-models", "list models")
priced_model = next(
    (
        item
        for item in models
        if item.get("provider") == PROVIDER
        and item.get("modelId") == MODEL
        and positive_price(item.get("pricePerMillionInput"))
        and positive_price(item.get("pricePerMillionOutput"))
    ),
    None,
)
if priced_model is None:
    raise RuntimeError("approved cloud model is missing reviewed non-zero pricing")

limits = require_list(
    client,
    "/api/limits?entityType=organization&limitType=token_cost",
    "list organization limits",
)
existing_org = next(
    (
        item
        for item in limits
        if item.get("entityType") == "organization"
        and item.get("entityId") == organization_id
        and item.get("limitType") == "token_cost"
        and model_set(item.get("model")) == [MODEL]
    ),
    None,
)
defaults = require_list(client, "/api/default-user-limits", "list user defaults")
existing_default = next(
    (item for item in defaults if item.get("environmentId") is None),
    None,
)

org_payload = {
    "entityType": "organization",
    "entityId": organization_id,
    "limitType": "token_cost",
    "limitValue": ORG_LIMIT,
    "model": [MODEL],
    "cleanupInterval": CLEANUP_INTERVAL,
}
default_payload = {
    "limitValue": USER_LIMIT,
    "model": [MODEL],
    "cleanupInterval": CLEANUP_INTERVAL,
}

created_org_id: str | None = None
created_default_id: str | None = None
org_changed = False
default_changed = False


def restore() -> None:
    if created_default_id:
        client.call(f"/api/default-user-limits/{created_default_id}", "DELETE")
    elif default_changed and existing_default:
        client.call(
            f"/api/default-user-limits/{existing_default['id']}",
            "PATCH",
            {
                "limitValue": existing_default["limitValue"],
                "model": existing_default.get("model"),
                "cleanupInterval": existing_default.get(
                    "cleanupInterval", "calendar_month"
                ),
            },
        )
    if created_org_id:
        client.call(f"/api/limits/{created_org_id}", "DELETE")
    elif org_changed and existing_org:
        client.call(
            f"/api/limits/{existing_org['id']}",
            "PATCH",
            {
                "limitValue": existing_org["limitValue"],
                "model": existing_org.get("model"),
                "cleanupInterval": existing_org.get(
                    "cleanupInterval", "calendar_month"
                ),
            },
        )


try:
    if existing_org:
        result = require(
            client.call(
                f"/api/limits/{existing_org['id']}",
                "PATCH",
                {
                    "limitValue": ORG_LIMIT,
                    "model": [MODEL],
                    "cleanupInterval": CLEANUP_INTERVAL,
                },
            ),
            (200,),
            "update organization limit",
        )
        org_changed = True
    else:
        result = require(
            client.call("/api/limits", "POST", org_payload),
            (200, 201),
            "create organization limit",
        )
        created_org_id = result.get("id") if isinstance(result, dict) else None
        if not created_org_id:
            raise RuntimeError("created organization limit has no ID")

    if existing_default:
        result = require(
            client.call(
                f"/api/default-user-limits/{existing_default['id']}",
                "PATCH",
                default_payload,
            ),
            (200,),
            "update default-user limit",
        )
        default_changed = True
    else:
        result = require(
            client.call("/api/default-user-limits", "POST", default_payload),
            (200, 201),
            "create default-user limit",
        )
        created_default_id = result.get("id") if isinstance(result, dict) else None
        if not created_default_id:
            raise RuntimeError("created default-user limit has no ID")

    verified_limits = require_list(
        client,
        "/api/limits?entityType=organization&limitType=token_cost",
        "verify organization limit",
    )
    verified_defaults = require_list(
        client, "/api/default-user-limits", "verify default-user limit"
    )
    org_ok = any(
        item.get("entityId") == organization_id
        and item.get("limitType") == "token_cost"
        and item.get("limitValue") == ORG_LIMIT
        and model_set(item.get("model")) == [MODEL]
        and item.get("cleanupInterval") == CLEANUP_INTERVAL
        for item in verified_limits
    )
    user_ok = any(
        item.get("environmentId") is None
        and item.get("limitValue") == USER_LIMIT
        and model_set(item.get("model")) == [MODEL]
        and item.get("cleanupInterval") == CLEANUP_INTERVAL
        for item in verified_defaults
    )
    if not org_ok or not user_ok:
        raise RuntimeError("post-write budget verification failed")
except Exception:
    restore()
    raise

print(
    json.dumps(
        {
            "status": "PASS",
            "provider": PROVIDER,
            "model": MODEL,
            "organization_limit_dollars": ORG_LIMIT,
            "default_user_limit_dollars": USER_LIMIT,
            "cleanup_interval": CLEANUP_INTERVAL,
            "guarded_base_url": EXPECTED_BASE_URL,
            "provider_scope": "team",
            "rollback_armed": True,
        },
        separators=(",", ":"),
    )
)
