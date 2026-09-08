#!/usr/bin/env python3
"""Create a signed, team-scoped Archestra provider for the OpenAI DLP hop.

The real OpenAI key stays in the DLP container. Archestra stores only the DLP
client key and server-managed signed route identity. The local Ollama provider
and managed agent are never modified by this preparation step.
"""

from __future__ import annotations

import hashlib
import hmac
import http.cookiejar
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any


ARCHESTRA_URL = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_URL", "https://192.0.2.10"
).rstrip("/")
ARCHESTRA_ORIGIN = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_ORIGIN", "https://192.0.2.10"
).rstrip("/")
ADMIN_EMAIL = os.environ.get("ARCHESTRA_ACCEPTANCE_ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD", "")
ADMIN_PASSWORD_FILE = os.environ.get("ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD_FILE", "")
TEAM_NAME = os.environ.get("ARCHESTRA_ACCEPTANCE_TEAM", "AI Gateway Users")
MODEL = os.environ.get("ARCHESTRA_CLOUD_MODEL", "").strip()
DLP_URL = os.environ.get(
    "OPENAI_DLP_ADMIN_URL", "http://192.0.2.10:4201"
).rstrip("/")
DLP_PROVIDER_URL = os.environ.get(
    "OPENAI_DLP_PROVIDER_URL", "http://192.0.2.10:4201/v1"
).rstrip("/")
PROFILE_ID = os.environ.get("OPENAI_DLP_PROFILE", "archestra-openai")


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
if not ADMIN_PASSWORD and ADMIN_PASSWORD_FILE:
    ADMIN_PASSWORD = Path(ADMIN_PASSWORD_FILE).read_text(encoding="utf-8").strip()
DLP_POLICY_KEY = os.environ.get("OPENAI_DLP_POLICY_API_KEY") or env.get(
    "OPENAI_DLP_POLICY_API_KEY", ""
)
DLP_ADMIN_KEY = os.environ.get("DLP_ADMIN_API_KEY") or env.get(
    "DLP_ADMIN_API_KEY", ""
)
IDENTITY_KEY = os.environ.get("DLP_IDENTITY_HMAC_KEY") or env.get(
    "DLP_IDENTITY_HMAC_KEY", ""
)
EXPECTED_TEAM_ID = os.environ.get("DLP_MANAGED_GROUP_ID") or env.get(
    "DLP_MANAGED_GROUP_ID", ""
)
POLICY_GROUP_ID = os.environ.get("OPENAI_DLP_POLICY_GROUP") or env.get(
    "OPENAI_DLP_POLICY_GROUP", ""
)

missing = [
    name
    for name, value in (
        ("ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD", ADMIN_PASSWORD),
        ("ARCHESTRA_CLOUD_MODEL", MODEL),
        ("OPENAI_DLP_POLICY_API_KEY", DLP_POLICY_KEY),
        ("DLP_ADMIN_API_KEY", DLP_ADMIN_KEY),
        ("DLP_IDENTITY_HMAC_KEY", IDENTITY_KEY),
        ("DLP_MANAGED_GROUP_ID", EXPECTED_TEAM_ID),
    )
    if not value
]
if missing:
    raise SystemExit("Missing required values: " + ", ".join(missing))
if not POLICY_GROUP_ID:
    POLICY_GROUP_ID = f"openai:{EXPECTED_TEAM_ID}"


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
            "Origin": ARCHESTRA_ORIGIN,
            "Referer": ARCHESTRA_ORIGIN + "/",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            ARCHESTRA_URL + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=180) as response:
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


def dlp_call(path: str) -> Result:
    request = urllib.request.Request(
        DLP_URL + path,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {DLP_ADMIN_KEY}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
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


def list_data(value: Any, action: str) -> list[dict[str, Any]]:
    rows = value.get("data", value) if isinstance(value, dict) else value
    if not isinstance(rows, list):
        raise RuntimeError(f"{action} did not return a JSON list")
    return [item for item in rows if isinstance(item, dict)]


def positive_price(value: Any) -> bool:
    try:
        return Decimal(str(value or "0")) > 0
    except InvalidOperation:
        return False


health = require(dlp_call("/readyz"), (200,), "check OpenAI DLP readiness")
if not (
    isinstance(health, dict)
    and health.get("status") == "ready"
    and health.get("guardrail_database") == "connected"
    and health.get("policy_auth") == "configured"
    and health.get("upstream") == "configured"
    and health.get("signed_identity") == "configured"
):
    raise RuntimeError("OpenAI DLP is not ready with signed identity")

effective_query = urllib.parse.urlencode(
    {"user_id": "cloud-route-probe", "agent_id": "cloud-route-probe", "groups": POLICY_GROUP_ID}
)
effective = require(
    dlp_call(f"/admin/api/effective?{effective_query}"),
    (200,),
    "resolve OpenAI DLP policy identity",
)
if not isinstance(effective, dict) or effective.get("profile_id") != PROFILE_ID:
    raise RuntimeError("route-qualified OpenAI identity does not resolve its profile")

client = Client()
require(
    client.call(
        "/api/auth/sign-in/email",
        "POST",
        {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    ),
    (200, 201),
    "administrator login",
)

teams = list_data(require(client.call("/api/teams?limit=100"), (200,), "list teams"), "list teams")
team = next((item for item in teams if item.get("name") == TEAM_NAME), None)
team_id = team.get("id") if isinstance(team, dict) else None
if not isinstance(team_id, str):
    raise RuntimeError(f"team {TEAM_NAME!r} was not found")
if team_id != EXPECTED_TEAM_ID:
    raise RuntimeError("persisted managed team ID does not match the live team")

canonical = f"user=\ngroups={POLICY_GROUP_ID}"
signature = hmac.new(
    IDENTITY_KEY.encode(), canonical.encode(), hashlib.sha256
).hexdigest()
extra_headers = {
    "X-AI-Gateway-Groups": POLICY_GROUP_ID,
    "X-AI-Gateway-Identity-Signature": signature,
}
provider_name = f"DLP-Guarded OpenAI - {TEAM_NAME}"
providers = list_data(
    require(client.call("/api/llm-provider-api-keys"), (200,), "list providers"),
    "list providers",
)
provider = next(
    (
        item
        for item in providers
        if item.get("provider") == "openai" and item.get("name") == provider_name
    ),
    None,
)
provider_created = False
provider_changed = False
old_provider_config: dict[str, Any] | None = None

if provider is None:
    provider = require(
        client.call(
            "/api/llm-provider-api-keys",
            "POST",
            {
                "name": provider_name,
                "provider": "openai",
                "apiKey": DLP_POLICY_KEY,
                "baseUrl": DLP_PROVIDER_URL,
                "extraHeaders": extra_headers,
                "scope": "team",
                "teamId": team_id,
                "isPrimary": False,
            },
        ),
        (200, 201),
        "create signed OpenAI DLP provider",
    )
    provider_created = True
else:
    provider_id_value = provider.get("id")
    if not isinstance(provider_id_value, str):
        raise RuntimeError("existing cloud provider has no ID")
    expected_config = {
        "name": provider_name,
        "baseUrl": DLP_PROVIDER_URL,
        "extraHeaders": extra_headers,
        "scope": "team",
        "teamId": team_id,
        "isPrimary": False,
    }
    old_provider_config = {
        key: provider.get(key)
        for key in expected_config
    }
    if any(provider.get(key) != value for key, value in expected_config.items()):
        provider = require(
            client.call(
                f"/api/llm-provider-api-keys/{provider_id_value}",
                "PATCH",
                expected_config,
            ),
            (200,),
            "repair signed OpenAI DLP provider metadata",
        )
        provider_changed = True

provider_id = provider.get("id") if isinstance(provider, dict) else None
if not isinstance(provider_id, str):
    raise RuntimeError("cloud provider response did not contain an ID")

model_changed = False
model_db_id: str | None = None
old_model_team_ids: list[str] = []
try:
    require(client.call("/api/llm-models/sync", "POST"), (200,), "sync cloud models")
    available_query = urllib.parse.urlencode(
        {"provider": "openai", "apiKeyId": provider_id}
    )
    available = list_data(
        require(
            client.call(f"/api/llm-models/available?{available_query}"),
            (200,),
            "list cloud models for signed provider",
        ),
        "list cloud models for signed provider",
    )
    selected = next((item for item in available if item.get("id") == MODEL), None)
    model_db_id = selected.get("dbId") if isinstance(selected, dict) else None
    capabilities = selected.get("capabilities") if isinstance(selected, dict) else None
    if not isinstance(model_db_id, str):
        raise RuntimeError("approved cloud model was not discovered through DLP")
    if not isinstance(capabilities, dict) or not (
        positive_price(capabilities.get("pricePerMillionInput"))
        and positive_price(capabilities.get("pricePerMillionOutput"))
    ):
        raise RuntimeError("approved cloud model lacks reviewed non-zero pricing")

    catalog = list_data(
        require(client.call("/api/llm-models"), (200,), "read model catalog"),
        "read model catalog",
    )
    catalog_model = next((item for item in catalog if item.get("id") == model_db_id), None)
    if catalog_model is None:
        raise RuntimeError("approved cloud model is missing from the catalog")
    old_model_team_ids = [
        item["id"]
        for item in catalog_model.get("teams", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]
    if old_model_team_ids != [team_id]:
        require(
            client.call(
                f"/api/llm-models/{model_db_id}",
                "PATCH",
                {"teamIds": [team_id]},
            ),
            (200,),
            "restrict cloud model to managed team",
        )
        model_changed = True

    refreshed = list_data(
        require(client.call("/api/llm-provider-api-keys"), (200,), "verify provider"),
        "verify provider",
    )
    verified_provider = next((item for item in refreshed if item.get("id") == provider_id), None)
    if not verified_provider or not (
        verified_provider.get("scope") == "team"
        and verified_provider.get("teamId") == team_id
        and (verified_provider.get("baseUrl") or "").rstrip("/") == DLP_PROVIDER_URL
        and verified_provider.get("extraHeaders") == extra_headers
        and verified_provider.get("isPrimary") is False
    ):
        raise RuntimeError("signed team-scoped cloud provider verification failed")
except Exception:
    if model_changed and model_db_id:
        client.call(
            f"/api/llm-models/{model_db_id}",
            "PATCH",
            {"teamIds": old_model_team_ids},
        )
    if provider_created:
        client.call(f"/api/llm-provider-api-keys/{provider_id}", "DELETE")
    elif provider_changed and old_provider_config:
        client.call(
            f"/api/llm-provider-api-keys/{provider_id}",
            "PATCH",
            old_provider_config,
        )
    raise

print(
    json.dumps(
        {
            "status": "PASS",
            "provider": "openai",
            "provider_id": provider_id,
            "provider_scope": "team",
            "team_id": team_id,
            "policy_identity": "route-qualified-signed-group",
            "profile": PROFILE_ID,
            "model": MODEL,
            "model_team_restricted": True,
            "local_route_changed": False,
        },
        separators=(",", ":"),
    )
)
