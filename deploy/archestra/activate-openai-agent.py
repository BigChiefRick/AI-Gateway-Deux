#!/usr/bin/env python3
"""Expose a budgeted, signed OpenAI agent without changing the local agent."""

from __future__ import annotations

import hashlib
import hmac
import http.cookiejar
import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
import uuid
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
SOURCE_AGENT_ID = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_AGENT_ID", "00000000-0000-4000-8000-000000001003"
)
CLOUD_AGENT_NAME = os.environ.get(
    "ARCHESTRA_CLOUD_AGENT_NAME", "AI Gateway POC - OpenAI"
)
MODEL = os.environ.get("ARCHESTRA_CLOUD_MODEL", "").strip()
EXPECTED_BASE_URL = os.environ.get(
    "ARCHESTRA_EXPECTED_CLOUD_BASE_URL", "http://192.0.2.10:4201/v1"
).rstrip("/")
DLP_URL = os.environ.get(
    "OPENAI_DLP_ADMIN_URL", "http://192.0.2.10:4201"
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


def persist_env_value(path: Path, key: str, value: str) -> None:
    if not path.exists():
        return
    original_mode = path.stat().st_mode
    lines = path.read_text(encoding="utf-8").splitlines()
    replacement = f"{key}={value}"
    for index, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[index] = replacement
            break
    else:
        lines.append(replacement)
    temporary = path.with_name(path.name + ".cloud-agent.tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(temporary, original_mode)
    os.replace(temporary, path)


env = load_env(Path(".env"))
if not ADMIN_PASSWORD and ADMIN_PASSWORD_FILE:
    ADMIN_PASSWORD = Path(ADMIN_PASSWORD_FILE).read_text(encoding="utf-8").strip()
DLP_ADMIN_KEY = os.environ.get("DLP_ADMIN_API_KEY") or env.get(
    "DLP_ADMIN_API_KEY", ""
)
IDENTITY_KEY = os.environ.get("DLP_IDENTITY_HMAC_KEY") or env.get(
    "DLP_IDENTITY_HMAC_KEY", ""
)
TEAM_ID = os.environ.get("DLP_MANAGED_GROUP_ID") or env.get(
    "DLP_MANAGED_GROUP_ID", ""
)
POLICY_GROUP_ID = os.environ.get("OPENAI_DLP_POLICY_GROUP") or env.get(
    "OPENAI_DLP_POLICY_GROUP", ""
)
if not POLICY_GROUP_ID and TEAM_ID:
    POLICY_GROUP_ID = f"openai:{TEAM_ID}"

missing = [
    name
    for name, value in (
        ("ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD", ADMIN_PASSWORD),
        ("ARCHESTRA_CLOUD_MODEL", MODEL),
        ("DLP_ADMIN_API_KEY", DLP_ADMIN_KEY),
        ("DLP_IDENTITY_HMAC_KEY", IDENTITY_KEY),
        ("DLP_MANAGED_GROUP_ID", TEAM_ID),
    )
    if not value
]
if missing:
    raise SystemExit("Missing required values: " + ", ".join(missing))


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


def rows(value: Any, action: str) -> list[dict[str, Any]]:
    data = value.get("data", value) if isinstance(value, dict) else value
    if not isinstance(data, list):
        raise RuntimeError(f"{action} did not return a JSON list")
    return [item for item in data if isinstance(item, dict)]


def positive_price(value: Any) -> bool:
    try:
        return Decimal(str(value or "0")) > 0
    except InvalidOperation:
        return False


def model_applies(configured: Any) -> bool:
    return configured is None or configured == [] or MODEL in configured


health = require(dlp_call("/readyz"), (200,), "check OpenAI DLP readiness")
if not (
    isinstance(health, dict)
    and health.get("status") == "ready"
    and health.get("signed_identity") == "configured"
    and health.get("upstream") == "configured"
    and health.get("policy_auth") == "configured"
    and health.get("guardrail_database") == "connected"
):
    raise RuntimeError("OpenAI DLP is not ready with signed identity")

effective_query = urllib.parse.urlencode(
    {"user_id": "cloud-agent-probe", "agent_id": "cloud-agent-probe", "groups": POLICY_GROUP_ID}
)
effective = require(
    dlp_call(f"/admin/api/effective?{effective_query}"),
    (200,),
    "resolve OpenAI DLP profile",
)
if not isinstance(effective, dict) or effective.get("profile_id") != PROFILE_ID:
    raise RuntimeError("OpenAI route identity does not resolve its managed profile")

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
session = require(client.call("/api/auth/get-session"), (200,), "get session")
session_state = session.get("session") if isinstance(session, dict) else None
organization_id = (
    session_state.get("activeOrganizationId")
    if isinstance(session_state, dict)
    else None
)
if not isinstance(organization_id, str):
    raise RuntimeError("administrator session has no active organization")

credential_status = require(
    client.call("/api/auth/default-credentials-status"),
    (200,),
    "read bootstrap credential status",
)
if not isinstance(credential_status, dict) or credential_status.get("enabled") is not False:
    raise RuntimeError("bootstrap administrator password must be rotated first")

teams = rows(require(client.call("/api/teams?limit=100"), (200,), "list teams"), "list teams")
team = next((item for item in teams if item.get("name") == TEAM_NAME), None)
if not team or team.get("id") != TEAM_ID:
    raise RuntimeError("live managed team does not match the persisted team ID")

canonical = f"user=\ngroups={POLICY_GROUP_ID}"
signature = hmac.new(
    IDENTITY_KEY.encode(), canonical.encode(), hashlib.sha256
).hexdigest()
expected_headers = {
    "X-AI-Gateway-Groups": POLICY_GROUP_ID,
    "X-AI-Gateway-Identity-Signature": signature,
}
providers = rows(
    require(client.call("/api/llm-provider-api-keys"), (200,), "list providers"),
    "list providers",
)
provider = next(
    (
        item
        for item in providers
        if item.get("provider") == "openai"
        and item.get("scope") == "team"
        and item.get("teamId") == TEAM_ID
        and (item.get("baseUrl") or "").rstrip("/") == EXPECTED_BASE_URL
        and item.get("extraHeaders") == expected_headers
        and item.get("secretStorageType") not in (None, "none")
        and item.get("isChatgptSubscription") is not True
        and item.get("isPrimary") is False
    ),
    None,
)
provider_id = provider.get("id") if isinstance(provider, dict) else None
if not isinstance(provider_id, str):
    raise RuntimeError("verified signed team-scoped OpenAI provider was not found")

models = rows(require(client.call("/api/llm-models"), (200,), "list models"), "list models")
model = next(
    (
        item
        for item in models
        if item.get("provider") == "openai"
        and item.get("modelId") == MODEL
        and positive_price(item.get("pricePerMillionInput"))
        and positive_price(item.get("pricePerMillionOutput"))
        and [team.get("id") for team in item.get("teams", []) if isinstance(team, dict)]
        == [TEAM_ID]
    ),
    None,
)
model_db_id = model.get("id") if isinstance(model, dict) else None
if not isinstance(model_db_id, str):
    raise RuntimeError("reviewed, team-restricted cloud model was not found")

limits = rows(
    require(client.call("/api/limits?limitType=token_cost"), (200,), "list limits"),
    "list limits",
)
defaults = rows(
    require(client.call("/api/default-user-limits"), (200,), "list user defaults"),
    "list user defaults",
)
org_budget = next(
    (
        item
        for item in limits
        if item.get("entityType") == "organization"
        and item.get("entityId") == organization_id
        and item.get("limitType") == "token_cost"
        and isinstance(item.get("limitValue"), int)
        and item["limitValue"] > 0
        and model_applies(item.get("model"))
        and isinstance(item.get("cleanupInterval"), str)
    ),
    None,
)
if org_budget is None:
    raise RuntimeError("positive organization cloud-model budget was not found")
user_budget = next(
    (
        item
        for item in defaults
        if item.get("environmentId") is None
        and isinstance(item.get("limitValue"), int)
        and item["limitValue"] > 0
        and model_applies(item.get("model"))
        and isinstance(item.get("cleanupInterval"), str)
    ),
    None,
)
if user_budget is None:
    raise RuntimeError("positive default-user cloud-model budget was not found")
if user_budget["limitValue"] > org_budget["limitValue"]:
    raise RuntimeError("default-user cloud budget exceeds the organization budget")

source = require(client.call(f"/api/agents/{SOURCE_AGENT_ID}"), (200,), "read local managed agent")
if source.get("scope") != "team" or [item.get("id") for item in source.get("teams", [])] != [TEAM_ID]:
    raise RuntimeError("local managed agent is not scoped to the expected team")
source_tool_ids = sorted(
    item["id"]
    for item in source.get("tools", [])
    if isinstance(item, dict) and isinstance(item.get("id"), str)
)
if len(source_tool_ids) != 6:
    raise RuntimeError("local managed agent does not expose exactly six tools")

agents = rows(
    require(client.call("/api/agents/all?agentType=agent"), (200,), "list agents"),
    "list agents",
)
cloud_agent = next((item for item in agents if item.get("name") == CLOUD_AGENT_NAME), None)
created = False
old_config: dict[str, Any] | None = None
if cloud_agent is None:
    cloud_agent = require(
        client.call(
            f"/api/agents/{SOURCE_AGENT_ID}/clone",
            "POST",
            {"scope": "team", "teams": [TEAM_ID]},
        ),
        (200, 201),
        "clone local managed agent",
    )
    created = True

agent_id = cloud_agent.get("id") if isinstance(cloud_agent, dict) else None
if not isinstance(agent_id, str):
    raise RuntimeError("cloud agent response did not contain an ID")
old_config = {
    "name": cloud_agent.get("name"),
    "modelId": cloud_agent.get("modelId"),
    "llmApiKeyId": cloud_agent.get("llmApiKeyId"),
    "scope": cloud_agent.get("scope"),
    "teams": [
        item["id"]
        for item in cloud_agent.get("teams", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ],
}
updated = False

try:
    cloud_agent = require(
        client.call(
            f"/api/agents/{agent_id}",
            "PUT",
            {
                "name": CLOUD_AGENT_NAME,
                "modelId": model_db_id,
                "llmApiKeyId": provider_id,
                "scope": "team",
                "teams": [TEAM_ID],
            },
        ),
        (200,),
        "bind cloud agent to signed provider and model",
    )
    updated = True
    verified = require(client.call(f"/api/agents/{agent_id}"), (200,), "verify cloud agent")
    verified_tool_ids = sorted(
        item["id"]
        for item in verified.get("tools", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    )
    if not (
        verified.get("name") == CLOUD_AGENT_NAME
        and verified.get("modelId") == model_db_id
        and verified.get("llmApiKeyId") == provider_id
        and verified.get("scope") == "team"
        and [item.get("id") for item in verified.get("teams", [])] == [TEAM_ID]
        and verified_tool_ids == source_tool_ids
    ):
        raise RuntimeError("cloud agent configuration verification failed")

    before_audit = require(dlp_call("/admin/api/audit?limit=1"), (200,), "read DLP audit")
    before_id = before_audit[0]["id"] if isinstance(before_audit, list) and before_audit else 0
    conversation = require(
        client.call(
            "/api/chat/conversations",
            "POST",
            {"agentId": agent_id, "title": "OpenAI guarded route acceptance"},
        ),
        (200,),
        "create cloud acceptance conversation",
    )
    conversation_id = conversation.get("id") if isinstance(conversation, dict) else None
    if not isinstance(conversation_id, str):
        raise RuntimeError("cloud acceptance conversation has no ID")
    proof = "OPENAI_GATEWAY_OK"
    chat = client.call(
        "/api/chat",
        "POST",
        {
            "id": conversation_id,
            "trigger": "submit-message",
            "messages": [
                {
                    "id": str(uuid.uuid4()),
                    "role": "user",
                    "parts": [
                        {"type": "text", "text": f"Reply with exactly {proof} and nothing else."}
                    ],
                }
            ],
        },
    )
    if chat.status != 200 or proof not in chat.text:
        raise RuntimeError(f"cloud acceptance chat returned HTTP {chat.status}")
    audit = require(dlp_call("/admin/api/audit?limit=100"), (200,), "verify DLP audit")
    if not any(
        item.get("id", 0) > before_id
        and item.get("profile_id") == PROFILE_ID
        and item.get("decision") == "allow"
        and item.get("stage") == "output"
        for item in audit
        if isinstance(item, dict)
    ):
        raise RuntimeError("cloud chat did not create an OpenAI-profile DLP audit row")
    local_after = require(
        client.call(f"/api/agents/{SOURCE_AGENT_ID}"),
        (200,),
        "verify local managed agent rollback path",
    )
    if not (
        local_after.get("modelId") == source.get("modelId")
        and local_after.get("llmApiKeyId") == source.get("llmApiKeyId")
    ):
        raise RuntimeError("cloud activation changed the local managed agent route")
except Exception:
    if created:
        client.call(f"/api/agents/{agent_id}", "DELETE")
    elif updated and old_config:
        client.call(f"/api/agents/{agent_id}", "PUT", old_config)
    raise

persist_env_value(Path(".env"), "OPENAI_MANAGED_AGENT_ID", agent_id)
print(
    json.dumps(
        {
            "status": "PASS",
            "agent_id": agent_id,
            "agent_name": CLOUD_AGENT_NAME,
            "team_id": TEAM_ID,
            "provider_scope": "team",
            "model": MODEL,
            "organization_budget_verified": True,
            "default_user_budget_verified": True,
            "managed_chat": "OPENAI_GATEWAY_OK",
            "dlp_profile_verified": True,
            "local_agent_changed": False,
        },
        separators=(",", ":"),
    )
)
