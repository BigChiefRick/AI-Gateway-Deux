#!/usr/bin/env python3
"""Bind a managed Archestra team to a signed DLP group identity.

The DLP policy key, identity signing key, and administrator password are read
only from the environment or the VM's root-owned .env. Secret values, cookies,
and signatures are never printed.
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
import uuid
from dataclasses import dataclass
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
AGENT_ID = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_AGENT_ID", "00000000-0000-4000-8000-000000001003"
)
DLP_URL = os.environ.get("DLP_ADMIN_URL", "http://192.0.2.10:4200").rstrip("/")
DLP_PROVIDER_URL = os.environ.get(
    "DLP_PROVIDER_URL", "http://192.0.2.10:4200/v1"
).rstrip("/")
PROFILE_ID = os.environ.get("DLP_MANAGED_PROFILE", "archestra-managed")


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
    """Atomically persist non-secret routing metadata without changing file mode."""

    if not path.exists():
        return
    original_mode = path.stat().st_mode
    lines = path.read_text(encoding="utf-8").splitlines()
    replacement = f"{key}={value}"
    updated = False
    for index, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[index] = replacement
            updated = True
            break
    if not updated:
        lines.append(replacement)
    temporary = path.with_name(path.name + ".identity.tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(temporary, original_mode)
    os.replace(temporary, path)


env = load_env(Path(".env"))
if not ADMIN_PASSWORD and ADMIN_PASSWORD_FILE:
    ADMIN_PASSWORD = Path(ADMIN_PASSWORD_FILE).read_text(encoding="utf-8").strip()
DLP_POLICY_KEY = os.environ.get("DLP_POLICY_API_KEY") or env.get(
    "DLP_POLICY_API_KEY", ""
)
DLP_ADMIN_KEY = os.environ.get("DLP_ADMIN_API_KEY") or env.get(
    "DLP_ADMIN_API_KEY", ""
)
IDENTITY_KEY = os.environ.get("DLP_IDENTITY_HMAC_KEY") or env.get(
    "DLP_IDENTITY_HMAC_KEY", ""
)

missing = [
    name
    for name, value in (
        ("ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD", ADMIN_PASSWORD),
        ("DLP_POLICY_API_KEY", DLP_POLICY_KEY),
        ("DLP_ADMIN_API_KEY", DLP_ADMIN_KEY),
        ("DLP_IDENTITY_HMAC_KEY", IDENTITY_KEY),
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


class ArchestraClient:
    def __init__(self) -> None:
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )

    def call(self, path: str, method: str = "GET", payload: dict | None = None) -> Result:
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


def require(result: Result, expected: tuple[int, ...], action: str) -> Any:
    if result.status not in expected:
        raise RuntimeError(f"{action} returned HTTP {result.status}")
    return result.data


def dlp_call(path: str, method: str = "GET", payload: dict | None = None) -> Result:
    body = None if payload is None else json.dumps(payload).encode()
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {DLP_ADMIN_KEY}",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        DLP_URL + path,
        data=body,
        headers=headers,
        method=method,
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


client = ArchestraClient()
require(
    client.call(
        "/api/auth/sign-in/email",
        "POST",
        {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    ),
    (200, 201),
    "administrator login",
)

teams = require(client.call("/api/teams?limit=100"), (200,), "list teams")
team_rows = teams.get("data", teams) if isinstance(teams, dict) else teams
team = next(
    (item for item in team_rows if isinstance(item, dict) and item.get("name") == TEAM_NAME),
    None,
)
if not team or not isinstance(team.get("id"), str):
    raise RuntimeError(f"team {TEAM_NAME!r} was not found")
team_id = team["id"]

canonical = f"user=\ngroups={team_id}"
signature = hmac.new(
    IDENTITY_KEY.encode(), canonical.encode(), hashlib.sha256
).hexdigest()
extra_headers = {
    "X-AI-Gateway-Groups": team_id,
    "X-AI-Gateway-Identity-Signature": signature,
}

providers = require(
    client.call("/api/llm-provider-api-keys"), (200,), "list provider keys"
)
provider_name = f"DLP-Guarded Ollama - {TEAM_NAME}"
team_provider = next(
    (
        item
        for item in providers
        if isinstance(item, dict)
        and item.get("provider") == "vllm"
        and item.get("scope") == "team"
        and item.get("teamId") == team_id
        and item.get("name") == provider_name
    ),
    None,
)
provider_created = False
provider_payload = {
    "name": provider_name,
    "provider": "vllm",
    "apiKey": DLP_POLICY_KEY,
    "baseUrl": DLP_PROVIDER_URL,
    "extraHeaders": extra_headers,
    "scope": "team",
    "teamId": team_id,
    "isPrimary": True,
}
if team_provider is None:
    team_provider = require(
        client.call("/api/llm-provider-api-keys", "POST", provider_payload),
        (200, 201),
        "create team-scoped DLP provider",
    )
    provider_created = True
else:
    team_provider = require(
        client.call(
            f"/api/llm-provider-api-keys/{team_provider['id']}",
            "PATCH",
            {key: value for key, value in provider_payload.items() if key != "provider"},
        ),
        (200,),
        "update team-scoped DLP provider",
    )
provider_id = team_provider.get("id") if isinstance(team_provider, dict) else None
if not isinstance(provider_id, str):
    raise RuntimeError("team-scoped provider response did not contain an ID")

assignments = require(dlp_call("/admin/api/assignments"), (200,), "list assignments")
group_assignment = next(
    (
        item
        for item in assignments
        if item.get("subject_type") == "group"
        and item.get("subject_id") == team_id
        and item.get("profile_id") == PROFILE_ID
    ),
    None,
)
group_assignment_created = False
if group_assignment is None:
    group_assignment = require(
        dlp_call(
            "/admin/api/assignments",
            "POST",
            {
                "subject_type": "group",
                "subject_id": team_id,
                "profile_id": PROFILE_ID,
                "priority": 100,
            },
        ),
        (200,),
        "create team DLP assignment",
    )
    group_assignment_created = True

effective_query = urllib.parse.urlencode(
    {
        "user_id": "identity-probe",
        "agent_id": "identity-probe",
        "groups": team_id,
    }
)
effective = require(
    dlp_call(f"/admin/api/effective?{effective_query}"),
    (200,),
    "resolve team DLP assignment",
)
if effective.get("profile_id") != PROFILE_ID:
    raise RuntimeError("team DLP assignment did not resolve the managed profile")

agent = require(client.call(f"/api/agents/{AGENT_ID}"), (200,), "read managed agent")
old_agent_key_id = agent.get("llmApiKeyId")
agent_changed = False
agent_assignment_removed = False
agent_assignments = [
    item
    for item in assignments
    if item.get("subject_type") == "agent"
    and item.get("subject_id") == "archestra-managed-chat"
    and item.get("profile_id") == PROFILE_ID
]

try:
    if old_agent_key_id != provider_id:
        require(
            client.call(
                f"/api/agents/{AGENT_ID}",
                "PUT",
                {"llmApiKeyId": provider_id},
            ),
            (200,),
            "bind managed agent to team-scoped DLP provider",
        )
        agent_changed = True

    for assignment in agent_assignments:
        require(
            dlp_call(f"/admin/api/assignments/{assignment['id']}", "DELETE"),
            (204,),
            "remove route-wide DLP assignment",
        )
        agent_assignment_removed = True

    before_audit = require(dlp_call("/admin/api/audit?limit=1"), (200,), "read audit")
    before_id = before_audit[0]["id"] if before_audit else 0
    conversation = require(
        client.call(
            "/api/chat/conversations",
            "POST",
            {"agentId": AGENT_ID, "title": "Team DLP identity acceptance"},
        ),
        (200,),
        "create team DLP acceptance conversation",
    )
    conversation_id = conversation.get("id")
    if not isinstance(conversation_id, str):
        raise RuntimeError("acceptance conversation did not return an ID")
    proof = "TEAM_DLP_IDENTITY_OK"
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
                        {
                            "type": "text",
                            "text": f"Reply with exactly {proof} and nothing else.",
                        }
                    ],
                }
            ],
        },
    )
    if chat.status != 200 or proof not in chat.text:
        raise RuntimeError(f"team DLP acceptance chat returned HTTP {chat.status}")

    audit = require(dlp_call("/admin/api/audit?limit=100"), (200,), "verify audit")
    matching = [
        item
        for item in audit
        if item.get("id", 0) > before_id
        and item.get("profile_id") == PROFILE_ID
        and item.get("decision") == "allow"
        and item.get("stage") == "output"
    ]
    if not matching:
        raise RuntimeError("team-scoped chat did not create a managed-profile audit row")
except Exception:
    if agent_changed:
        client.call(f"/api/agents/{AGENT_ID}", "PUT", {"llmApiKeyId": old_agent_key_id})
    if agent_assignment_removed:
        dlp_call(
            "/admin/api/assignments",
            "POST",
            {
                "subject_type": "agent",
                "subject_id": "archestra-managed-chat",
                "profile_id": PROFILE_ID,
                "priority": 100,
            },
        )
    if provider_created:
        client.call(f"/api/llm-provider-api-keys/{provider_id}", "DELETE")
    if group_assignment_created and isinstance(group_assignment, dict):
        dlp_call(
            f"/admin/api/assignments/{group_assignment['id']}",
            "DELETE",
        )
    raise

persist_env_value(Path(".env"), "DLP_MANAGED_GROUP_ID", team_id)

print(
    json.dumps(
        {
            "status": "PASS",
            "team": TEAM_NAME,
            "team_id": team_id,
            "provider_scope": "team",
            "managed_agent_key": "team-scoped",
            "dlp_profile": PROFILE_ID,
            "dlp_assignment": "group",
            "managed_chat": "TEAM_DLP_IDENTITY_OK",
            "audit_profile_verified": True,
        },
        separators=(",", ":"),
    )
)
