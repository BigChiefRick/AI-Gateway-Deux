from __future__ import annotations

import json
import os
from pathlib import Path
import urllib.error
import urllib.request


MANAGED_TOOLS = [
    "gateway_web_research__fetch_webpage",
    "gateway_web_research__get_weather",
    "gateway_web_research__ocr_document",
    "gateway_web_research__scan_qr_codes",
    "gateway_web_research__scrape_webpage",
    "gateway_web_research__search_web",
]


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
admin_key = os.environ.get("DLP_ADMIN_API_KEY") or env.get("DLP_ADMIN_API_KEY", "")
bind_address = (
    os.environ.get("DLP_BIND_ADDRESS")
    or env.get("DLP_BIND_ADDRESS")
    or env.get("ARCHESTRA_BIND_ADDRESS")
    or "127.0.0.1"
)
base_url = os.environ.get("OPENAI_DLP_ADMIN_URL", f"http://{bind_address}:4201").rstrip("/")
model_value = os.environ.get("OPENAI_DLP_ALLOWED_MODELS") or env.get(
    "OPENAI_DLP_ALLOWED_MODELS", ""
)
allowed_models = [item.strip() for item in model_value.split(",") if item.strip()]
managed_group_id = os.environ.get("OPENAI_DLP_MANAGED_GROUP_ID") or env.get(
    "OPENAI_DLP_MANAGED_GROUP_ID", ""
) or os.environ.get("DLP_MANAGED_GROUP_ID") or env.get(
    "DLP_MANAGED_GROUP_ID", ""
)
policy_group_id = os.environ.get("OPENAI_DLP_POLICY_GROUP") or env.get(
    "OPENAI_DLP_POLICY_GROUP", ""
)
legacy_subject_id = os.environ.get("OPENAI_DLP_DEFAULT_AGENT_ID") or env.get(
    "OPENAI_DLP_DEFAULT_AGENT_ID", "archestra-openai-chat"
)

if not admin_key:
    raise SystemExit("DLP_ADMIN_API_KEY is not set")
if not allowed_models:
    raise SystemExit("OPENAI_DLP_ALLOWED_MODELS must contain at least one approved model")
if not managed_group_id:
    raise SystemExit(
        "DLP_MANAGED_GROUP_ID is required; run configure-team-dlp-identity.py first"
    )
if not policy_group_id:
    policy_group_id = f"openai:{managed_group_id}"

headers = {
    "Authorization": f"Bearer {admin_key}",
    "Content-Type": "application/json",
}


def request(path: str, payload: dict | None = None) -> dict | list:
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        base_url + path,
        data=body,
        headers=headers,
        method="GET" if body is None else "POST",
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


profiles = request("/admin/api/profiles")
default = next(profile for profile in profiles if profile["id"] == "default")
settings = dict(default["settings"])
settings["allowed_models"] = allowed_models
settings["allowed_tools"] = MANAGED_TOOLS
settings["memory_read"] = True
settings["memory_write"] = True

profile = request(
    "/admin/api/profiles",
    {
        "id": "archestra-openai",
        "name": "Archestra guarded OpenAI chat",
        "description": (
            "Prompt/response DLP policy for the side-by-side metered OpenAI route."
        ),
        "enabled": True,
        "settings": settings,
    },
)

assignments = request("/admin/api/assignments")
matching_assignment = next(
    (
        assignment
        for assignment in assignments
        if assignment["subject_type"] == "group"
        and assignment["subject_id"] == policy_group_id
        and assignment["profile_id"] == "archestra-openai"
    ),
    None,
)

if matching_assignment is None:
    try:
        request(
            "/admin/api/assignments",
            {
                "subject_type": "group",
                "subject_id": policy_group_id,
                "profile_id": "archestra-openai",
                "priority": 100,
            },
        )
    except urllib.error.HTTPError as error:
        if error.code != 409:
            raise

for assignment in assignments:
    if (
        assignment["subject_type"] == "agent"
        and assignment["subject_id"] == legacy_subject_id
        and assignment["profile_id"] == "archestra-openai"
    ):
        req = urllib.request.Request(
            base_url + f"/admin/api/assignments/{assignment['id']}",
            headers=headers,
            method="DELETE",
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            if response.status != 204:
                raise RuntimeError(
                    "removing legacy OpenAI agent assignment returned "
                    f"HTTP {response.status}"
                )

print(
    "PASS: configured profile=archestra-openai "
    f"allowed_models={len(profile['settings']['allowed_models'])} "
    f"allowed_tools={len(profile['settings']['allowed_tools'])} "
    f"subject=group:{policy_group_id}"
)
