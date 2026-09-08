from __future__ import annotations

import json
import os
from pathlib import Path
from decimal import Decimal, InvalidOperation
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
    for line in path.read_text(encoding="utf-8").splitlines():
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
base_url = os.environ.get("DLP_ADMIN_URL", f"http://{bind_address}:4200").rstrip("/")
managed_group_id = os.environ.get("DLP_MANAGED_GROUP_ID") or env.get(
    "DLP_MANAGED_GROUP_ID", ""
)
allowed_models_value = os.environ.get("DLP_ALLOWED_MODELS") or env.get(
    "DLP_ALLOWED_MODELS", "granite4.1:3b"
)
allowed_models = [
    model.strip() for model in allowed_models_value.split(",") if model.strip()
]
if allowed_models != ["granite4.1:3b"]:
    raise SystemExit(
        "DLP_ALLOWED_MODELS must contain exactly the approved model granite4.1:3b"
    )
auto_model_alias = os.environ.get("DLP_AUTO_MODEL_ALIAS") or env.get(
    "DLP_AUTO_MODEL_ALIAS", "gateway-auto"
)
external_model_alias = os.environ.get("DLP_EXTERNAL_MODEL_ALIAS") or env.get(
    "DLP_EXTERNAL_MODEL_ALIAS", "gateway-cloud"
)
external_enabled = (
    os.environ.get("DLP_EXTERNAL_ENABLED") or env.get("DLP_EXTERNAL_ENABLED", "false")
).lower() == "true"
routing_mode = os.environ.get("DLP_MANAGED_ROUTING_MODE") or env.get(
    "DLP_MANAGED_ROUTING_MODE", "local_only"
)
if external_enabled and routing_mode != "local_first":
    raise SystemExit(
        "DLP_MANAGED_ROUTING_MODE must be local_first when DLP_EXTERNAL_ENABLED=true"
    )
if not external_enabled:
    routing_mode = "local_only"


def configured_decimal(name: str) -> float:
    raw = os.environ.get(name) or env.get(name, "0")
    try:
        value = Decimal(raw)
    except InvalidOperation as error:
        raise SystemExit(f"{name} must be a non-negative decimal") from error
    if not value.is_finite() or value < 0:
        raise SystemExit(f"{name} must be a non-negative decimal")
    if external_enabled and value <= 0:
        raise SystemExit(f"{name} must be positive when external routing is enabled")
    return float(value if external_enabled else 0)


external_budget = configured_decimal("DLP_EXTERNAL_MONTHLY_BUDGET_USD")
external_input_price = configured_decimal(
    "DLP_EXTERNAL_INPUT_PRICE_PER_MILLION_USD"
)
external_output_price = configured_decimal(
    "DLP_EXTERNAL_OUTPUT_PRICE_PER_MILLION_USD"
)
managed_models = [allowed_models[0], auto_model_alias, external_model_alias]
subject_type = "group" if managed_group_id else "agent"
subject_id = managed_group_id or "archestra-managed-chat"

if not admin_key:
    raise SystemExit("DLP_ADMIN_API_KEY is not set")

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


def delete(path: str) -> None:
    req = urllib.request.Request(
        base_url + path,
        headers=headers,
        method="DELETE",
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        if response.status != 204:
            raise RuntimeError(f"DELETE {path} returned HTTP {response.status}")


profiles = request("/admin/api/profiles")
default = next(profile for profile in profiles if profile["id"] == "default")
settings = dict(default["settings"])
settings["allowed_tools"] = MANAGED_TOOLS
settings["allowed_models"] = managed_models
settings["routing_mode"] = routing_mode
settings["allow_external"] = external_enabled
settings["classifier_enabled"] = True
settings["classifier_confidence_threshold"] = 0.70
settings["allow_user_route_override"] = False
settings["fallback_on_local_error"] = True
settings["external_for_tools"] = False
settings["external_monthly_budget_usd"] = external_budget
settings["external_input_cost_per_million_usd"] = external_input_price
settings["external_output_cost_per_million_usd"] = external_output_price
settings["memory_read"] = True
settings["memory_write"] = True

profile = request(
    "/admin/api/profiles",
    {
        "id": "archestra-managed",
        "name": "Archestra managed chat",
        "description": (
            "Managed local-first AI Gateway policy with centrally controlled routing, "
            "paid-provider budget, shared-team Mem0, and six read-only web/OCR/QR tools."
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
        if assignment["subject_type"] == subject_type
        and assignment["subject_id"] == subject_id
        and assignment["profile_id"] == "archestra-managed"
    ),
    None,
)

if matching_assignment is None:
    try:
        matching_assignment = request(
            "/admin/api/assignments",
            {
                "subject_type": subject_type,
                "subject_id": subject_id,
                "profile_id": "archestra-managed",
                "priority": 100,
            },
        )
    except urllib.error.HTTPError as error:
        if error.code != 409:
            raise

if subject_type == "group":
    for assignment in assignments:
        if (
            assignment["subject_type"] == "agent"
            and assignment["subject_id"] == "archestra-managed-chat"
            and assignment["profile_id"] == "archestra-managed"
        ):
            delete(f"/admin/api/assignments/{assignment['id']}")

print(
    "PASS: configured profile=archestra-managed "
    f"allowed_tools={len(profile['settings']['allowed_tools'])} "
    f"subject={subject_type}:{subject_id}"
)
