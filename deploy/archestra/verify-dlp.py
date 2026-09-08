from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request


base_url = os.environ.get("DLP_VERIFY_URL", "http://127.0.0.1:4200").rstrip("/")
policy_key = os.environ.get("DLP_POLICY_API_KEY", "")
admin_key = os.environ.get("DLP_ADMIN_API_KEY", "")
model = os.environ.get("DLP_DEFAULT_MODEL", "granite4.1:3b")
default_user_id = os.environ.get("DLP_DEFAULT_USER_ID", "gateway-deux")
default_agent_id = os.environ.get("DLP_DEFAULT_AGENT_ID", "archestra-managed-chat")
identity_key = os.environ.get("DLP_IDENTITY_HMAC_KEY", "")
identity_headers: dict[str, str] = {}

managed_tools = [
    "gateway_web_research__fetch_webpage",
    "gateway_web_research__get_weather",
    "gateway_web_research__ocr_document",
    "gateway_web_research__scan_qr_codes",
    "gateway_web_research__scrape_webpage",
    "gateway_web_research__search_web",
]

if not policy_key:
    raise SystemExit("DLP_POLICY_API_KEY is not set")
if not admin_key:
    raise SystemExit("DLP_ADMIN_API_KEY is not set")
if not identity_key:
    raise SystemExit("DLP_IDENTITY_HMAC_KEY is not set")


def request(path: str, payload: dict | None = None) -> tuple[int, dict | str]:
    body = None if payload is None else json.dumps(payload).encode()
    headers = {"Authorization": f"Bearer {policy_key}", **identity_headers}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base_url + path, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            raw = response.read().decode()
            return response.status, json.loads(raw) if raw else ""
    except urllib.error.HTTPError as error:
        raw = error.read().decode()
        return error.code, json.loads(raw) if raw else ""


def admin_request(
    path: str, payload: dict | None = None
) -> tuple[int, dict | list | str]:
    body = None if payload is None else json.dumps(payload).encode()
    headers = {"Authorization": f"Bearer {admin_key}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        base_url + path,
        data=body,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read().decode()
            return response.status, json.loads(raw) if raw else ""
    except urllib.error.HTTPError as error:
        raw = error.read().decode()
        return error.code, json.loads(raw) if raw else ""


status, health = request("/readyz")
if (
    status != 200
    or not isinstance(health, dict)
    or health.get("status") != "ready"
    or health.get("mem0") != "configured"
    or health.get("memory_read") != "enabled"
    or health.get("memory_write") != "enabled"
    or health.get("memory_scope") != "shared"
    or health.get("local_provider") != "configured"
    or health.get("external_provider") not in {"enabled", "disabled"}
):
    raise SystemExit(f"DLP health failed: status={status}")

with urllib.request.urlopen(base_url + "/admin", timeout=30) as response:
    admin_html = response.read().decode()
if (
    response.status != 200
    or "AI Gateway Guardrail Console" not in admin_html
    or 'id="token" type="password"' not in admin_html
    or 'id="input-categories"' not in admin_html
    or 'id="allowed-models"' not in admin_html
    or 'id="resolve-effective"' not in admin_html
    or 'id="audit-search"' not in admin_html
    or 'id="import-config"' not in admin_html
    or 'id="routing-mode"' not in admin_html
    or 'id="classifier-enabled"' not in admin_html
    or 'id="external-budget"' not in admin_html
    or 'id="external-spend"' not in admin_html
    or 'id="assignment-subject-options"' not in admin_html
    or 'id="assignment-directory-status"' not in admin_html
    or 'id="client-credentials"' not in admin_html
    or 'id="issue-client-key"' not in admin_html
    or 'id="copy-client-key"' not in admin_html
    or 'class="auth-required"' not in admin_html
    or 'class="nav-link" href="/"' not in admin_html
    or "Sign in to AI Gateway as an administrator" not in admin_html
    or "/admin/api/config-import" not in admin_html
):
    raise SystemExit("DLP administrator UI is unavailable or malformed")

profiles_status, profiles = admin_request("/admin/api/profiles")
assignments_status, assignments = admin_request("/admin/api/assignments")
client_credentials_status, client_credentials = admin_request(
    "/admin/api/client-credentials"
)
export_status, config_export = admin_request("/admin/api/config-export")
usage_status, usage = admin_request("/admin/api/usage?profile_id=archestra-managed")
managed_profile = next(
    (profile for profile in profiles if profile.get("id") == "archestra-managed"),
    None,
) if isinstance(profiles, list) else None
managed_assignment = next(
    (
        assignment
        for assignment in assignments
        if assignment.get("subject_type") == "group"
        and assignment.get("profile_id") == "archestra-managed"
    ),
    None,
) if isinstance(assignments, list) else None
if (
    profiles_status != 200
    or assignments_status != 200
    or client_credentials_status != 200
    or export_status != 200
    or usage_status != 200
    or not isinstance(config_export, dict)
    or config_export.get("schema_version") != 2
    or config_export.get("service_version") != "0.8.5"
    or config_export.get("profiles") != profiles
    or config_export.get("assignments") != assignments
    or not isinstance(client_credentials, list)
    or any(
        "api_key" in item or "key_hash" in item
        for item in client_credentials
        if isinstance(item, dict)
    )
    or managed_profile is None
    or managed_assignment is None
    or managed_profile.get("settings", {}).get("allowed_tools") != managed_tools
    or managed_profile.get("settings", {}).get("memory_read") is not True
    or managed_profile.get("settings", {}).get("memory_write") is not True
    or managed_profile.get("settings", {}).get("routing_mode")
    not in {"local_only", "local_first"}
    or not isinstance(usage, dict)
    or usage.get("profile_id") != "archestra-managed"
):
    raise SystemExit("Managed Archestra DLP profile or assignment is missing")

managed_group_id = managed_assignment["subject_id"]
canonical_identity = f"user=\ngroups={managed_group_id}"
identity_headers.update(
    {
        "X-AI-Gateway-Groups": managed_group_id,
        "X-AI-Gateway-Identity-Signature": hmac.new(
            identity_key.encode(),
            canonical_identity.encode(),
            hashlib.sha256,
        ).hexdigest(),
    }
)

restore_status, restore_result = admin_request(
    "/admin/api/config-import", config_export
)
if (
    restore_status != 200
    or not isinstance(restore_result, dict)
    or restore_result.get("mode") != "merge"
    or restore_result.get("profiles_upserted") != len(profiles)
    or restore_result.get("assignments_upserted") != len(assignments)
):
    raise SystemExit("DLP configuration export could not be restored by merge")

safe_status, safe = request(
    "/v1/chat/completions",
    {
        "model": model,
        "messages": [{"role": "user", "content": "Reply exactly DLP_SAFE_OK."}],
        "max_tokens": 32,
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": "Acceptance-only tool declaration",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
            for name in managed_tools
        ],
        "tool_choice": "none",
    },
)
if safe_status != 200 or not isinstance(safe, dict):
    raise SystemExit(f"Safe DLP inference failed: status={safe_status}")
content = safe.get("choices", [{}])[0].get("message", {}).get("content", "")
if "DLP_SAFE_OK" not in content:
    raise SystemExit("Safe DLP inference returned unexpected content")

blocked_status, blocked = request(
    "/v1/chat/completions",
    {
        "model": model,
        "messages": [
            {"role": "user", "content": "Synthetic acceptance SSN 123-45-6789"}
        ],
    },
)
categories = (
    blocked.get("detail", {}).get("blocked", []) if isinstance(blocked, dict) else []
)
if blocked_status != 422 or categories != ["us_ssn"]:
    raise SystemExit(
        f"DLP input canary failed: status={blocked_status} categories={categories}"
    )

blocked_request_id = (
    blocked.get("detail", {}).get("request_id") if isinstance(blocked, dict) else None
)
audit_status, audit_events = admin_request("/admin/api/audit?limit=100")
blocked_event = next(
    (
        event
        for event in audit_events
        if event.get("request_id") == blocked_request_id
        and event.get("user_id") == default_user_id
        and event.get("agent_id") == default_agent_id
        and event.get("profile_id") == "archestra-managed"
        and event.get("stage") == "input"
        and event.get("decision") == "block"
        and event.get("categories") == ["us_ssn"]
    ),
    None,
) if isinstance(audit_events, list) else None
if audit_status != 200 or not blocked_request_id or blocked_event is None:
    raise SystemExit("DLP input canary did not produce the expected audit record")

print(
    "PASS: DLP admin UI/API ready; managed profile assigned; shared-team Mem0 "
    "middleware enabled; six research/OCR/QR tools accepted; configuration export "
    "restored by merge; managed routing controls and spend ledger readable; safe "
    "inference completed; synthetic SSN blocked and audited "
    "before upstream"
)
