#!/usr/bin/env python3
"""Enable the managed team's local-first route after provider staging.

This transaction changes only the existing DLP profile. It proves a local
request, a deterministic cloud escalation, spend accounting, and audit before
leaving the profile enabled. On failure the original profile is restored.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request


PROFILE_ID = "archestra-managed"
CONFIRMATION = "ENABLE_LOCAL_FIRST_ROUTING"


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def positive_decimal(name: str, raw: str) -> float:
    try:
        value = Decimal(raw)
    except InvalidOperation as error:
        raise SystemExit(f"{name} must be a positive decimal") from error
    if not value.is_finite() or value <= 0:
        raise SystemExit(f"{name} must be a positive decimal")
    return float(value)


class Client:
    def __init__(self, base_url: str, admin_key: str, policy_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.admin_key = admin_key
        self.policy_key = policy_key

    def call(
        self,
        path: str,
        method: str = "GET",
        payload: dict | None = None,
        *,
        admin: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, object, dict[str, str]]:
        body = None if payload is None else json.dumps(payload).encode()
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.admin_key if admin else self.policy_key}",
            **(extra_headers or {}),
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path, data=body, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                text = response.read().decode(errors="replace")
                return (
                    response.status,
                    json.loads(text) if text else None,
                    {key.lower(): value for key, value in response.headers.items()},
                )
        except urllib.error.HTTPError as error:
            text = error.read().decode(errors="replace")
            try:
                data = json.loads(text) if text else None
            except json.JSONDecodeError:
                data = None
            return error.code, data, {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Enable managed local-first routing.")
    parser.add_argument("--monthly-budget", required=True)
    parser.add_argument("--input-price-per-million", required=True)
    parser.add_argument("--output-price-per-million", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"--confirm must equal {CONFIRMATION}")
    budget = positive_decimal("--monthly-budget", args.monthly_budget)
    input_price = positive_decimal(
        "--input-price-per-million", args.input_price_per_million
    )
    output_price = positive_decimal(
        "--output-price-per-million", args.output_price_per_million
    )

    env_path = Path(
        os.environ.get("AI_GATEWAY_ENV_PATH", "/opt/ai-gateway/archestra/.env")
    )
    values = load_env(env_path)
    required = (
        "DLP_ADMIN_API_KEY",
        "DLP_POLICY_API_KEY",
        "DLP_IDENTITY_HMAC_KEY",
        "DLP_MANAGED_GROUP_ID",
        "OPENAI_API_KEY",
        "OPENAI_DLP_DEFAULT_MODEL",
    )
    missing = [name for name in required if not values.get(name)]
    if missing:
        raise RuntimeError("Missing managed routing prerequisites: " + ", ".join(missing))
    if values.get("DLP_EXTERNAL_ENABLED", "false").lower() != "true":
        raise RuntimeError("DLP_EXTERNAL_ENABLED must be true before policy activation")

    bind = values.get("DLP_BIND_ADDRESS") or values.get(
        "ARCHESTRA_BIND_ADDRESS", "192.0.2.10"
    )
    client = Client(
        os.environ.get("DLP_ADMIN_URL", f"http://{bind}:4200"),
        values["DLP_ADMIN_API_KEY"],
        values["DLP_POLICY_API_KEY"],
    )
    status, provider, _ = client.call(
        "/admin/api/providers/external/test", "POST", {}
    )
    if (
        status != 200
        or not isinstance(provider, dict)
        or provider.get("model") != values["OPENAI_DLP_DEFAULT_MODEL"]
    ):
        raise RuntimeError(f"external provider validation failed with HTTP {status}")

    status, profiles, _ = client.call("/admin/api/profiles")
    if status != 200 or not isinstance(profiles, list):
        raise RuntimeError("guardrail profiles are unavailable")
    original = next(
        (item for item in profiles if isinstance(item, dict) and item.get("id") == PROFILE_ID),
        None,
    )
    if original is None:
        raise RuntimeError(f"guardrail profile {PROFILE_ID!r} is missing")

    settings = dict(original["settings"])
    for model in (
        values.get("DLP_DEFAULT_MODEL", "granite4.1:3b"),
        values.get("DLP_AUTO_MODEL_ALIAS", "gateway-auto"),
        values.get("DLP_EXTERNAL_MODEL_ALIAS", "gateway-cloud"),
    ):
        if model not in settings["allowed_models"]:
            settings["allowed_models"].append(model)
    settings.update(
        {
            "routing_mode": "local_first",
            "allow_external": True,
            "classifier_enabled": True,
            "classifier_confidence_threshold": 0.70,
            "allow_user_route_override": False,
            "fallback_on_local_error": True,
            "external_for_tools": False,
            "external_monthly_budget_usd": budget,
            "external_input_cost_per_million_usd": input_price,
            "external_output_cost_per_million_usd": output_price,
        }
    )
    updated = {
        "id": original["id"],
        "name": original["name"],
        "description": original.get("description", ""),
        "enabled": True,
        "settings": settings,
    }

    group_id = values["DLP_MANAGED_GROUP_ID"]
    canonical = f"user=\ngroups={group_id}"
    identity_headers = {
        "X-AI-Gateway-Groups": group_id,
        "X-AI-Gateway-Identity-Signature": hmac.new(
            values["DLP_IDENTITY_HMAC_KEY"].encode(),
            canonical.encode(),
            hashlib.sha256,
        ).hexdigest(),
    }
    before_status, before_usage, _ = client.call(
        f"/admin/api/usage?{urllib.parse.urlencode({'profile_id': PROFILE_ID})}"
    )
    if before_status != 200 or not isinstance(before_usage, dict):
        raise RuntimeError("external usage ledger is unavailable")
    before_requests = int(before_usage.get("requests", 0))

    local_only_settings = dict(settings)
    local_only_settings.update(
        {
            "routing_mode": "local_only",
            "allow_external": False,
            "external_monthly_budget_usd": 0,
            "external_input_cost_per_million_usd": 0,
            "external_output_cost_per_million_usd": 0,
        }
    )
    local_only = {
        "id": original["id"],
        "name": original["name"],
        "description": original.get("description", ""),
        "enabled": True,
        "settings": local_only_settings,
    }

    try:
        status, _, _ = client.call("/admin/api/profiles", "POST", local_only)
        if status != 200:
            raise RuntimeError(f"local-only canary profile returned HTTP {status}")

        local_status, local_body, local_headers = client.call(
            "/v1/chat/completions",
            "POST",
            {
                "model": values.get("DLP_DEFAULT_MODEL", "granite4.1:3b"),
                "messages": [
                    {"role": "user", "content": "Write a two-word friendly greeting."}
                ],
                "max_tokens": 32,
            },
            admin=False,
            extra_headers=identity_headers,
        )
        if (
            local_status != 200
            or not isinstance(local_body, dict)
            or local_headers.get("x-ai-gateway-route-kind") != "local"
        ):
            raise RuntimeError("local-first canary did not remain on local inference")

        status, _, _ = client.call("/admin/api/profiles", "POST", updated)
        if status != 200:
            raise RuntimeError(f"managed routing profile update returned HTTP {status}")

        cloud_status, cloud_body, cloud_headers = client.call(
            "/v1/chat/completions",
            "POST",
            {
                # Exercise the same managed alias used by real clients. Sending
                # the concrete local model here explicitly pins the request to
                # local inference and can never prove governed escalation.
                "model": values.get("DLP_AUTO_MODEL_ALIAS", "gateway-auto"),
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Security review task. Reply with exactly CLOUD_OK "
                            "and no other text."
                        ),
                    }
                ],
                # Reasoning-model completion budgets include hidden reasoning
                # tokens. The canary also receives shared Mem0 context, so use
                # the same bounded ceiling as real external requests.
                "max_tokens": 1024,
            },
            admin=False,
            extra_headers=identity_headers,
        )
        if (
            cloud_status != 200
            or not isinstance(cloud_body, dict)
            or cloud_headers.get("x-ai-gateway-route-kind") != "external"
        ):
            raise RuntimeError(
                "cloud escalation canary failed "
                f"(status={cloud_status}, "
                f"route={cloud_headers.get('x-ai-gateway-route-kind', 'missing')})"
            )

        after_status, after_usage, _ = client.call(
            f"/admin/api/usage?{urllib.parse.urlencode({'profile_id': PROFILE_ID})}"
        )
        if (
            after_status != 200
            or not isinstance(after_usage, dict)
            or int(after_usage.get("requests", 0)) <= before_requests
            or int(after_usage.get("cost_microusd", 0)) <= 0
        ):
            raise RuntimeError("cloud escalation was not recorded in the spend ledger")
    except Exception:
        rollback = {
            "id": original["id"],
            "name": original["name"],
            "description": original.get("description", ""),
            "enabled": original.get("enabled", True),
            "settings": original["settings"],
        }
        rollback_status, _, _ = client.call("/admin/api/profiles", "POST", rollback)
        if rollback_status != 200:
            print(
                f"WARNING: managed profile rollback returned HTTP {rollback_status}",
                file=os.sys.stderr,
            )
        raise

    print(
        json.dumps(
            {
                "status": "PASS",
                "action": "configure-managed-routing",
                "profile": PROFILE_ID,
                "routing_mode": "local_first",
                "external_model": values["OPENAI_DLP_DEFAULT_MODEL"],
                "monthly_budget_usd": budget,
                "local_canary": "local",
                "cloud_canary": "external",
                "spend_accounted": True,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError) as error:
        print(f"ERROR: {error}", file=os.sys.stderr)
        raise SystemExit(1)
