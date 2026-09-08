#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile


SCRIPT = Path(__file__).with_name("configure-managed-routing.py")
COMPOSE = Path(__file__).with_name("compose.yaml")

spec = importlib.util.spec_from_file_location("configure_managed_routing", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load configure-managed-routing.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeClient:
    chat_models: list[str] = []
    chat_limits: list[int] = []
    chat_prompts: list[str] = []
    usage_calls = 0

    def __init__(self, base_url: str, admin_key: str, policy_key: str) -> None:
        self.base_url = base_url
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
        del admin, extra_headers
        if path == "/admin/api/providers/external/test":
            return 200, {"model": "gpt-test"}, {}
        if path == "/admin/api/profiles" and method == "GET":
            return (
                200,
                [
                    {
                        "id": "archestra-managed",
                        "name": "Managed users",
                        "description": "test profile",
                        "enabled": True,
                        "settings": {
                            "allowed_models": ["granite4.1:3b"],
                            "routing_mode": "local_only",
                            "allow_external": False,
                        },
                    }
                ],
                {},
            )
        if path.startswith("/admin/api/usage"):
            FakeClient.usage_calls += 1
            if FakeClient.usage_calls == 1:
                return 200, {"requests": 0, "cost_microusd": 0}, {}
            return 200, {"requests": 1, "cost_microusd": 1000}, {}
        if path == "/admin/api/profiles" and method == "POST":
            return 200, payload or {}, {}
        if path == "/v1/chat/completions":
            if payload is None:
                raise AssertionError("chat payload is missing")
            model = str(payload.get("model"))
            FakeClient.chat_models.append(model)
            FakeClient.chat_limits.append(int(payload.get("max_tokens", 0)))
            FakeClient.chat_prompts.append(str(payload["messages"][-1]["content"]))
            route = "local" if len(FakeClient.chat_models) == 1 else (
                "external" if model == "gateway-auto" else "local"
            )
            return 200, {"choices": []}, {"x-ai-gateway-route-kind": route}
        raise AssertionError(f"unexpected request: {method} {path}")


with tempfile.TemporaryDirectory() as directory:
    env_path = Path(directory) / ".env"
    env_path.write_text(
        "DLP_ADMIN_API_KEY=test-admin\n"
        "DLP_POLICY_API_KEY=test-policy\n"
        "DLP_IDENTITY_HMAC_KEY=test-hmac\n"
        "DLP_MANAGED_GROUP_ID=test-group\n"
        "DLP_DEFAULT_MODEL=granite4.1:3b\n"
        "DLP_AUTO_MODEL_ALIAS=gateway-auto\n"
        "DLP_EXTERNAL_MODEL_ALIAS=gateway-cloud\n"
        "OPENAI_API_KEY=sk-test-routing-secret\n"
        "OPENAI_DLP_DEFAULT_MODEL=gpt-test\n"
        "DLP_EXTERNAL_ENABLED=true\n",
        encoding="utf-8",
    )
    previous_argv = sys.argv
    previous_env_path = os.environ.get("AI_GATEWAY_ENV_PATH")
    try:
        module.Client = FakeClient
        os.environ["AI_GATEWAY_ENV_PATH"] = str(env_path)
        sys.argv = [
            str(SCRIPT),
            "--monthly-budget",
            "20.00",
            "--input-price-per-million",
            "2.50",
            "--output-price-per-million",
            "15.00",
            "--confirm",
            "ENABLE_LOCAL_FIRST_ROUTING",
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = module.main()
    finally:
        sys.argv = previous_argv
        if previous_env_path is None:
            os.environ.pop("AI_GATEWAY_ENV_PATH", None)
        else:
            os.environ["AI_GATEWAY_ENV_PATH"] = previous_env_path

if result != 0:
    raise AssertionError(result)
if FakeClient.chat_models != ["granite4.1:3b", "gateway-auto"]:
    raise AssertionError(
        f"managed canaries used unexpected models: {FakeClient.chat_models}"
    )
if FakeClient.chat_limits != [32, 1024]:
    raise AssertionError(
        f"managed canaries used unexpected token limits: {FakeClient.chat_limits}"
    )
if FakeClient.chat_prompts[-1] != (
    "Security review task. Reply with exactly CLOUD_OK and no other text."
):
    raise AssertionError(f"cloud canary prompt is not deterministic: {FakeClient.chat_prompts[-1]}")
router_canary = COMPOSE.read_text(encoding="utf-8").split(
    "  dlp-router-canary:", 1
)[1].split("\n  dlp-cloud:", 1)[0]
if 'EXTERNAL_MAX_COMPLETION_TOKENS: "1024"' not in router_canary:
    raise AssertionError("router canary external ceiling must match the 1024-token request")
payload = json.loads(output.getvalue())
if payload.get("cloud_canary") != "external":
    raise AssertionError(payload)

print("CONFIGURE_MANAGED_ROUTING_CANARY_TEST_OK")
