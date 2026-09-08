from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import unittest
import uuid

import httpx
from fastapi.testclient import TestClient


DATABASE_URL = os.environ.get("GUARDRAIL_TEST_DATABASE_URL")

if DATABASE_URL:
    os.environ["GUARDRAIL_DATABASE_URL"] = DATABASE_URL
    os.environ["POLICY_API_KEY"] = "integration-policy-key"
    os.environ["GUARDRAIL_ADMIN_KEY"] = "integration-admin-key"
    os.environ["IDENTITY_HMAC_KEY"] = "integration-identity-key"
    os.environ["ALLOW_UNSIGNED_IDENTITY_HEADERS"] = "true"
    os.environ["UPSTREAM_API_KEY"] = "integration-upstream-key"
    os.environ["UPSTREAM_BASE_URL"] = "http://mock-upstream"
    os.environ["DEFAULT_USER_ID"] = "integration-user"
    os.environ["DEFAULT_AGENT_ID"] = "integration-agent"
    os.environ["DEFAULT_ALLOWED_MODELS"] = "test-model"
    os.environ["DEFAULT_ALLOWED_TOOLS"] = ""
    os.environ["LOCAL_MODEL_ALIAS"] = "test-model"
    os.environ["AUTO_MODEL_ALIAS"] = "test-model"
    os.environ["EXTERNAL_MODEL_ALIAS"] = "external-disabled"
    os.environ["MEMORY_READ_ENABLED"] = "false"
    os.environ["MEMORY_WRITE_ENABLED"] = "false"

from app.main import app, runtime  # noqa: E402


@unittest.skipUnless(DATABASE_URL, "GUARDRAIL_TEST_DATABASE_URL is not set")
class PolicyApiIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.upstream_calls = 0
        cls.classifier_calls = 0
        cls.external_calls = 0

        async def upstream_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/models":
                model_id = (
                    "external-test-model"
                    if request.url.host == "mock-external"
                    else "test-model"
                )
                return httpx.Response(
                    200,
                    json={"object": "list", "data": [{"id": model_id}]},
                )
            if request.url.path == "/v1/chat/completions":
                cls.upstream_calls += 1
                payload = __import__("json").loads(request.content)
                if any(
                    message.get("role") == "system"
                    and "routing classifier" in message.get("content", "")
                    for message in payload.get("messages", [])
                ):
                    cls.classifier_calls += 1
                    return httpx.Response(
                        200,
                        json={
                            "choices": [
                                {
                                    "message": {
                                        "role": "assistant",
                                        "content": '{"route":"external","confidence":0.91,"reason":"integration-complex"}',
                                    },
                                    "finish_reason": "stop",
                                }
                            ]
                        },
                    )
                user_content = payload["messages"][-1]["content"]
                if request.url.host == "mock-external":
                    cls.external_calls += 1
                    return httpx.Response(
                        200,
                        json={
                            "id": "chatcmpl-external",
                            "object": "chat.completion",
                            "created": 1,
                            "model": "external-test-model",
                            "usage": {"prompt_tokens": 100, "completion_tokens": 20},
                            "choices": [
                                {
                                    "index": 0,
                                    "message": {
                                        "role": "assistant",
                                        "content": "EXTERNAL_UPSTREAM_OK",
                                    },
                                    "finish_reason": "stop",
                                }
                            ],
                        },
                    )
                content = (
                    "Synthetic output 123-45-6789"
                    if user_content == "emit-output-ssn"
                    else "SAFE_UPSTREAM_OK"
                )
                return httpx.Response(
                    200,
                    json={
                        "id": "chatcmpl-integration",
                        "object": "chat.completion",
                        "created": 1,
                        "model": "test-model",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": content},
                                "finish_reason": "stop",
                            }
                        ],
                    },
                )
            return httpx.Response(404)

        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()
        runtime.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    @classmethod
    def _headers(cls) -> dict[str, str]:
        return {
            "Authorization": "Bearer integration-policy-key",
            "X-User-ID": "integration-user",
            "X-Agent-ID": "integration-agent",
        }

    def test_admin_console_exposes_structured_policy_management(self) -> None:
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "text/html; charset=utf-8")
        for control in (
            'id="input-categories"',
            'id="output-categories"',
            'id="allowed-models"',
            'id="allowed-tools"',
            'id="max-input"',
            'id="allow-external"',
            'id="routing-mode"',
            'id="classifier-enabled"',
            'id="external-budget"',
            'id="test-external-provider"',
            'id="memory-read"',
            'id="memory-write"',
            'id="assignment-subject"',
            'id="assignment-subject-options"',
            'id="assignment-directory-status"',
            'id="client-credentials"',
            'id="issue-client-key"',
            'id="copy-client-key"',
            'id="resolve-effective"',
            'id="audit-search"',
            'id="export-config"',
            'id="import-config"',
        ):
            self.assertIn(control, response.text)
        self.assertIn("User assignments win over agent assignments", response.text)
        self.assertIn("Connected as gateway administrator", response.text)
        self.assertIn("Optional recovery token", response.text)
        self.assertIn('class="auth-required"', response.text)
        self.assertIn('class="nav-link" href="/"', response.text)
        self.assertIn("Sign in to AI Gateway as an administrator", response.text)
        self.assertIn("setConsoleLocked(false)", response.text)
        self.assertIn("section.inert=locked", response.text)
        self.assertIn("servicePrefix", response.text)
        self.assertNotIn("Enforced settings (JSON)", response.text)

    def test_admin_directory_returns_named_users_and_teams(self) -> None:
        original_client = runtime.admin_auth_http
        original_url = runtime.archestra_admin_authz_url
        original_origin = runtime.archestra_session_origin

        async def directory_handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.headers["cookie"], "session=valid")
            if request.url.path == "/api/identity-providers":
                return httpx.Response(200, json={"data": []})
            if request.url.path == "/api/members":
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {
                                "userId": "user-1",
                                "name": "Gateway User",
                                "email": "user@example.com",
                                "role": "member",
                            }
                        ]
                    },
                )
            if request.url.path == "/api/teams":
                return httpx.Response(
                    200,
                    json={"data": [{"id": "team-1", "name": "POC Users"}]},
                )
            return httpx.Response(404)

        directory_client = httpx.AsyncClient(
            transport=httpx.MockTransport(directory_handler)
        )
        runtime.admin_auth_http = directory_client
        runtime.archestra_admin_authz_url = (
            "http://archestra:9000/api/identity-providers"
        )
        runtime.archestra_session_origin = "https://192.0.2.10"
        try:
            response = self.client.get(
                "/admin/api/directory", headers={"Cookie": "session=valid"}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                response.json(),
                {
                    "users": [
                        {
                            "id": "user-1",
                            "label": "Gateway User <user@example.com>",
                        }
                    ],
                    "groups": [{"id": "team-1", "label": "POC Users"}],
                },
            )
            self.assertNotIn("role", response.text)
        finally:
            runtime.admin_auth_http = original_client
            runtime.archestra_admin_authz_url = original_url
            runtime.archestra_session_origin = original_origin
            asyncio.run(directory_client.aclose())

    def test_admin_api_requires_gateway_session_or_recovery_token(self) -> None:
        response = self.client.get("/admin/api/profiles")
        self.assertEqual(response.status_code, 401)
        self.assertIn("Gateway administrator session", response.text)

        response = self.client.get(
            "/admin/api/profiles",
            headers={"Authorization": "Bearer wrong-admin-key"},
        )
        self.assertEqual(response.status_code, 401)

    def test_safe_nonstreaming_and_streaming_requests_pass(self) -> None:
        readiness = self.client.get("/readyz")
        self.assertEqual(readiness.status_code, 200)
        self.assertEqual(readiness.json()["status"], "ready")
        self.assertEqual(readiness.json()["guardrail_database"], "connected")
        self.assertEqual(readiness.json()["signed_identity"], "configured")

        response = self.client.post(
            "/v1/chat/completions",
            headers=self._headers(),
            json={
                "model": "test-model",
                "messages": [{"role": "user", "content": "safe request"}],
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["choices"][0]["message"]["content"], "SAFE_UPSTREAM_OK"
        )

        streamed = self.client.post(
            "/v1/chat/completions",
            headers=self._headers(),
            json={
                "model": "test-model",
                "stream": True,
                "messages": [{"role": "user", "content": "safe stream"}],
            },
        )
        self.assertEqual(streamed.status_code, 200)
        self.assertIn("SAFE_UPSTREAM_OK", streamed.text)
        self.assertIn("data: [DONE]", streamed.text)
        self.assertEqual(streamed.headers["x-ai-gateway-streaming"], "buffered")

    def test_readyz_fails_closed_when_upstream_credential_is_missing(self) -> None:
        upstream_api_key = runtime.local_upstream_api_key
        try:
            runtime.local_upstream_api_key = ""
            readiness = self.client.get("/readyz")
        finally:
            runtime.local_upstream_api_key = upstream_api_key

        self.assertEqual(readiness.status_code, 503)
        self.assertEqual(readiness.json()["detail"]["status"], "degraded")
        self.assertEqual(readiness.json()["detail"]["upstream"], "missing")

    def test_invalid_signed_identity_is_blocked_before_upstream(self) -> None:
        before = self.upstream_calls
        headers = self._headers()
        headers.update(
            {
                "X-AI-Gateway-Groups": "engineering",
                "X-AI-Gateway-Identity-Signature": "0" * 64,
            }
        )
        response = self.client.post(
            "/v1/chat/completions",
            headers=headers,
            json={
                "model": "test-model",
                "messages": [{"role": "user", "content": "safe request"}],
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.upstream_calls, before)

    def test_signed_group_selects_managed_profile_and_audit_scope(self) -> None:
        profiles = self.client.get(
            "/admin/api/profiles",
            headers={"Authorization": "Bearer integration-admin-key"},
        ).json()
        default_settings = next(item for item in profiles if item["id"] == "default")[
            "settings"
        ]
        profile = self.client.post(
            "/admin/api/profiles",
            headers={"Authorization": "Bearer integration-admin-key"},
            json={
                "id": "integration-team",
                "name": "Integration team",
                "enabled": True,
                "settings": default_settings,
            },
        )
        self.assertEqual(profile.status_code, 200)
        assignment = self.client.post(
            "/admin/api/assignments",
            headers={"Authorization": "Bearer integration-admin-key"},
            json={
                "subject_type": "group",
                "subject_id": "engineering",
                "profile_id": "integration-team",
                "priority": 100,
            },
        )
        self.assertEqual(assignment.status_code, 200)

        canonical = "user=\ngroups=engineering"
        signature = hmac.new(
            b"integration-identity-key", canonical.encode(), hashlib.sha256
        ).hexdigest()
        response = self.client.post(
            "/v1/chat/completions",
            headers={
                "Authorization": "Bearer integration-policy-key",
                "X-AI-Gateway-Groups": "engineering",
                "X-AI-Gateway-Identity-Signature": signature,
            },
            json={
                "model": "test-model",
                "messages": [{"role": "user", "content": "signed group request"}],
            },
        )
        self.assertEqual(response.status_code, 200)

        audit = self.client.get(
            "/admin/api/audit?limit=10",
            headers={"Authorization": "Bearer integration-admin-key"},
        )
        self.assertEqual(audit.status_code, 200)
        matching = [
            item
            for item in audit.json()
            if item["profile_id"] == "integration-team"
            and item["stage"] == "output"
            and item["decision"] == "allow"
        ]
        self.assertTrue(matching)

    def test_sensitive_input_is_blocked_before_upstream(self) -> None:
        before = self.upstream_calls
        response = self.client.post(
            "/v1/chat/completions",
            headers=self._headers(),
            json={
                "model": "test-model",
                "messages": [
                    {"role": "user", "content": "Synthetic SSN 123-45-6789"}
                ],
            },
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.upstream_calls, before)
        self.assertEqual(response.json()["detail"]["blocked"], ["us_ssn"])

    def test_sensitive_output_is_blocked_before_client(self) -> None:
        response = self.client.post(
            "/v1/chat/completions",
            headers=self._headers(),
            json={
                "model": "test-model",
                "messages": [{"role": "user", "content": "emit-output-ssn"}],
            },
        )
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("123-45-6789", response.text)
        self.assertEqual(response.json()["detail"]["blocked"], ["us_ssn"])

    def test_local_classifier_routes_to_paid_provider_and_records_spend(self) -> None:
        headers = {"Authorization": "Bearer integration-admin-key"}
        profiles = self.client.get("/admin/api/profiles", headers=headers).json()
        default = next(item for item in profiles if item["id"] == "default")
        original_settings = default["settings"]
        managed_settings = {
            **original_settings,
            "allowed_models": [*original_settings["allowed_models"], "auto-test"],
            "routing_mode": "local_first",
            "allow_external": True,
            "classifier_enabled": True,
            "external_task_hints": [],
            "external_monthly_budget_usd": 5.0,
            "external_input_cost_per_million_usd": 2.0,
            "external_output_cost_per_million_usd": 8.0,
        }
        original_runtime = (
            runtime.external_model_enabled,
            runtime.external_upstream_base_url,
            runtime.external_upstream_api_key,
            runtime.external_upstream_model,
            runtime.auto_model_alias,
        )
        classifier_before = self.classifier_calls
        external_before = self.external_calls
        try:
            runtime.external_model_enabled = True
            runtime.external_upstream_base_url = "http://mock-external"
            runtime.external_upstream_api_key = "external-test-key"
            runtime.external_upstream_model = "external-test-model"
            runtime.auto_model_alias = "auto-test"
            saved = self.client.post(
                "/admin/api/profiles",
                headers=headers,
                json={
                    "id": "default",
                    "name": default["name"],
                    "description": default["description"],
                    "enabled": True,
                    "settings": managed_settings,
                },
            )
            self.assertEqual(saved.status_code, 200)

            provider_test = self.client.post(
                "/admin/api/providers/external/test", headers=headers, json={}
            )
            self.assertEqual(provider_test.status_code, 200)
            self.assertEqual(provider_test.json()["model"], "external-test-model")

            response = self.client.post(
                "/v1/chat/completions",
                headers=self._headers(),
                json={
                    "model": "auto-test",
                    "messages": [
                        {"role": "user", "content": "Analyze this unfamiliar scenario"}
                    ],
                },
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["x-ai-gateway-route-kind"], "external")
            self.assertTrue(
                response.headers["x-ai-gateway-route-reason"].startswith("classifier:")
            )
            self.assertEqual(
                response.json()["choices"][0]["message"]["content"],
                "EXTERNAL_UPSTREAM_OK",
            )
            self.assertEqual(self.classifier_calls, classifier_before + 1)
            self.assertEqual(self.external_calls, external_before + 1)

            usage = self.client.get(
                "/admin/api/usage?profile_id=default", headers=headers
            )
            self.assertEqual(usage.status_code, 200)
            self.assertGreater(usage.json()["cost_microusd"], 0)
        finally:
            self.client.post(
                "/admin/api/profiles",
                headers=headers,
                json={
                    "id": "default",
                    "name": default["name"],
                    "description": default["description"],
                    "enabled": True,
                    "settings": original_settings,
                },
            )
            (
                runtime.external_model_enabled,
                runtime.external_upstream_base_url,
                runtime.external_upstream_api_key,
                runtime.external_upstream_model,
                runtime.auto_model_alias,
            ) = original_runtime

    def test_block_decisions_are_auditable(self) -> None:
        input_block = self.client.post(
            "/v1/chat/completions",
            headers=self._headers(),
            json={
                "model": "test-model",
                "messages": [
                    {"role": "user", "content": "Synthetic SSN 123-45-6789"}
                ],
            },
        )
        output_block = self.client.post(
            "/v1/chat/completions",
            headers=self._headers(),
            json={
                "model": "test-model",
                "messages": [{"role": "user", "content": "emit-output-ssn"}],
            },
        )
        self.assertEqual(input_block.status_code, 422)
        self.assertEqual(output_block.status_code, 502)

        response = self.client.get(
            "/admin/api/audit?limit=20",
            headers={"Authorization": "Bearer integration-admin-key"},
        )
        self.assertEqual(response.status_code, 200)
        blocked = [event for event in response.json() if event["decision"] == "block"]
        self.assertTrue(any(event["stage"] == "input" for event in blocked))
        self.assertTrue(any(event["stage"] == "output" for event in blocked))

    def test_configuration_export_is_versioned_and_secret_free(self) -> None:
        response = self.client.get(
            "/admin/api/config-export",
            headers={"Authorization": "Bearer integration-admin-key"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["service_version"], "0.8.5")
        self.assertTrue(any(profile["id"] == "default" for profile in payload["profiles"]))
        self.assertIsInstance(payload["assignments"], list)
        serialized = response.text.lower()
        for forbidden in ("api_key", "authorization", "credential", "prompt", "audit"):
            self.assertNotIn(forbidden, serialized)

    def test_configuration_export_can_be_merged_back_idempotently(self) -> None:
        headers = {"Authorization": "Bearer integration-admin-key"}
        exported = self.client.get("/admin/api/config-export", headers=headers)
        self.assertEqual(exported.status_code, 200)

        restored = self.client.post(
            "/admin/api/config-import", headers=headers, json=exported.json()
        )
        self.assertEqual(restored.status_code, 200)
        result = restored.json()
        self.assertEqual(result["mode"], "merge")
        self.assertEqual(result["profiles_upserted"], len(exported.json()["profiles"]))
        self.assertEqual(
            result["assignments_upserted"], len(exported.json()["assignments"])
        )

        profiles = self.client.get("/admin/api/profiles", headers=headers)
        assignments = self.client.get("/admin/api/assignments", headers=headers)
        self.assertEqual(profiles.status_code, 200)
        self.assertEqual(assignments.status_code, 200)
        self.assertEqual(
            {item["id"] for item in profiles.json()},
            {item["id"] for item in exported.json()["profiles"]},
        )

    def test_managed_client_key_is_one_time_attributed_and_revocable(self) -> None:
        admin_headers = {"Authorization": "Bearer integration-admin-key"}
        user_id = f"client-{uuid.uuid4().hex[:10]}"
        issued = self.client.post(
            "/admin/api/client-credentials",
            headers=admin_headers,
            json={
                "name": "Integration managed client",
                "user_id": user_id,
                "agent_id": "vscode",
                "groups": [],
                "expires_at": None,
            },
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        payload = issued.json()
        plaintext = payload["api_key"]
        credential = payload["credential"]
        self.assertTrue(plaintext.startswith("gateway_"))
        self.assertNotIn("key_hash", issued.text)

        listed = self.client.get(
            "/admin/api/client-credentials", headers=admin_headers
        )
        self.assertEqual(listed.status_code, 200)
        listed_item = next(
            item for item in listed.json() if item["id"] == credential["id"]
        )
        self.assertNotIn("api_key", listed_item)
        self.assertNotIn("key_hash", listed_item)

        completion = self.client.post(
            "/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {plaintext}",
                "X-User-ID": "spoofed-user",
                "X-Agent-ID": "spoofed-agent",
            },
            json={
                "model": "test-model",
                "messages": [{"role": "user", "content": "managed key acceptance"}],
            },
        )
        self.assertEqual(completion.status_code, 200, completion.text)
        request_id = completion.headers["x-ai-gateway-request-id"]
        audit = self.client.get("/admin/api/audit?limit=100", headers=admin_headers)
        event = next(item for item in audit.json() if item["request_id"] == request_id)
        self.assertEqual(event["user_id"], user_id)
        self.assertEqual(event["agent_id"], "vscode")

        revoked = self.client.post(
            f"/admin/api/client-credentials/{credential['id']}/revoke",
            headers=admin_headers,
            json={},
        )
        self.assertEqual(revoked.status_code, 200)
        denied = self.client.get(
            "/v1/models", headers={"Authorization": f"Bearer {plaintext}"}
        )
        self.assertEqual(denied.status_code, 401)


if __name__ == "__main__":
    unittest.main()
