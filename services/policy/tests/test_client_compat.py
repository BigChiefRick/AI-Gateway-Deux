import asyncio
from datetime import datetime, timezone
import hashlib
import hmac
import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

from app.guardrails import GuardrailSettings
from app.main import (
    GatewayPrincipal,
    _approved_memories,
    _assistant_text,
    _bounded_provider_payload,
    _buffered_sse,
    _classifier_result,
    _client_identity,
    _client_groups,
    _conversation_id,
    _external_cost_microusd,
    _has_governed_web_tool,
    _has_current_web_evidence,
    _input_dlp_violations,
    _memory_scope,
    _memory_created_at_window,
    _memory_write_messages,
    _managed_route_payload,
    _require_admin_access,
    _requested_tool_names,
    _request_identity,
    _response_tool_names,
    _route_payload,
    _safe_route_reason,
    _search_memories,
    _signed_identity_context,
    _text_length,
    _trusted_current_date_message,
    _is_volatile_request,
    _is_explicit_memory_request,
    _is_code_contribution,
    runtime,
)


class ClientCompatibilityTests(unittest.TestCase):
    def test_explicit_local_model_stays_local_when_tools_would_auto_escalate(self) -> None:
        original = (
            runtime.local_model_alias,
            runtime.auto_model_alias,
            runtime.external_model_alias,
            runtime.local_upstream_model,
            runtime.external_upstream_model,
            runtime.external_model_enabled,
        )
        try:
            runtime.local_model_alias = "granite-local"
            runtime.auto_model_alias = "gateway-auto"
            runtime.external_model_alias = "gateway-cloud"
            runtime.local_upstream_model = "granite-local"
            runtime.external_upstream_model = "gpt-cloud"
            runtime.external_model_enabled = True
            _, decision = asyncio.run(
                _managed_route_payload(
                    {
                        "model": "granite-local",
                        "messages": [{"role": "user", "content": "safe request"}],
                    },
                    GuardrailSettings(
                        routing_mode="local_first",
                        allow_external=True,
                        external_for_tools=True,
                    ),
                    {"approved_tool"},
                )
            )
        finally:
            (
                runtime.local_model_alias,
                runtime.auto_model_alias,
                runtime.external_model_alias,
                runtime.local_upstream_model,
                runtime.external_upstream_model,
                runtime.external_model_enabled,
            ) = original
        self.assertEqual(decision.kind, "local")
        self.assertEqual(decision.model, "granite-local")
        self.assertEqual(decision.reason, "model:local")

    def test_poc_defaults_support_clients_without_custom_headers(self) -> None:
        self.assertEqual(
            _client_identity(None, None, "example-user", "managed-chat"),
            ("example-user", "managed-chat"),
        )

    def test_managed_client_credential_identity_ignores_spoofable_headers(self) -> None:
        principal = GatewayPrincipal(
            credential_kind="client",
            credential_id="client-key-1",
            user_id="managed-user",
            agent_id="vscode",
            groups=("managed-team",),
        )
        self.assertEqual(
            _request_identity(
                "spoofed-user",
                "spoofed-agent",
                "spoofed-team",
                None,
                None,
                None,
                "default-user",
                "default-agent",
                principal,
            ),
            ("managed-user", "vscode", ["managed-team"]),
        )

    def test_mem0_scope_can_be_per_user_across_conversations(self) -> None:
        self.assertEqual(_memory_scope("ai-gateway", "user-123"), "ai-gateway::user-123")

    def test_mem0_scope_can_be_shared_across_team_users(self) -> None:
        first = _memory_scope("ai-gateway", "alice@example.test", "shared", "gateway-deux")
        second = _memory_scope("ai-gateway", "bob@example.test", "shared", "gateway-deux")
        self.assertEqual(first, "ai-gateway::gateway-deux")
        self.assertEqual(first, second)

    def test_memory_relevance_gate_rejects_unrelated_and_unscored_results(self) -> None:
        response = {
            "results": [
                {
                    "memory": "Directly relevant",
                    "score": 0.81,
                    "metadata": {"knowledge_origin": "user-contributed"},
                },
                {
                    "memory": "Unrelated weather",
                    "score": 0.32,
                    "metadata": {"knowledge_origin": "user-contributed"},
                },
                {
                    "memory": "Untrusted legacy assistant answer",
                    "score": 0.95,
                    "metadata": {},
                },
                {"memory": "Missing score", "metadata": {"knowledge_origin": "user-contributed"}},
            ]
        }
        self.assertEqual(_approved_memories(response, 0.55), ["Directly relevant"])

    def test_current_data_requests_bypass_durable_memory_recall(self) -> None:
        self.assertTrue(
            _is_volatile_request("What is the record of the Texas Rangers as of today?")
        )
        self.assertTrue(_is_volatile_request("Give me the current weather"))
        self.assertFalse(_is_volatile_request("Remember my preferred writing style"))

    def test_explicit_organization_memory_requests_are_detected(self) -> None:
        self.assertTrue(
            _is_explicit_memory_request(
                "Using Mem0, tell me about the last project I worked on"
            )
        )
        self.assertTrue(_is_explicit_memory_request("Recall this from team memory"))
        self.assertTrue(_is_explicit_memory_request("What did I work on yesterday?"))
        self.assertTrue(_is_explicit_memory_request("What was the team working on?"))
        self.assertTrue(_is_explicit_memory_request("Give me a work recap"))
        self.assertFalse(_is_explicit_memory_request("Search the web for a project"))

    def test_yesterday_memory_query_uses_gateway_local_day_window(self) -> None:
        original = runtime.gateway_timezone
        try:
            runtime.gateway_timezone = "America/Chicago"
            window = _memory_created_at_window(
                "What did I work on yesterday?",
                datetime(2026, 8, 13, 15, 0, tzinfo=timezone.utc),
            )
        finally:
            runtime.gateway_timezone = original
        self.assertEqual(
            window,
            {
                "gte": "2026-08-12T05:00:00Z",
                "lte": "2026-08-13T04:59:59.999999Z",
            },
        )

    def test_non_temporal_memory_query_has_no_date_filter(self) -> None:
        self.assertIsNone(_memory_created_at_window("What was our last project?"))

    def test_trusted_memory_scope_does_not_require_gateway_provenance(self) -> None:
        response = {
            "results": [
                {
                    "memory": "Codex project checkpoint",
                    "score": 0.91,
                    "metadata": {"source": "codex_turn_ended_hook"},
                }
            ]
        }
        self.assertEqual(
            _approved_memories(response, 0.25, require_user_origin=False),
            ["Codex project checkpoint"],
        )
        self.assertEqual(_approved_memories(response, 0.25), [])

    def test_memory_search_combines_shared_and_all_project_trusted_scope(self) -> None:
        class FakeMemory:
            def __init__(self) -> None:
                self.filters: list[dict] = []

            def search(self, _query: str, **kwargs: object) -> dict:
                filters = kwargs["filters"]
                assert isinstance(filters, dict)
                self.filters.append(filters)
                scope = filters["AND"][0]["user_id"]
                if scope == "ai-gateway::gateway-deux":
                    return {
                        "results": [
                            {
                                "memory": "Shared user contribution",
                                "score": 0.80,
                                "metadata": {"knowledge_origin": "user-contributed"},
                            },
                            {
                                "memory": "Legacy assistant output",
                                "score": 0.99,
                                "metadata": {},
                            },
                        ]
                    }
                return {
                    "results": [
                        {
                            "memory": "Codex checkpoint from another project",
                            "score": 0.90,
                            "metadata": {
                                "source": "codex_turn_ended_hook",
                                "project": "Fortigate",
                                "session_id": "session-1",
                                "turn_id": "turn-1",
                            },
                        },
                        {
                            "memory": "Duplicate wording for the same Codex turn",
                            "score": 0.89,
                            "metadata": {
                                "source": "codex_turn_ended_hook",
                                "project": "Fortigate",
                                "session_id": "session-1",
                                "turn_id": "turn-1",
                            },
                        }
                    ]
                }

        fake = FakeMemory()
        original = (
            runtime.mem0,
            runtime.mem0_trusted_read_user_ids,
            runtime.max_memories,
            runtime.mem0_min_relevance_score,
        )
        try:
            runtime.mem0 = fake
            runtime.mem0_trusted_read_user_ids = ("example-user",)
            runtime.max_memories = 5
            runtime.mem0_min_relevance_score = 0.25
            results = asyncio.run(
                _search_memories(
                    "What did I work on yesterday?",
                    "ai-gateway::gateway-deux",
                    created_at_window={
                        "gte": "2026-08-12T05:00:00Z",
                        "lte": "2026-08-13T04:59:59.999999Z",
                    },
                )
            )
        finally:
            (
                runtime.mem0,
                runtime.mem0_trusted_read_user_ids,
                runtime.max_memories,
                runtime.mem0_min_relevance_score,
            ) = original

        self.assertEqual(
            results,
            [
                "Codex checkpoint from another project\n[project=Fortigate]",
                "Shared user contribution",
            ],
        )
        self.assertEqual(len(fake.filters), 2)
        filters_by_scope = {
            item["AND"][0]["user_id"]: item for item in fake.filters
        }
        self.assertEqual(
            len(filters_by_scope["ai-gateway::gateway-deux"]["AND"]), 3
        )
        self.assertEqual(
            filters_by_scope["example-user"],
            {
                "AND": [
                    {"user_id": "example-user"},
                    {
                        "created_at": {
                            "gte": "2026-08-12T05:00:00Z",
                            "lte": "2026-08-13T04:59:59.999999Z",
                        }
                    },
                ]
            },
        )

    def test_tool_evidence_does_not_trigger_payment_card_false_positive(self) -> None:
        payload = {
            "model": "gateway-auto",
            "messages": [
                {"role": "user", "content": "Summarize the fetched page"},
                {
                    "role": "tool",
                    "tool_call_id": "call-1",
                    "content": "Public page identifier 4242 4242 4242 4242",
                },
            ],
        }
        self.assertNotIn("payment_card", _input_dlp_violations(payload))

    def test_user_payment_card_is_still_blocked(self) -> None:
        payload = {
            "model": "gateway-auto",
            "messages": [
                {"role": "user", "content": "My card is 4242 4242 4242 4242"}
            ],
        }
        self.assertIn("payment_card", _input_dlp_violations(payload))

    def test_volatile_requests_are_not_written_to_organization_memory(self) -> None:
        self.assertEqual(_memory_write_messages("What is the score today?", True), [])

    def test_automatic_memory_write_contains_only_user_contribution(self) -> None:
        self.assertEqual(
            _memory_write_messages("Here is my reusable code solution", False),
            [{"role": "user", "content": "Here is my reusable code solution"}],
        )

    def test_explicit_memory_queries_are_not_written_back_as_knowledge(self) -> None:
        self.assertEqual(
            _memory_write_messages(
                "Using Mem0, what was our last project?", False, True
            ),
            [],
        )

    def test_code_contributions_are_detected_for_verbatim_storage(self) -> None:
        self.assertTrue(_is_code_contribution("```python\nprint('shared')\n```"))
        self.assertTrue(_is_code_contribution("def shared_solution():\n    return 1"))
        self.assertFalse(_is_code_contribution("How should I solve this problem?"))

    def test_explicit_chat_id_becomes_memory_conversation_id(self) -> None:
        self.assertEqual(
            _conversation_id("chat-123", "request-1"),
            "chat-123",
        )

    def test_provider_payload_disables_reasoning_and_caps_tokens(self) -> None:
        payload = _bounded_provider_payload(
            {
                "model": "local-chat",
                "max_tokens": 4096,
                "stream": True,
                "stream_options": {"include_usage": True},
            },
            512,
        )
        self.assertEqual(payload["max_tokens"], 512)
        self.assertNotIn("reasoning_effort", payload)
        self.assertFalse(payload["stream"])
        self.assertNotIn("stream_options", payload)

    def test_trusted_current_date_uses_gateway_timezone(self) -> None:
        original_timezone = runtime.gateway_timezone
        try:
            runtime.gateway_timezone = "America/Chicago"
            message = _trusted_current_date_message(
                datetime(2026, 8, 11, 3, 0, tzinfo=timezone.utc)
            )
        finally:
            runtime.gateway_timezone = original_timezone
        self.assertEqual(message["role"], "system")
        self.assertIn("2026-08-10 (America/Chicago)", message["content"])
        self.assertIn("include its year", message["content"])

    def test_provider_payload_adds_default_token_limit_without_rewriting_prompt(self) -> None:
        payload = _bounded_provider_payload(
            {"model": "local-chat", "messages": [{"role": "user", "content": "hello"}]},
            512,
        )
        self.assertEqual(payload["max_tokens"], 512)
        self.assertEqual(payload["messages"][0]["content"], "hello")

    def test_external_payload_enforces_low_reasoning(self) -> None:
        payload = _bounded_provider_payload(
            {
                "model": "external-chat",
                "max_tokens": 4096,
                "reasoning_effort": "high",
                "messages": [{"role": "user", "content": "review this"}],
            },
            1024,
            "low",
            True,
        )
        self.assertEqual(payload["reasoning_effort"], "low")
        self.assertEqual(payload["max_completion_tokens"], 1024)
        self.assertNotIn("max_tokens", payload)

    def test_external_tool_payload_disables_reasoning_for_chat_completions(self) -> None:
        payload = _bounded_provider_payload(
            {
                "model": "external-chat",
                "messages": [{"role": "user", "content": "check the weather"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "parameters": {"type": "object", "properties": {}},
                        },
                    }
                ],
            },
            1024,
            "low",
            True,
        )
        self.assertEqual(payload["reasoning_effort"], "none")

    def test_tool_availability_does_not_force_auto_route_external(self) -> None:
        original = (
            runtime.auto_model_alias,
            runtime.local_upstream_model,
            runtime.external_upstream_model,
            runtime.external_model_enabled,
        )
        try:
            runtime.auto_model_alias = "gateway-auto"
            runtime.local_upstream_model = "granite-local"
            runtime.external_upstream_model = "gpt-cloud"
            runtime.external_model_enabled = True
            _, decision = asyncio.run(
                _managed_route_payload(
                    {
                        "model": "gateway-auto",
                        "messages": [{"role": "user", "content": "check the weather"}],
                    },
                    GuardrailSettings(
                        routing_mode="local_first",
                        allow_external=True,
                        classifier_enabled=False,
                        external_for_tools=False,
                    ),
                    {"get_weather"},
                )
            )
        finally:
            (
                runtime.auto_model_alias,
                runtime.local_upstream_model,
                runtime.external_upstream_model,
                runtime.external_model_enabled,
            ) = original
        self.assertEqual(decision.kind, "local")
        self.assertEqual(decision.model, "granite-local")

    def test_current_web_evidence_escalates_only_the_synthesis_turn(self) -> None:
        original = (
            runtime.auto_model_alias,
            runtime.local_upstream_model,
            runtime.external_upstream_model,
            runtime.external_model_enabled,
        )
        messages = [
            {"role": "user", "content": "What is the current record?"},
            {
                "role": "tool",
                "content": (
                    'current_date: "2026-08-11"\n'
                    'freshness_policy: "fetch an authoritative source"'
                ),
            },
        ]
        self.assertTrue(_has_current_web_evidence(messages))
        try:
            runtime.auto_model_alias = "gateway-auto"
            runtime.local_upstream_model = "granite-local"
            runtime.external_upstream_model = "gpt-cloud"
            runtime.external_model_enabled = True
            _, decision = asyncio.run(
                _managed_route_payload(
                    {"model": "gateway-auto", "messages": messages},
                    GuardrailSettings(
                        routing_mode="local_first",
                        allow_external=True,
                        classifier_enabled=False,
                        external_for_tools=False,
                    ),
                    {"search_web", "fetch_webpage"},
                )
            )
        finally:
            (
                runtime.auto_model_alias,
                runtime.local_upstream_model,
                runtime.external_upstream_model,
                runtime.external_model_enabled,
            ) = original
        self.assertEqual(decision.kind, "external")
        self.assertEqual(decision.model, "gpt-cloud")
        self.assertEqual(decision.reason, "policy:current-evidence-synthesis")

    def test_organization_memory_synthesis_uses_governed_external_route(self) -> None:
        original = (
            runtime.auto_model_alias,
            runtime.local_upstream_model,
            runtime.external_upstream_model,
            runtime.external_model_enabled,
        )
        try:
            runtime.auto_model_alias = "gateway-auto"
            runtime.local_upstream_model = "granite-local"
            runtime.external_upstream_model = "gpt-cloud"
            runtime.external_model_enabled = True
            _, decision = asyncio.run(
                _managed_route_payload(
                    {
                        "model": "gateway-auto",
                        "messages": [
                            {
                                "role": "user",
                                "content": "What did I work on yesterday?",
                            }
                        ],
                    },
                    GuardrailSettings(
                        routing_mode="local_first",
                        allow_external=True,
                        classifier_enabled=True,
                        external_for_tools=False,
                    ),
                    {
                        "gateway_web_research__search_web",
                        "gateway_web_research__fetch_webpage",
                    },
                )
            )
        finally:
            (
                runtime.auto_model_alias,
                runtime.local_upstream_model,
                runtime.external_upstream_model,
                runtime.external_model_enabled,
            ) = original
        self.assertEqual(decision.kind, "external")
        self.assertEqual(decision.model, "gpt-cloud")
        self.assertEqual(decision.reason, "policy:organization-memory-synthesis")

    def test_local_classifier_gates_current_research_before_external_route(self) -> None:
        original = (
            runtime.auto_model_alias,
            runtime.local_upstream_model,
            runtime.external_upstream_model,
            runtime.external_model_enabled,
        )
        classifier = AsyncMock(return_value=("local", 0.99, "simple-question"))
        try:
            runtime.auto_model_alias = "gateway-auto"
            runtime.local_upstream_model = "granite-local"
            runtime.external_upstream_model = "gpt-cloud"
            runtime.external_model_enabled = True
            with patch("app.main._classify_with_local_model", classifier):
                _, decision = asyncio.run(
                    _managed_route_payload(
                        {
                            "model": "gateway-auto",
                            "messages": [
                                {
                                    "role": "user",
                                    "content": "What is the Texas Rangers record today?",
                                }
                            ],
                        },
                        GuardrailSettings(
                            routing_mode="local_first",
                            allow_external=True,
                            classifier_enabled=True,
                            external_for_tools=False,
                        ),
                        {
                            "gateway_web_research__search_web",
                            "gateway_web_research__fetch_webpage",
                        },
                    )
                )
        finally:
            (
                runtime.auto_model_alias,
                runtime.local_upstream_model,
                runtime.external_upstream_model,
                runtime.external_model_enabled,
            ) = original
        classifier.assert_awaited_once()
        self.assertEqual(decision.kind, "external")
        self.assertEqual(decision.model, "gpt-cloud")
        self.assertEqual(decision.reason, "policy:current-data-research")

    def test_local_payload_translates_client_max_completion_tokens(self) -> None:
        payload = _bounded_provider_payload(
            {"model": "local-chat", "max_completion_tokens": 256},
            128,
        )
        self.assertEqual(payload["max_tokens"], 128)
        self.assertNotIn("max_completion_tokens", payload)

    def test_buffered_sse_contains_content_finish_and_done(self) -> None:
        payload = {
            "id": "chatcmpl-1",
            "created": 123,
            "model": "local-chat",
            "choices": [
                {
                    "message": {"role": "assistant", "content": "CLIENT OK"},
                    "finish_reason": "stop",
                }
            ],
        }

        assistant_text = _assistant_text(payload)
        response = _buffered_sse(payload, assistant_text)
        events = response.body.decode().strip().split("\n\n")

        first = json.loads(events[0].removeprefix("data: "))
        final = json.loads(events[1].removeprefix("data: "))
        self.assertEqual(first["choices"][0]["delta"]["content"], "CLIENT OK")
        self.assertEqual(final["choices"][0]["finish_reason"], "stop")
        self.assertEqual(events[2], "data: [DONE]")
        self.assertEqual(response.headers["x-ai-gateway-streaming"], "buffered")

    def test_explicit_local_directive_strips_control_text(self) -> None:
        payload, model, reason = _route_payload(
            {
                "model": "auto-chat",
                "messages": [{"role": "user", "content": "/local summarize this"}],
            },
            external_enabled=True,
        )
        self.assertEqual(model, "local-chat")
        self.assertEqual(reason, "directive:local")
        self.assertEqual(payload["messages"][0]["content"], "summarize this")

    def test_explicit_external_directive_routes_to_openai(self) -> None:
        payload, model, reason = _route_payload(
            {
                "model": "auto-chat",
                "messages": [{"role": "user", "content": "/external review this architecture"}],
            },
            external_enabled=True,
        )
        self.assertEqual(payload["model"], "external-chat")
        self.assertEqual(model, "external-chat")
        self.assertEqual(reason, "directive:external")

    def test_auto_routes_coding_work_to_external(self) -> None:
        _, model, reason = _route_payload(
            {
                "model": "auto-chat",
                "messages": [{"role": "user", "content": "Debug this Python service"}],
            },
            external_enabled=True,
        )
        self.assertEqual(model, "external-chat")
        self.assertEqual(reason, "auto:external-capability")

    def test_auto_defaults_simple_chat_to_local(self) -> None:
        _, model, reason = _route_payload(
            {
                "model": "auto-chat",
                "messages": [{"role": "user", "content": "Write a short thank-you note"}],
            },
            external_enabled=True,
        )
        self.assertEqual(model, "local-chat")
        self.assertEqual(reason, "auto:local-default")

    def test_auto_falls_back_local_when_external_is_disabled(self) -> None:
        _, model, reason = _route_payload(
            {
                "model": "auto-chat",
                "messages": [{"role": "user", "content": "Review this code"}],
            },
            external_enabled=False,
        )
        self.assertEqual(model, "local-chat")
        self.assertEqual(reason, "auto:external-unavailable-fallback-local")

    def test_forced_external_fails_closed_when_disabled(self) -> None:
        with self.assertRaises(HTTPException) as context:
            _route_payload(
                {
                    "model": "external-chat",
                    "messages": [{"role": "user", "content": "hello"}],
                },
                external_enabled=False,
            )
        self.assertEqual(context.exception.status_code, 503)

    def test_assistant_text_is_empty_when_provider_returns_no_content(self) -> None:
        self.assertEqual(_assistant_text({"choices": [{"message": {}}]}), "")

    def test_local_classifier_accepts_only_bounded_json_contract(self) -> None:
        self.assertEqual(
            _classifier_result(
                '{"route":"external","confidence":0.91,"reason":"complex-code"}'
            ),
            ("external", 0.91, "complex-code"),
        )
        self.assertIsNone(_classifier_result("I think external would be better"))
        self.assertIsNone(
            _classifier_result(
                '{"route":"external","confidence":4,"reason":"invalid"}'
            )
        )
        self.assertEqual(
            _classifier_result(
                '{"route":"external","confidence":0.9,'
                '"reason":"Requires current data\\nfrom MLB âœ“"}'
            ),
            ("external", 0.9, "Requires-current-data-from-MLB"),
        )
        self.assertEqual(_safe_route_reason("unsafe\r\nheader âœ“"), "unsafe-header")

    def test_namespaced_governed_web_tools_are_recognized(self) -> None:
        self.assertTrue(
            _has_governed_web_tool(
                {
                    "gateway_web_research__search_web",
                    "gateway_web_research__fetch_webpage",
                }
            )
        )
        self.assertFalse(_has_governed_web_tool({"get_weather", "scan_qr_code"}))

    def test_external_cost_uses_integer_microdollar_accounting(self) -> None:
        settings = GuardrailSettings(
            external_input_cost_per_million_usd=2.0,
            external_output_cost_per_million_usd=8.0,
        )
        self.assertEqual(_external_cost_microusd(1_000, 500, settings), 6_000)

    def test_group_header_is_validated_and_deduplicated(self) -> None:
        self.assertEqual(_client_groups("engineering, finance,engineering"), ["engineering", "finance"])

    def test_signed_group_identity_is_canonical_and_verified(self) -> None:
        key = "identity-test-key"
        canonical = "user=\ngroups=engineering,finance"
        signature = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()

        user_id, groups, signed = _signed_identity_context(
            None,
            "finance,engineering,finance",
            signature,
            key,
        )

        self.assertIsNone(user_id)
        self.assertEqual(groups, ["engineering", "finance"])
        self.assertTrue(signed)

    def test_invalid_signed_identity_fails_closed(self) -> None:
        with self.assertRaises(HTTPException) as context:
            _signed_identity_context(
                "user-123",
                "engineering",
                "0" * 64,
                "identity-test-key",
            )

        self.assertEqual(context.exception.status_code, 403)

    def test_text_length_counts_nested_message_content(self) -> None:
        self.assertEqual(
            _text_length([{"role": "user", "content": "hello"}, {"content": ["abc"]}]),
            12,
        )

    def test_tool_names_are_extracted_from_request_and_response(self) -> None:
        request = {
            "tools": [
                {"type": "function", "function": {"name": "weather_lookup"}},
                {"type": "function", "function": {"name": "search_web"}},
            ]
        }
        response = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {"type": "function", "function": {"name": "weather_lookup"}}
                        ]
                    }
                }
            ]
        }
        self.assertEqual(_requested_tool_names(request), {"weather_lookup", "search_web"})
        self.assertEqual(_response_tool_names(response), {"weather_lookup"})

    def test_buffered_sse_preserves_tool_calls(self) -> None:
        payload = {
            "id": "chatcmpl-tool",
            "model": "external-chat",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-1",
                                "type": "function",
                                "function": {"name": "weather_lookup", "arguments": "{}"},
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
        response = _buffered_sse(payload, "")
        event = json.loads(response.body.decode().split("\n\n")[0].removeprefix("data: "))
        self.assertEqual(
            event["choices"][0]["delta"]["tool_calls"][0]["function"]["name"],
            "weather_lookup",
        )


class AdminSessionAuthorizationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.original_admin_key = runtime.guardrail_admin_key
        self.original_authz_url = runtime.archestra_admin_authz_url
        self.original_origin = runtime.archestra_session_origin
        self.original_client = runtime.admin_auth_http
        runtime.guardrail_admin_key = "recovery-key"
        runtime.archestra_admin_authz_url = (
            "http://archestra:9000/api/identity-providers"
        )
        runtime.archestra_session_origin = "https://192.0.2.10"

    def tearDown(self) -> None:
        runtime.guardrail_admin_key = self.original_admin_key
        runtime.archestra_admin_authz_url = self.original_authz_url
        runtime.archestra_session_origin = self.original_origin
        runtime.admin_auth_http = self.original_client

    @staticmethod
    def request(
        method: str = "GET",
        headers: list[tuple[bytes, bytes]] | None = None,
    ) -> Request:
        return Request(
            {
                "type": "http",
                "method": method,
                "path": "/admin/api/profiles",
                "headers": headers or [],
            }
        )

    async def test_recovery_bearer_remains_available(self) -> None:
        await _require_admin_access(
            self.request(),
            HTTPAuthorizationCredentials(
                scheme="Bearer", credentials="recovery-key"
            ),
        )

    async def test_invalid_bearer_does_not_fall_back_to_session(self) -> None:
        with self.assertRaises(HTTPException) as context:
            await _require_admin_access(
                self.request(headers=[(b"cookie", b"session=valid")]),
                HTTPAuthorizationCredentials(scheme="Bearer", credentials="wrong"),
            )
        self.assertEqual(context.exception.status_code, 401)

    async def test_archestra_admin_permission_allows_session(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.headers["cookie"], "session=valid")
            self.assertNotIn("authorization", request.headers)
            self.assertEqual(request.headers["origin"], "https://192.0.2.10")
            return httpx.Response(200, json=[])

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        runtime.admin_auth_http = client
        try:
            await _require_admin_access(
                self.request(headers=[(b"cookie", b"session=valid")]), None
            )
        finally:
            await client.aclose()

    async def test_restricted_session_is_forbidden(self) -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(403, json={"error": "forbidden"})
            )
        )
        runtime.admin_auth_http = client
        try:
            with self.assertRaises(HTTPException) as context:
                await _require_admin_access(
                    self.request(headers=[(b"cookie", b"session=restricted")]),
                    None,
                )
            self.assertEqual(context.exception.status_code, 403)
        finally:
            await client.aclose()

    async def test_session_mutation_requires_canonical_origin(self) -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=[]))
        )
        runtime.admin_auth_http = client
        try:
            with self.assertRaises(HTTPException) as context:
                await _require_admin_access(
                    self.request(
                        method="POST",
                        headers=[
                            (b"cookie", b"session=valid"),
                            (b"origin", b"https://attacker.example"),
                        ],
                    ),
                    None,
                )
            self.assertEqual(context.exception.status_code, 403)
        finally:
            await client.aclose()

    async def test_session_validator_failure_is_fail_closed(self) -> None:
        async def handler(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("unavailable")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        runtime.admin_auth_http = client
        try:
            with self.assertRaises(HTTPException) as context:
                await _require_admin_access(
                    self.request(headers=[(b"cookie", b"session=valid")]), None
                )
            self.assertEqual(context.exception.status_code, 503)
        finally:
            await client.aclose()


if __name__ == "__main__":
    unittest.main()
