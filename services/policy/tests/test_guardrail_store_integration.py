import os
import hashlib
import unittest
import uuid

from app.guardrails import (
    AuditEventInput,
    ClientCredentialCreateInput,
    ExternalUsageInput,
    GuardrailAssignmentInput,
    GuardrailProfileInput,
    GuardrailSettings,
    GuardrailStore,
)


DATABASE_URL = os.environ.get("GUARDRAIL_TEST_DATABASE_URL")
if not DATABASE_URL and os.environ.get("GUARDRAIL_RUN_INTEGRATION_TESTS") == "true":
    DATABASE_URL = os.environ.get("GUARDRAIL_DATABASE_URL")


@unittest.skipUnless(DATABASE_URL, "GUARDRAIL_TEST_DATABASE_URL is not set")
class GuardrailStoreIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.store = GuardrailStore(
            DATABASE_URL,
            GuardrailSettings(
                allowed_models=["test-model"],
                allowed_tools=[],
                routing_mode="local_only",
            ),
        )
        await self.store.open()

    async def asyncTearDown(self) -> None:
        await self.store.close()

    async def test_profile_assignment_resolution_and_audit(self) -> None:
        suffix = uuid.uuid4().hex[:10]
        profile_id = f"restricted-{suffix}"
        user_id = f"user-{suffix}"
        profile = await self.store.upsert_profile(
            GuardrailProfileInput(
                id=profile_id,
                name="Restricted user",
                settings=GuardrailSettings(
                    allowed_models=["local-chat"],
                    allow_external=False,
                    max_input_chars=500,
                ),
            )
        )
        self.assertEqual(profile.id, profile_id)

        assignment = await self.store.add_assignment(
            GuardrailAssignmentInput(
                subject_type="user",
                subject_id=user_id,
                profile_id=profile_id,
                priority=500,
            )
        )
        effective = await self.store.effective_policy(user_id, "browser-chat")
        self.assertEqual(effective.profile_id, profile_id)
        self.assertFalse(effective.settings.allow_external)
        self.assertEqual(effective.assignment_id, assignment.id)

        request_id = uuid.uuid4().hex
        await self.store.add_audit_event(
            AuditEventInput(
                request_id=request_id,
                user_id=user_id,
                agent_id="browser-chat",
                profile_id=profile_id,
                stage="route",
                decision="block",
                categories=["external_provider"],
            )
        )
        events = await self.store.list_audit_events(25)
        event = next(item for item in events if item["request_id"] == request_id)
        self.assertEqual(event["categories"], ["external_provider"])

        self.assertTrue(await self.store.delete_assignment(assignment.id))
        self.assertTrue(await self.store.delete_profile(profile_id))

    async def test_external_budget_reservation_is_atomic_and_reconciled(self) -> None:
        suffix = uuid.uuid4().hex[:10]
        request_id = f"budget-{suffix}"
        usage = ExternalUsageInput(
            request_id=request_id,
            user_id=f"user-{suffix}",
            agent_id="managed-chat",
            profile_id="default",
            provider="openai",
            model="test-external",
            prompt_tokens=100,
            completion_tokens=100,
            cost_microusd=900_000,
        )
        self.assertTrue(await self.store.reserve_external_usage(usage, 1_000_000))
        rejected = usage.model_copy(
            update={"request_id": f"budget-rejected-{suffix}", "cost_microusd": 200_000}
        )
        self.assertFalse(await self.store.reserve_external_usage(rejected, 1_000_000))

        await self.store.finalize_external_usage(request_id, 10, 20, 30_000)
        summary = await self.store.external_usage_summary("default", usage.user_id)
        self.assertGreaterEqual(summary["cost_microusd"], 30_000)
        await self.store.release_external_usage(request_id)

    async def test_client_credential_is_hashed_at_rest_attributed_and_revocable(self) -> None:
        credential_id = str(uuid.uuid4())
        plaintext = "gateway_integration_client_key"
        key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
        issued = await self.store.create_client_credential(
            credential_id,
            ClientCredentialCreateInput(
                name="Integration VS Code",
                user_id="integration-user",
                agent_id="vscode",
                groups=["integration-team"],
            ),
            plaintext[:17],
            key_hash,
        )
        self.assertEqual(issued.id, credential_id)
        self.assertEqual(issued.user_id, "integration-user")
        self.assertEqual(issued.groups, ["integration-team"])

        authenticated = await self.store.authenticate_client_credential(key_hash)
        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.agent_id, "vscode")
        self.assertIsNotNone(authenticated.last_used_at)

        revoked = await self.store.revoke_client_credential(credential_id)
        self.assertIsNotNone(revoked)
        self.assertFalse(revoked.enabled)
        self.assertIsNotNone(revoked.revoked_at)
        self.assertIsNone(await self.store.authenticate_client_credential(key_hash))


if __name__ == "__main__":
    unittest.main()
