import unittest

from pydantic import ValidationError

from app.admin_ui import ADMIN_HTML
from app.guardrails import (
    GuardrailConfigurationImport,
    GuardrailProfileInput,
    GuardrailSettings,
)


class GuardrailModelTests(unittest.TestCase):
    def test_admin_console_uses_structured_guardrail_controls(self) -> None:
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
            'id="external-input-price"',
            'id="external-output-price"',
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
        ):
            self.assertIn(control, ADMIN_HTML)
        self.assertIn("email_address", ADMIN_HTML)
        self.assertIn("phone_number", ADMIN_HTML)
        self.assertIn("loadDirectory()", ADMIN_HTML)
        self.assertNotIn("Enforced settings (JSON)", ADMIN_HTML)

    def test_default_policy_blocks_sensitive_categories_and_allows_managed_tools(self) -> None:
        settings = GuardrailSettings()
        self.assertIn("private_key", settings.input_block_categories)
        self.assertIn("payment_card", settings.output_block_categories)
        self.assertEqual(settings.allowed_tools, ["search_web", "fetch_url"])
        self.assertFalse(settings.allow_external)
        self.assertEqual(settings.routing_mode, "local_only")
        self.assertEqual(settings.external_monthly_budget_usd, 0)
        self.assertTrue(settings.memory_read)
        self.assertTrue(settings.memory_write)

    def test_policy_lists_are_cleaned_and_deduplicated(self) -> None:
        settings = GuardrailSettings(
            allowed_tools=["weather_lookup", " weather_lookup ", "search_web", ""],
            allowed_models=["auto-chat", "auto-chat"],
        )
        self.assertEqual(settings.allowed_tools, ["weather_lookup", "search_web"])
        self.assertEqual(settings.allowed_models, ["auto-chat"])

    def test_profile_id_rejects_unstable_or_unsafe_names(self) -> None:
        with self.assertRaises(ValidationError):
            GuardrailProfileInput(id="Finance Users!", name="Finance")

    def test_limits_are_bounded(self) -> None:
        with self.assertRaises(ValidationError):
            GuardrailSettings(max_input_chars=0)
        with self.assertRaises(ValidationError):
            GuardrailSettings(external_max_completion_tokens=99_999)

    def test_email_and_phone_detection_are_opt_in_by_default(self) -> None:
        settings = GuardrailSettings()
        self.assertNotIn("email_address", settings.input_block_categories)
        self.assertNotIn("phone_number", settings.input_block_categories)

    def test_portable_configuration_requires_safe_complete_references(self) -> None:
        valid = {
            "schema_version": 1,
            "service_version": "0.5.6",
            "profiles": [
                {
                    "id": "default",
                    "name": "Default",
                    "enabled": True,
                    "settings": {},
                },
                {
                    "id": "managed",
                    "name": "Managed",
                    "enabled": True,
                    "settings": {"allowed_models": ["granite4.1:3b"]},
                },
            ],
            "assignments": [
                {
                    "subject_type": "agent",
                    "subject_id": "managed-chat",
                    "profile_id": "managed",
                    "priority": 100,
                }
            ],
        }
        parsed = GuardrailConfigurationImport.model_validate(valid)
        self.assertEqual(parsed.assignments[0].profile_id, "managed")

        invalid = {**valid, "profiles": valid["profiles"][:1]}
        with self.assertRaises(ValidationError):
            GuardrailConfigurationImport.model_validate(invalid)

        unexpected = {**valid, "credential": "must-not-be-accepted"}
        with self.assertRaises(ValidationError):
            GuardrailConfigurationImport.model_validate(unexpected)


if __name__ == "__main__":
    unittest.main()
