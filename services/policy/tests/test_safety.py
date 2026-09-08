import unittest

from app.safety import scan_text, scan_value


class SafetyScannerTests(unittest.TestCase):
    def test_safe_text_passes(self):
        self.assertEqual(scan_text("Summarize the deployment status."), set())

    def test_secret_categories_do_not_return_secret_value(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
        result = scan_text(f"credential={secret}")
        self.assertEqual(result, {"openai_style_key"})
        self.assertNotIn(secret, result)

    def test_nested_payload_is_scanned(self):
        result = scan_value({"messages": [{"content": "SSN 123-45-6789"}]})
        self.assertEqual(result, {"us_ssn"})

    def test_private_key_header_is_blocked(self):
        result = scan_text("-----BEGIN PRIVATE KEY-----")
        self.assertEqual(result, {"private_key"})

    def test_valid_payment_card_is_detected_with_luhn(self):
        self.assertEqual(scan_text("card 4242 4242 4242 4242"), {"payment_card"})

    def test_long_numeric_identifier_is_not_misclassified_as_card(self):
        self.assertEqual(scan_text("order 1234567890123456"), set())

    def test_email_and_phone_are_detected_as_optional_pii_categories(self):
        result = scan_text("Contact alice@example.com or (512) 555-0123")
        self.assertEqual(result, {"email_address", "phone_number"})


if __name__ == "__main__":
    unittest.main()
