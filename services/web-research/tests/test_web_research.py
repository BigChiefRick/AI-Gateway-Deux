from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import socket
import unittest
from unittest.mock import patch

from app import server


class UrlSafetyTests(unittest.TestCase):
    def test_normalizes_public_http_urls(self) -> None:
        self.assertEqual(
            server.normalized_url("https://example.com/path?q=1"),
            "https://example.com/path?q=1",
        )

    def test_rejects_unsafe_url_shapes(self) -> None:
        for value in (
            "file:///etc/passwd",
            "http://user:password@example.com/",
            "http://example.com:8080/",
            "http:///missing-host",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                server.normalized_url(value)

    def test_rejects_private_dns_results(self) -> None:
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.0.10", 0))]
        with patch("socket.getaddrinfo", return_value=private):
            with self.assertRaisesRegex(ValueError, "private, loopback"):
                asyncio.run(server.public_addresses("internal.example"))

    def test_accepts_only_global_dns_results(self) -> None:
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        with patch("socket.getaddrinfo", return_value=public):
            self.assertEqual(
                asyncio.run(server.public_addresses("example.com")),
                ["93.184.216.34"],
            )


class ExtractionTests(unittest.TestCase):
    def test_current_query_replaces_a_conflicting_single_year(self) -> None:
        query, adjusted, current_date = server.freshness_adjusted_query(
            "Texas Rangers current win loss record 2025",
            datetime(2026, 8, 11, 17, 0, tzinfo=timezone.utc),
        )
        self.assertTrue(adjusted)
        self.assertEqual(current_date, "2026-08-11")
        self.assertIn("2026", query)
        self.assertNotIn("2025", query)
        self.assertIn("as of 2026-08-11", query)

    def test_historical_query_is_not_rewritten(self) -> None:
        original = "Texas Rangers 2025 final record"
        query, adjusted, current_date = server.freshness_adjusted_query(
            original,
            datetime(2026, 8, 11, 17, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(query, original)
        self.assertFalse(adjusted)
        self.assertEqual(current_date, "")

    def test_comparison_query_preserves_historical_year(self) -> None:
        query, adjusted, current_date = server.freshness_adjusted_query(
            "Compare the current Rangers record versus 2025",
            datetime(2026, 8, 11, 17, 0, tzinfo=timezone.utc),
        )
        self.assertTrue(adjusted)
        self.assertEqual(current_date, "2026-08-11")
        self.assertIn("2025", query)
        self.assertIn("2026", query)

    def test_exposes_only_the_approved_read_only_tools(self) -> None:
        tools = asyncio.run(server.mcp.list_tools())
        self.assertEqual(
            {tool.name for tool in tools},
            {
                "search_web",
                "fetch_webpage",
                "scrape_webpage",
                "get_weather",
                "ocr_document",
                "scan_qr_codes",
            },
        )

    def test_visible_text_removes_active_content(self) -> None:
        soup = server.html_document(
            b"<html><head><title>Title</title><script>steal()</script></head>"
            b"<body><h1>Weather</h1><p>Sunny today</p></body></html>"
        )
        text = server.visible_text(soup, 1000)
        self.assertIn("Weather Sunny today", text)
        self.assertNotIn("steal", text)

    def test_clean_text_caps_untrusted_output(self) -> None:
        self.assertEqual(server.clean_text("  alpha\n beta  ", 10), "alpha beta")
        self.assertEqual(server.clean_text("x" * 50, 12), "x" * 12)


if __name__ == "__main__":
    unittest.main()
