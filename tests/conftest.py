"""Shared test fixtures for Email Forensic Tool test suite."""

import pytest

from eft.ingestion.engine import EmailIngester


@pytest.fixture
def ingester() -> EmailIngester:
    return EmailIngester()


@pytest.fixture
def sample_eml_content() -> bytes:
    return (
        b"From: sender@example.com\r\n"
        b"To: recipient1@example.com, recipient2@example.com\r\n"
        b"Cc: cc@example.com\r\n"
        b"Subject: Forensic Investigation Test\r\n"
        b"Date: Mon, 19 Sep 2026 14:00:00 +0000\r\n"
        b"Message-ID: <msg-12345@example.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"X-Custom-Header: Alpha\r\n"
        b"\r\n"
        b"This is the plaintext body of the test email.\r\n"
    )
