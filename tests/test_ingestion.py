"""Comprehensive unit and integration tests for the Email Ingestion Engine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from eft.core.exceptions import (
    CorruptFileError,
    EvidenceTamperedException,
    UnsupportedFormatError,
)
from eft.core.integrity import compute_bytes_hashes, compute_file_hashes
from eft.ingestion.base import BaseEmailParser
from eft.ingestion.engine import OLE_MAGIC_HEADER, EmailIngester
from eft.ingestion.mbox_parser import MBOXParser
from eft.models.canonical import CanonicalEmail, SourceFileInfo


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


@pytest.fixture
def sample_multipart_eml() -> bytes:
    boundary = "----=_Part_123_456"
    return (
        f"From: alert@security.corp\r\n"
        f"To: analyst@security.corp\r\n"
        f"Subject: Security Incident Notice\r\n"
        f"MIME-Version: 1.0\r\n"
        f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n'
        f"\r\n"
        f"--{boundary}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"Plain text incident summary.\r\n"
        f"--{boundary}\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"\r\n"
        f"<p>HTML incident summary with <b>alert</b>.</p>\r\n"
        f"--{boundary}\r\n"
        f"Content-Type: application/pdf; name=\"report.pdf\"\r\n"
        f"Content-Disposition: attachment; filename=\"report.pdf\"\r\n"
        f"Content-Transfer-Encoding: base64\r\n"
        f"\r\n"
        f"JVBERi0xLjQKJcTl8uXr...\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")


@pytest.fixture
def sample_mbox_content() -> bytes:
    msg1 = (
        "From MAILER-DAEMON Mon Sep 19 14:00:00 2026\n"
        "From: user1@example.com\n"
        "To: dest@example.com\n"
        "Subject: Mbox Message 1\n"
        "\n"
        "First message body\n\n"
    )
    msg2 = (
        "From MAILER-DAEMON Mon Sep 19 14:05:00 2026\n"
        "From: user2@example.com\n"
        "To: dest@example.com\n"
        "Subject: Mbox Message 2\n"
        "\n"
        "Second message body\n\n"
    )
    return (msg1 + msg2).encode("utf-8")


# ---------------------------------------------------------------------------
# Test EML Parsing
# ---------------------------------------------------------------------------


def test_eml_single_part_ingestion(tmp_path: Path, ingester: EmailIngester, sample_eml_content: bytes):
    eml_file = tmp_path / "test_sample.eml"
    eml_file.write_bytes(sample_eml_content)

    result = ingester.ingest_file(eml_file)

    assert result.success is True
    assert result.total_messages == 1
    assert result.tamper_verified is True

    msg = result.messages[0]
    assert msg.subject == "Forensic Investigation Test"
    assert msg.from_address == "sender@example.com"
    assert msg.to_addresses == ["recipient1@example.com", "recipient2@example.com"]
    assert msg.cc_addresses == ["cc@example.com"]
    assert msg.message_id == "<msg-12345@example.com>"
    assert msg.body_plain is not None
    assert "This is the plaintext body" in msg.body_plain
    assert msg.headers.get("x-custom-header") == "Alpha"
    assert len(msg.ordered_headers) >= 7

    # Verify source file integrity info
    assert msg.source_file is not None
    assert msg.source_file.file_format == "eml"
    assert msg.source_file.file_size_bytes == len(sample_eml_content)
    assert "sha256" in msg.source_file.hashes


def test_eml_multipart_with_attachment(tmp_path: Path, ingester: EmailIngester, sample_multipart_eml: bytes):
    eml_file = tmp_path / "incident.eml"
    eml_file.write_bytes(sample_multipart_eml)

    result = ingester.ingest_file(eml_file)

    assert result.success is True
    assert result.total_messages == 1
    msg = result.messages[0]

    assert msg.body_plain == "Plain text incident summary."
    assert "<p>HTML incident summary" in (msg.body_html or "")
    assert len(msg.attachments) == 1

    att = msg.attachments[0]
    assert att.filename == "report.pdf"
    assert att.content_type == "application/pdf"
    assert att.size_bytes > 0
    assert "sha256" in att.hashes
    assert "md5" in att.hashes
    assert "sha1" in att.hashes

    assert len(msg.mime_parts) >= 3


def test_eml_latin1_encoding_fallback(tmp_path: Path, ingester: EmailIngester):
    latin1_data = (
        b"From: latin@example.com\r\n"
        b"To: target@example.com\r\n"
        b"Subject: Latin1 Test: \xe9\xe0\xfc\r\n"
        b"Content-Type: text/plain; charset=iso-8859-1\r\n"
        b"\r\n"
        b"Caract\xe8res sp\xe9ciaux: \xe9, \xe8, \xe0\r\n"
    )
    eml_file = tmp_path / "latin1.eml"
    eml_file.write_bytes(latin1_data)

    result = ingester.ingest_file(eml_file)
    assert result.success is True
    msg = result.messages[0]
    assert "Caractères spéciaux" in (msg.body_plain or "")


# ---------------------------------------------------------------------------
# Test MBOX Parsing
# ---------------------------------------------------------------------------


def test_mbox_multi_message_ingestion(tmp_path: Path, ingester: EmailIngester, sample_mbox_content: bytes):
    mbox_file = tmp_path / "archive.mbox"
    mbox_file.write_bytes(sample_mbox_content)

    result = ingester.ingest_file(mbox_file)

    assert result.success is True
    assert result.total_messages == 2
    assert len(result.messages) == 2

    assert result.messages[0].subject == "Mbox Message 1"
    assert result.messages[0].from_address == "user1@example.com"
    assert result.messages[0].body_plain == "First message body"

    assert result.messages[1].subject == "Mbox Message 2"
    assert result.messages[1].from_address == "user2@example.com"
    assert result.messages[1].body_plain == "Second message body"


def test_mbox_empty_file(tmp_path: Path):
    empty_mbox = tmp_path / "empty.mbox"
    empty_mbox.write_bytes(b"   \n  \n")
    parser = MBOXParser()
    source_info = SourceFileInfo(
        file_path=str(empty_mbox),
        file_name="empty.mbox",
        file_format="mbox",
        file_size_bytes=empty_mbox.stat().st_size,
    )
    with pytest.raises(CorruptFileError):
        parser.parse(empty_mbox, source_info)


# ---------------------------------------------------------------------------
# Test MSG Parsing & Mock Tests
# ---------------------------------------------------------------------------


def test_msg_parser_with_mock_and_attachments(tmp_path: Path, ingester: EmailIngester):
    msg_file = tmp_path / "sample.msg"
    msg_file.write_bytes(OLE_MAGIC_HEADER + b"\x00" * 504)

    mock_att = MagicMock()
    mock_att.longFilename = "invoice.pdf"
    mock_att.shortFilename = None
    mock_att.name = None
    mock_att.data = b"%PDF-1.4 Mock Invoice Data"
    mock_att.mimetype = "application/pdf"
    mock_att.cid = "cid_inv_1"

    mock_msg_obj = type("MockMsg", (), {
        "subject": "Outlook Invoice Attached",
        "sender": "accounts@enterprise.corp",
        "to": "billing@customer.com",
        "cc": "audit@enterprise.corp",
        "bcc": "hidden@enterprise.corp",
        "date": "2026-09-19 14:00:00",
        "messageId": "<msg-invoice-456@corp>",
        "replyTo": "accounts-reply@enterprise.corp",
        "body": "Please review invoice.",
        "htmlBody": "<p>Please review invoice.</p>",
        "rtfBody": b"{\\rtf1\\ansi Please review invoice.}",
        "header": "From: accounts@enterprise.corp\nTo: billing@customer.com\nSubject: Invoice\n",
        "attachments": [mock_att],
        "close": lambda self: None,
    })()

    with patch("extract_msg.openMsg", return_value=mock_msg_obj):
        result = ingester.ingest_file(msg_file)

        assert result.success is True
        assert result.total_messages == 1
        msg = result.messages[0]
        assert msg.subject == "Outlook Invoice Attached"
        assert msg.from_address == "accounts@enterprise.corp"
        assert msg.to_addresses == ["billing@customer.com"]
        assert msg.cc_addresses == ["audit@enterprise.corp"]
        assert msg.bcc_addresses == ["hidden@enterprise.corp"]
        assert msg.body_plain == "Please review invoice."
        assert msg.body_html == "<p>Please review invoice.</p>"
        assert msg.body_rtf is not None
        assert len(msg.attachments) == 1
        assert msg.attachments[0].filename == "invoice.pdf"
        assert msg.attachments[0].content_type == "application/pdf"
        assert msg.attachments[0].is_inline is True
        assert "sha256" in msg.attachments[0].hashes


def test_msg_parser_corrupt_file(tmp_path: Path, ingester: EmailIngester):
    corrupt_msg = tmp_path / "corrupt.msg"
    corrupt_msg.write_bytes(b"INVALID_OLE_DATA_HEADER_BYTES")

    with pytest.raises(CorruptFileError):
        ingester.ingest_file(corrupt_msg)


# ---------------------------------------------------------------------------
# Test Immutability & Tamper Detection
# ---------------------------------------------------------------------------


def test_tamper_detection_raises_exception(tmp_path: Path, ingester: EmailIngester, sample_eml_content: bytes):
    eml_file = tmp_path / "tamper_target.eml"
    eml_file.write_bytes(sample_eml_content)

    class MaliciousTamperingParser(BaseEmailParser):
        def parse(self, file_path_or_data, source_info):
            # Simulate unauthorized in-place file mutation during parsing
            with open(file_path_or_data, "ab") as f:
                f.write(b"\nTAMPERED_INJECTED_BYTES")
            return [CanonicalEmail(subject="Tampered")]

    ingester.register_parser("eml", MaliciousTamperingParser())

    with pytest.raises(EvidenceTamperedException) as exc_info:
        ingester.ingest_file(eml_file)

    assert "Evidence integrity violation" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test Format Auto-Detection (Extensionless Files)
# ---------------------------------------------------------------------------


def test_auto_detection_eml_without_extension(tmp_path: Path, ingester: EmailIngester, sample_eml_content: bytes):
    no_ext = tmp_path / "evidence_eml_no_ext"
    no_ext.write_bytes(sample_eml_content)

    result = ingester.ingest_file(no_ext)
    assert result.success is True
    assert result.source_file.file_format == "eml"


def test_auto_detection_msg_without_extension(tmp_path: Path, ingester: EmailIngester):
    no_ext = tmp_path / "evidence_msg_no_ext"
    no_ext.write_bytes(OLE_MAGIC_HEADER + b"\x00" * 504)

    mock_msg_obj = type("MockMsg", (), {
        "subject": "Detected MSG",
        "sender": "sender@test.com",
        "to": "to@test.com",
        "cc": None,
        "bcc": None,
        "date": None,
        "messageId": None,
        "replyTo": None,
        "body": "Detected",
        "htmlBody": None,
        "rtfBody": None,
        "header": None,
        "attachments": [],
        "close": lambda self: None,
    })()

    with patch("extract_msg.openMsg", return_value=mock_msg_obj):
        result = ingester.ingest_file(no_ext)
        assert result.success is True
        assert result.source_file.file_format == "msg"


def test_auto_detection_mbox_without_extension(tmp_path: Path, ingester: EmailIngester, sample_mbox_content: bytes):
    no_ext = tmp_path / "evidence_mbox_no_ext"
    no_ext.write_bytes(sample_mbox_content)

    result = ingester.ingest_file(no_ext)
    assert result.success is True
    assert result.source_file.file_format == "mbox"
    assert result.total_messages == 2


# ---------------------------------------------------------------------------
# Test Edge Cases, In-Memory Streams, and Error Handling
# ---------------------------------------------------------------------------


def test_ingest_bytes_in_memory(ingester: EmailIngester, sample_eml_content: bytes):
    result = ingester.ingest_bytes(sample_eml_content, file_name="stream.eml")
    assert result.success is True
    assert result.total_messages == 1
    assert result.messages[0].subject == "Forensic Investigation Test"
    assert result.source_file.file_path == "<memory>"


def test_empty_file_handling(tmp_path: Path, ingester: EmailIngester):
    empty_file = tmp_path / "empty.eml"
    empty_file.write_bytes(b"")

    with pytest.raises(CorruptFileError) as exc_info:
        ingester.ingest_file(empty_file)
    assert "empty" in str(exc_info.value).lower()


def test_empty_bytes_buffer(ingester: EmailIngester):
    with pytest.raises(CorruptFileError):
        ingester.ingest_bytes(b"")


def test_nonexistent_file_handling(ingester: EmailIngester):
    with pytest.raises(FileNotFoundError):
        ingester.ingest_file("nonexistent_email_path.eml")


def test_unsupported_format_rejection(tmp_path: Path, ingester: EmailIngester):
    dummy_bin = tmp_path / "unknown.xyz"
    dummy_bin.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07")

    with pytest.raises(UnsupportedFormatError):
        ingester.ingest_file(dummy_bin)


def test_cryptographic_hashing_utilities(tmp_path: Path, sample_eml_content: bytes):
    test_file = tmp_path / "hash_check.eml"
    test_file.write_bytes(sample_eml_content)

    file_hashes = compute_file_hashes(test_file)
    byte_hashes = compute_bytes_hashes(sample_eml_content)

    assert file_hashes == byte_hashes
    assert len(file_hashes["md5"]) == 32
    assert len(file_hashes["sha1"]) == 40
    assert len(file_hashes["sha256"]) == 64
