"""Unit tests for MIMETreeDecomposer subsystem."""

from __future__ import annotations

import email
from email import policy

import pytest

from eft.ingestion.eml_parser import EMLParser
from eft.ingestion.mime_decomposer import MIMETreeDecomposer
from eft.models.canonical import SourceFileInfo


@pytest.fixture
def nested_mime_raw() -> bytes:
    # Build deeply nested MIME structure:
    # multipart/mixed
    # ├── multipart/alternative
    # │   ├── text/plain (Quoted-Printable)
    # │   └── text/html (Base64)
    # ├── image/png (inline asset)
    # └── application/pdf (attachment)
    boundary_mixed = "====_Mixed_Boundary_001_===="
    boundary_alt = "====_Alt_Boundary_002_===="

    raw = f"""From: attacker@evil.corp
To: executive@target.corp
Subject: Nested MIME Phishing Attack
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary_mixed}"

--{boundary_mixed}
Content-Type: multipart/alternative; boundary="{boundary_alt}"

--{boundary_alt}
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

Please find the requested update attached.=20
Verify immediately.

--{boundary_alt}
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: base64

PHA+UGxlYXNlIGZpbmQgdGhlIDxiPnJlcXVlc3RlZCB1cGRhdGU8L2I+IGF0dGFjaGVkLjwvcD4=

--{boundary_alt}--

--{boundary_mixed}
Content-Type: image/png; name="logo.png"
Content-Disposition: inline; filename="logo.png"
Content-ID: <logo_cid_001>
Content-Transfer-Encoding: base64

iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==

--{boundary_mixed}
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcTl8uXrp/Og0MTGc...

--{boundary_mixed}--
"""
    return raw.replace("\n", "\r\n").encode("utf-8")


def test_mime_tree_hierarchical_decomposition(nested_mime_raw: bytes):
    msg = email.message_from_bytes(nested_mime_raw, policy=policy.default)
    decomposer = MIMETreeDecomposer()

    flat_nodes, body_artifacts, attachments, plain, html = decomposer.decompose(msg)

    # 1. Verify Nodes Structure
    # Node 1: multipart/mixed (depth 0, path 1)
    # Node 2: multipart/alternative (depth 1, path 1.1)
    # Node 3: text/plain (depth 2, path 1.1.1)
    # Node 4: text/html (depth 2, path 1.1.2)
    # Node 5: image/png (depth 1, path 1.2)
    # Node 6: application/pdf (depth 1, path 1.3)
    assert len(flat_nodes) >= 5

    root = flat_nodes[0]
    assert root.content_type == "multipart/mixed"
    assert root.is_multipart is True
    assert root.depth == 0
    assert root.part_path == "1"

    # Find text/plain and text/html parts
    plain_node = next(n for n in flat_nodes if n.content_type == "text/plain")
    assert plain_node.depth == 2
    assert plain_node.part_path == "1.1.1"
    assert plain_node.content_transfer_encoding == "quoted-printable"

    html_node = next(n for n in flat_nodes if n.content_type == "text/html")
    assert html_node.depth == 2
    assert html_node.part_path == "1.1.2"
    assert html_node.content_transfer_encoding == "base64"

    # 2. Verify Body Artifacts Isolation
    assert len(body_artifacts.plain_bodies) == 1
    assert len(body_artifacts.html_bodies) == 1
    assert "Please find the requested update attached." in body_artifacts.plain_bodies[0].content
    assert "<p>Please find the" in body_artifacts.html_bodies[0].content
    assert body_artifacts.plain_bodies[0].sha256 != ""
    assert body_artifacts.html_bodies[0].sha256 != ""

    # 3. Verify Combined text
    assert plain is not None and "Please find the requested update" in plain
    assert html is not None and "<p>Please find the" in html

    # 4. Verify Attachments
    # logo.png (inline) and invoice.pdf (attachment)
    assert len(attachments) == 2
    logo_att = next(a for a in attachments if a.filename == "logo.png")
    assert logo_att.is_inline is True
    assert logo_att.content_id == "<logo_cid_001>"
    assert logo_att.hashes["sha256"] != ""

    inv_att = next(a for a in attachments if a.filename == "invoice.pdf")
    assert inv_att.is_inline is False
    assert inv_att.content_disposition == "attachment"
    assert inv_att.hashes["sha256"] != ""


def test_eml_parser_end_to_end_mime_and_header_decomposition(nested_mime_raw: bytes):
    parser = EMLParser()
    source_info = SourceFileInfo(
        file_path="nested.eml",
        file_name="nested.eml",
        file_format="eml",
        file_size_bytes=len(nested_mime_raw),
    )

    result = parser.parse(nested_mime_raw, source_info)
    assert len(result) == 1
    canonical = result[0]

    # Verify header decomposition presence
    assert canonical.header_decomposition is not None
    assert canonical.header_decomposition.standard_headers["subject"] == "Nested MIME Phishing Attack"
    assert canonical.header_decomposition.standard_headers["from"] == "attacker@evil.corp"

    # Verify body artifacts presence
    assert canonical.body_artifacts is not None
    assert len(canonical.body_artifacts.plain_bodies) == 1
    assert len(canonical.body_artifacts.html_bodies) == 1

    # Verify MIME parts
    assert len(canonical.mime_parts) >= 5
    assert len(canonical.attachments) == 2
