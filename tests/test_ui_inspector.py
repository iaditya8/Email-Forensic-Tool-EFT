"""Comprehensive unit and integration tests for Dual-Pane UI Inspector and HTML Sanitizer."""

from pathlib import Path

import pytest

from eft.models.canonical import (
    CanonicalEmail,
    HeaderDecomposition,
    MIMEPartNode,
    SourceFileInfo,
)
from eft.ui.inspector import EmailInspector
from eft.ui.sanitizer import HTMLSanitizer


def test_html_sanitizer_removes_dangerous_tags():
    malicious_html = """
    <html>
        <head>
            <script>alert('pwned');</script>
            <style>body { background: red; }</style>
            <base href="http://evil.com/">
            <meta http-equiv="refresh" content="0;url=http://evil.com">
        </head>
        <body>
            <p>Normal text</p>
            <iframe src="http://c2.server/payload.exe"></iframe>
            <object data="exploit.swf"></object>
            <embed src="malware.pdf">
            <form action="http://phish.com/steal" method="POST">
                <input type="password" name="pwd">
                <button type="submit">Submit</button>
            </form>
        </body>
    </html>
    """

    sanitized = HTMLSanitizer.sanitize_html(malicious_html)

    assert "<script" not in sanitized
    assert "alert('pwned')" not in sanitized
    assert "<iframe" not in sanitized
    assert "<object" not in sanitized
    assert "<embed" not in sanitized
    assert "<form" not in sanitized
    assert "<input" not in sanitized
    assert "<button" not in sanitized
    assert "<base" not in sanitized
    assert "<meta" not in sanitized
    assert "<p>Normal text</p>" in sanitized


def test_html_sanitizer_removes_event_handlers():
    xss_html = """
    <p onload="stealCookies()" onclick="execute()" onmouseover="track()" onerror="pwn()">
        Click <a href="javascript:alert(1)" onclick="run()">here</a>
    </p>
    """

    sanitized = HTMLSanitizer.sanitize_html(xss_html)

    assert "onload" not in sanitized
    assert "onclick" not in sanitized
    assert "onmouseover" not in sanitized
    assert "onerror" not in sanitized
    assert "javascript:alert(1)" not in sanitized
    assert "#defanged-executable-uri" in sanitized


def test_html_sanitizer_blocks_remote_images_and_preserves_inline():
    html_with_images = """
    <div>
        <img src="http://tracker.adnetwork.com/beacon.gif?user=123">
        <img src="https://c2.server.org/track.png" width="1" height="1">
        <img src="cid:inline-logo.png" alt="Company Logo">
        <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==">
    </div>
    """

    sanitized = HTMLSanitizer.sanitize_html(html_with_images, block_remote_images=True)

    # Remote trackers should be blocked and replaced with badges
    assert "http://tracker.adnetwork.com" not in sanitized
    assert "https://c2.server.org" not in sanitized
    assert "eft-blocked-image" in sanitized
    assert "Remote Image Blocked" in sanitized

    # Inline CID and data:image must be preserved
    assert 'src="cid:inline-logo.png"' in sanitized
    assert 'src="data:image/png;base64,' in sanitized


def test_html_sanitizer_secures_hyperlinks():
    raw_html = '<a href="http://bank-phish.com/login" target="_self">Verify Account</a>'
    sanitized = HTMLSanitizer.sanitize_html(raw_html)

    assert 'target="_blank"' in sanitized
    assert 'rel="noopener noreferrer"' in sanitized
    assert 'data-defanged="hxxp[://]bank-phish[.]com/login"' in sanitized


def test_html_sanitizer_plain_text():
    raw_text = "Hello <world> & 'friends'!"
    escaped = HTMLSanitizer.sanitize_plain_text(raw_text)

    assert "<world>" not in escaped
    assert "&lt;world&gt;" in escaped
    assert "<pre class='eft-plaintext-body'>" in escaped


@pytest.fixture
def sample_canonical_for_ui() -> CanonicalEmail:
    mime_node1 = MIMEPartNode(
        part_index=0,
        part_path="1",
        content_type="text/plain",
        size_bytes=120,
    )
    mime_node2 = MIMEPartNode(
        part_index=1,
        part_path="2",
        content_type="text/html",
        size_bytes=450,
    )
    root_mime = MIMEPartNode(
        part_index=0,
        part_path="1",
        content_type="multipart/alternative",
        is_multipart=True,
        children=[mime_node1, mime_node2],
    )

    decomp = HeaderDecomposition(
        standard_headers={
            "From": "investigator@cyber.gov",
            "Subject": "Evidence Analysis Case 001",
        },
        received_headers=["from mail.sender.com by mx.google.com with ESMTPS id 123"],
        auth_results_headers=["mx.google.com; spf=pass dkim=pass dmarc=pass"],
        dkim_signatures=["v=1; a=rsa-sha256; d=cyber.gov; s=2026"],
        custom_x_headers={"X-Spam-Score": "0.0", "X-Forensic-Source": "EFT"},
    )

    return CanonicalEmail(
        message_id="<case-001@cyber.gov>",
        date="Mon, 19 Sep 2026 15:00:00 +0000",
        subject="Evidence Analysis Case 001",
        from_address="investigator@cyber.gov",
        to_addresses=["analyst@cyber.gov"],
        ordered_headers=[
            ("From", "investigator@cyber.gov"),
            ("To", "analyst@cyber.gov"),
            ("Subject", "Evidence Analysis Case 001"),
            ("Date", "Mon, 19 Sep 2026 15:00:00 +0000"),
            ("X-Forensic-Source", "EFT"),
        ],
        header_decomposition=decomp,
        mime_parts=[root_mime],
        body_plain="Forensic Plaintext Body Content",
        body_html="<p>Forensic <b>HTML</b> Body Content</p>",
        source_file=SourceFileInfo(
            file_path="/evidence/case_001.eml",
            file_name="case_001.eml",
            file_format="eml",
            file_size_bytes=3500,
            hashes={"sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
        ),
    )


def test_email_inspector_html_generation(sample_canonical_for_ui: CanonicalEmail, tmp_path: Path):
    output_html_file = tmp_path / "inspector_dashboard.html"
    html_output = EmailInspector.generate_inspector_html(
        sample_canonical_for_ui, output_path=output_html_file
    )

    assert output_html_file.exists()
    assert len(html_output) > 1000

    # Verify structural components
    assert "EFT Forensic Inspector" in html_output
    assert "Evidence Analysis Case 001" in html_output
    assert "header-search-input" in html_output
    assert "copyRawHeaders()" in html_output
    assert "view-categorized" in html_output
    assert "view-raw" in html_output
    assert "view-mime" in html_output
    assert "multipart/alternative" in html_output


def test_email_inspector_cli_layout(sample_canonical_for_ui: CanonicalEmail):
    layout = EmailInspector.generate_cli_layout(sample_canonical_for_ui)

    assert layout is not None
    child_names = [c.name for c in layout.children]
    assert "header" in child_names
    assert "main" in child_names
    assert "footer" in child_names

    main_child_names = [c.name for c in layout["main"].children]
    assert "left_pane" in main_child_names
    assert "right_pane" in main_child_names
