"""Unit tests for HeaderDecomposer subsystem."""

from __future__ import annotations

from eft.ingestion.header_decomposer import HeaderDecomposer


def test_header_decomposer_categorization():
    ordered_headers = [
        (
            "Received",
            "from mail-out.sender.com (mail-out.sender.com [192.0.2.1]) by mx.google.com with ESMTPS",
        ),
        ("Received", "from internal.corp ([10.0.0.5]) by mail-out.sender.com with ESMTP"),
        (
            "DKIM-Signature",
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d=sender.com; s=202601; h=from:to:subject; bh=xyz; b=abc",
        ),
        (
            "Authentication-Results",
            "mx.google.com; dkim=pass header.i=@sender.com; spf=pass (google.com: domain of sender@sender.com designates 192.0.2.1 as permitted sender)",
        ),
        (
            "Received-SPF",
            "pass (google.com: domain of sender@sender.com designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1;",
        ),
        (
            "ARC-Seal",
            "i=1; a=rsa-sha256; t=1700000000; cv=none; d=google.com; s=arc2026; b=arcseal1",
        ),
        (
            "ARC-Message-Signature",
            "i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc2026; bh=xyz; b=arcsig1",
        ),
        ("ARC-Authentication-Results", "i=1; mx.google.com; dkim=pass; spf=pass"),
        ("X-Originating-IP", "[203.0.113.50]"),
        ("X-Mailer", "ForensicTestClient/1.0"),
        ("X-Spam-Flag", "NO"),
        ("X-Custom-Multi", "Value1"),
        ("X-Custom-Multi", "Value2"),
        ("From", "Analyst <analyst@security.corp>"),
        ("To", "Victim <victim@enterprise.corp>"),
        ("Subject", "Urgent Security Verification"),
        ("Date", "Mon, 19 Sep 2026 14:00:00 +0000"),
        ("Message-ID", "<msg-security-123@security.corp>"),
    ]

    decomp = HeaderDecomposer.decompose(ordered_headers)

    # 1. Verify Received transit hops (order preserved)
    assert len(decomp.received_headers) == 2
    assert "mail-out.sender.com" in decomp.received_headers[0]
    assert "internal.corp" in decomp.received_headers[1]

    # 2. Verify Authentication Results & SPF
    assert len(decomp.auth_results_headers) == 2
    assert "mx.google.com; dkim=pass" in decomp.auth_results_headers[0]
    assert "client-ip=192.0.2.1" in decomp.auth_results_headers[1]

    # 3. Verify DKIM
    assert len(decomp.dkim_signatures) == 1
    assert "d=sender.com" in decomp.dkim_signatures[0]

    # 4. Verify ARC
    assert "arc-seal" in decomp.arc_headers
    assert "arc-message-signature" in decomp.arc_headers
    assert "arc-authentication-results" in decomp.arc_headers
    assert len(decomp.arc_headers["arc-seal"]) == 1

    # 5. Verify Custom X-* Headers
    assert decomp.custom_x_headers["x-originating-ip"] == "[203.0.113.50]"
    assert decomp.custom_x_headers["x-mailer"] == "ForensicTestClient/1.0"
    assert decomp.custom_x_headers["x-spam-flag"] == "NO"
    assert isinstance(decomp.custom_x_headers["x-custom-multi"], list)
    assert decomp.custom_x_headers["x-custom-multi"] == ["Value1", "Value2"]

    # 6. Verify Standard Headers
    assert decomp.standard_headers["from"] == "Analyst <analyst@security.corp>"
    assert decomp.standard_headers["to"] == "Victim <victim@enterprise.corp>"
    assert decomp.standard_headers["subject"] == "Urgent Security Verification"
    assert decomp.standard_headers["date"] == "Mon, 19 Sep 2026 14:00:00 +0000"
    assert decomp.standard_headers["message-id"] == "<msg-security-123@security.corp>"


def test_header_decomposer_empty_list():
    decomp = HeaderDecomposer.decompose([])
    assert decomp.received_headers == []
    assert decomp.auth_results_headers == []
    assert decomp.dkim_signatures == []
    assert decomp.arc_headers == {}
    assert decomp.custom_x_headers == {}
    assert decomp.standard_headers == {}
