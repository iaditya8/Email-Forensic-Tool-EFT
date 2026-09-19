"""Unit tests for email authentication verification (SPF, DKIM, DMARC, and ARC)."""

from eft.analysis.auth_verifier import AuthenticationVerifier
from eft.models.canonical import CanonicalEmail, HeaderDecomposition


def test_extract_domain_from_address():
    """Test extracting clean domain names from varied email address formats."""
    assert (
        AuthenticationVerifier.extract_domain_from_address("User <user@example.com>")
        == "example.com"
    )
    assert (
        AuthenticationVerifier.extract_domain_from_address("noreply@sub.domain.co.uk")
        == "sub.domain.co.uk"
    )
    assert (
        AuthenticationVerifier.extract_domain_from_address("<security@paypal.com>") == "paypal.com"
    )
    assert (
        AuthenticationVerifier.extract_domain_from_address("plain_domain.org") == "plain_domain.org"
    )
    assert AuthenticationVerifier.extract_domain_from_address("") == ""
    assert AuthenticationVerifier.extract_domain_from_address(None) == ""


def test_check_domain_alignment_strict_and_relaxed():
    """Test RFC 7489 identifier alignment matching rules."""
    # 1. Exact match (Passes both strict and relaxed)
    assert (
        AuthenticationVerifier.check_domain_alignment("example.com", "example.com", mode="strict")
        is True
    )
    assert (
        AuthenticationVerifier.check_domain_alignment("example.com", "example.com", mode="relaxed")
        is True
    )

    # 2. Subdomain alignment (Fails strict, passes relaxed)
    assert (
        AuthenticationVerifier.check_domain_alignment(
            "sub.example.com", "example.com", mode="strict"
        )
        is False
    )
    assert (
        AuthenticationVerifier.check_domain_alignment(
            "sub.example.com", "example.com", mode="relaxed"
        )
        is True
    )
    assert (
        AuthenticationVerifier.check_domain_alignment(
            "mail.sub.example.co.uk", "example.co.uk", mode="relaxed"
        )
        is True
    )

    # 3. Cross-domain mismatch (Fails both)
    assert (
        AuthenticationVerifier.check_domain_alignment("paypal.com", "evil-phish.com", mode="strict")
        is False
    )
    assert (
        AuthenticationVerifier.check_domain_alignment(
            "paypal.com", "evil-phish.com", mode="relaxed"
        )
        is False
    )


def test_parse_dkim_signature_header():
    """Test decomposing a raw DKIM-Signature header into parameters."""
    header = (
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d=paypal.com; s=20230601; "
        "t=1685600000; bh=abc123456=; b=xyz987654=; h=from:to:subject:date"
    )

    artifact = AuthenticationVerifier.parse_dkim_signature_header(header)

    assert artifact.domain == "paypal.com"
    assert artifact.selector == "20230601"
    assert artifact.algorithm == "rsa-sha256"
    assert artifact.canonicalization == "relaxed/relaxed"
    assert artifact.body_hash == "abc123456="
    assert artifact.signature_data == "xyz987654="
    assert artifact.signed_headers == ["from", "to", "subject", "date"]
    assert artifact.timestamp_signed is not None


def test_auth_results_parsing_perfect_pass():
    """Test parsing and synthesizing results for an email passing SPF, DKIM, and DMARC."""
    auth_header = (
        "mx.google.com; "
        "dkim=pass header.i=@github.com header.s=s20210517 header.b=abc; "
        "spf=pass (google.com: domain of noreply@github.com designates 192.30.252.204 as permitted sender) "
        "smtp.mailfrom=noreply@github.com; "
        "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com; "
        "arc=pass"
    )

    email = CanonicalEmail(
        from_address="GitHub <noreply@github.com>",
        return_path="noreply@github.com",
        header_decomposition=HeaderDecomposition(
            auth_results_headers=[auth_header],
        ),
    )

    report = AuthenticationVerifier.verify_email(email)

    assert report.overall_verdict == "PASS"
    assert report.spf is not None
    assert report.spf.status == "pass"
    assert report.spf.is_aligned is True
    assert report.spf.sender_ip == "192.30.252.204"

    assert len(report.dkim_signatures) > 0
    assert report.dkim_signatures[0].status == "pass"
    assert report.dkim_signatures[0].is_aligned is True

    assert report.dmarc is not None
    assert report.dmarc.status == "pass"
    assert report.dmarc.spf_alignment is True
    assert report.dmarc.dkim_alignment is True

    assert report.arc is not None
    assert report.arc.is_valid is True
    assert "DMARC_PASSED" in report.authentication_flags


def test_spoofing_attack_dmarc_fail():
    """Test detection and critical flagging of a spoofed email failing DMARC."""
    auth_header = (
        "mx.victim.com; "
        "spf=fail (victim.com: domain of evil@attacker.com does not designate 185.220.101.5 as permitted sender) "
        "smtp.mailfrom=evil@attacker.com; "
        "dkim=fail header.d=attacker.com header.s=default; "
        "dmarc=fail (p=REJECT dis=REJECT) header.from=paypal.com"
    )

    email = CanonicalEmail(
        from_address="PayPal Security <security@paypal.com>",
        return_path="evil@attacker.com",
        header_decomposition=HeaderDecomposition(
            auth_results_headers=[auth_header],
        ),
    )

    report = AuthenticationVerifier.verify_email(email)

    assert report.overall_verdict == "FAIL"
    assert report.dmarc is not None
    assert report.dmarc.status == "fail"
    assert "SPOOFING_CRITICAL_DMARC_FAILED" in report.authentication_flags
    assert "SPF_HARD_FAIL" in report.authentication_flags


def test_relaxed_subdomain_alignment_pass():
    """Test that DMARC relaxed alignment passes for subdomain sender matching org domain."""
    auth_header = (
        "mx.victim.com; "
        "spf=pass (victim.com: domain of bounce@netflix.com designates 198.51.100.1) "
        "smtp.mailfrom=bounce@netflix.com; "
        "dkim=pass header.d=netflix.com header.s=s1; "
        "dmarc=pass (p=REJECT) header.from=sub.netflix.com"
    )

    email = CanonicalEmail(
        from_address="Netflix Updates <info@sub.netflix.com>",
        return_path="bounce@netflix.com",
        header_decomposition=HeaderDecomposition(
            auth_results_headers=[auth_header],
        ),
    )

    report = AuthenticationVerifier.verify_email(email)

    assert report.overall_verdict == "PASS"
    assert report.spf is not None
    assert report.spf.is_aligned is True  # relaxed org domain match
    assert report.dkim_signatures[0].is_aligned is True


def test_no_auth_headers():
    """Test handling of email without any authentication headers."""
    email = CanonicalEmail(
        from_address="unknown@anonymous.local",
    )

    report = AuthenticationVerifier.verify_email(email)

    assert report.overall_verdict == "INSUFFICIENT_DATA"
    assert "NO_AUTH_HEADERS_FOUND" in report.authentication_flags
