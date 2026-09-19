"""Unit and integration tests for URL extraction, defanging, anchor mismatch, and homograph detection."""

import pytest

from eft.analysis.url_analyzer import URLAnalyzer
from eft.models.canonical import CanonicalEmail, URLExtractionReport


@pytest.fixture
def analyzer() -> URLAnalyzer:
    return URLAnalyzer()


def test_defang_and_refang(analyzer: URLAnalyzer) -> None:
    """Validate safe forensic defanging and reversible refanging of URLs."""
    urls = [
        ("https://malicious.evil.com/login.php", "hxxps[://]malicious[.]evil[.]com/login.php"),
        ("http://192.168.1.100:8080/admin", "hxxp[://]192[.]168[.]1[.]100:8080/admin"),
        ("ftp://files.suspicious.net/payload.exe", "fxp[://]files[.]suspicious[.]net/payload.exe"),
        ("sftp://vault.corp.com/dump", "sfxp[://]vault[.]corp[.]com/dump"),
        ("www.phishing-portal.com/auth", "www[.]phishing-portal[.]com/auth"),
    ]

    for raw, expected_defanged in urls:
        defanged = analyzer.defang_url(raw)
        assert defanged == expected_defanged, f"Failed defanging for {raw}"
        # Refang check (standard schemes)
        if raw.startswith(("http://", "https://", "ftp://", "sftp://")):
            refanged = analyzer.refang_url(defanged)
            assert refanged == raw, f"Failed refanging for {defanged}"


def test_anchor_mismatch_detection(analyzer: URLAnalyzer) -> None:
    """Validate detection of deceptive display anchor text pointing to malicious destinations."""
    # 1. Obvious Phishing Mismatch: display says paypal.com, href goes to evil-phish.ru
    mismatch, anchor_dom = analyzer.detect_anchor_mismatch(
        href="http://evil-phish.ru/signin",
        anchor_text="https://www.paypal.com/signin",
    )
    assert mismatch is True
    assert anchor_dom == "paypal.com"

    # 2. Microsoft Brand Mismatch
    mismatch, anchor_dom = analyzer.detect_anchor_mismatch(
        href="http://phish-login-portal.com/oauth",
        anchor_text="login.microsoftonline.com/auth",
    )
    assert mismatch is True
    assert anchor_dom == "microsoftonline.com"

    # 3. Legitimate Subdomain / Same Org Domain (not a mismatch)
    mismatch, _ = analyzer.detect_anchor_mismatch(
        href="https://account.google.com/security",
        anchor_text="https://mail.google.com/inbox",
    )
    assert mismatch is False

    # 4. Generic anchor text (Click Here, Verify Now) -> Not an anchor URL mismatch
    mismatch, _ = analyzer.detect_anchor_mismatch(
        href="http://malicious-site.com/payload",
        anchor_text="Click here to verify your account immediately",
    )
    assert mismatch is False

    # 5. Empty anchor text
    mismatch, _ = analyzer.detect_anchor_mismatch(
        href="http://example.com",
        anchor_text=None,
    )
    assert mismatch is False


def test_homograph_and_punycode_detection(analyzer: URLAnalyzer) -> None:
    """Validate detection of IDN homoglyph attacks using mixed scripts and Punycode."""
    # 1. Cyrillic 'а' (U+0430) in "pаypal.com"
    cyrillic_paypal = "p\u0430ypal.com"
    is_homo, puny, unicode_dom, details = analyzer.detect_homographs(cyrillic_paypal)
    assert is_homo is True
    assert puny is not None and puny.startswith("xn--")
    assert unicode_dom == cyrillic_paypal
    assert any("CYRILLIC" in d for d in details)

    # 2. Punycode direct input (e.g. xn--pple-43d.com -> аpple.com)
    punycode_host = "xn--pple-43d.com"
    is_homo, puny, unicode_dom, details = analyzer.detect_homographs(punycode_host)
    assert is_homo is True
    assert puny == punycode_host
    assert unicode_dom is not None and unicode_dom != punycode_host

    # 3. Legitimate Latin Domain -> No homograph
    is_homo, puny, unicode_dom, details = analyzer.detect_homographs("google.com")
    assert is_homo is False
    assert details == []


def test_ip_host_detection(analyzer: URLAnalyzer) -> None:
    """Validate detection of URLs with raw IP addresses as hosts."""
    # 1. Standard IPv4
    is_ip, detail = analyzer.detect_ip_host("198.51.100.25")
    assert is_ip is True
    assert "Standard IP" in (detail or "")

    # 2. IPv6
    is_ip, detail = analyzer.detect_ip_host("[2001:db8::1]")
    assert is_ip is True

    # 3. Dword IP (e.g. 2130706433 == 127.0.0.1)
    is_ip, detail = analyzer.detect_ip_host("2130706433")
    assert is_ip is True
    assert "Dword IP" in (detail or "")

    # 4. Hex IP (e.g. 0x7f000001 == 127.0.0.1)
    is_ip, detail = analyzer.detect_ip_host("0x7f000001")
    assert is_ip is True
    assert "Hex IP" in (detail or "")

    # 5. Normal Domain
    is_ip, detail = analyzer.detect_ip_host("example.com")
    assert is_ip is False


def test_shorteners_and_suspicious_tld(analyzer: URLAnalyzer) -> None:
    """Validate identification of URL shorteners and high-abuse TLDs."""
    assert analyzer.detect_shorteners("bit.ly") is True
    assert analyzer.detect_shorteners("tinyurl.com") is True
    assert analyzer.detect_shorteners("custom.t.co") is True
    assert analyzer.detect_shorteners("microsoft.com") is False

    assert analyzer.detect_suspicious_tld("malicious-drop.tk") is True
    assert analyzer.detect_suspicious_tld("credential-portal.xyz") is True
    assert analyzer.detect_suspicious_tld("account-update.top") is True
    assert analyzer.detect_suspicious_tld("apple.com") is False


def test_credential_phish_query_analysis(analyzer: URLAnalyzer) -> None:
    """Validate detection of query strings with credential targets or encoded emails."""
    rec = analyzer.analyze_single_url(
        raw_url="https://phish.attacker.com/login?email=victim%40enterprise.com&redirect=https://legit.com",
        anchor_text="Click here to review invoice",
    )
    assert "CREDENTIAL_PHISH_PARAM" in rec.risk_flags
    assert "OPEN_REDIRECT_PARAM" in rec.risk_flags
    assert rec.risk_score >= 40.0


def test_html_and_plaintext_extraction_end_to_end(analyzer: URLAnalyzer) -> None:
    """Validate full end-to-end extraction from a CanonicalEmail containing HTML, plaintext, and headers."""
    html_body = """
    <html>
      <body>
        <p>Dear Customer, please verify your account:</p>
        <a href="http://evil-phish.xyz/login.php?user=victim@corp.com">https://www.paypal.com/signin</a>
        <br/>
        <img src="http://198.51.100.50/tracker.png" alt="Logo"/>
        <form action="http://collector.badsite.top/submit">
          <input type="submit" value="Submit"/>
        </form>
        <p>Or visit: http://bit.ly/suspicious-short-link</p>
      </body>
    </html>
    """

    plain_body = """
    Please check the plain link as well:
    https://p\u0430ypal.com/verify
    """

    email = CanonicalEmail(
        message_id="<test-url-forensics@example.com>",
        body_html=html_body,
        body_plain=plain_body,
        headers={"List-Unsubscribe": "<https://unsubscribe.service.org/optout>"},
    )

    report: URLExtractionReport = analyzer.extract_urls(email)

    assert report.total_urls_found >= 5
    assert email.url_report is report
    assert report.overall_url_risk == "MALICIOUS"

    # Verify specific threat records
    assert report.anchor_mismatches_count >= 1
    assert report.homographs_count >= 1
    assert report.ip_urls_count >= 1
    assert report.shorteners_count >= 1

    # Check anchor mismatch URL
    mismatch_records = [u for u in report.urls if u.is_anchor_mismatch]
    assert len(mismatch_records) > 0
    assert mismatch_records[0].defanged_url.startswith("hxxp[://]evil-phish[.]xyz")
    assert mismatch_records[0].anchor_domain == "paypal.com"

    # Check homograph record
    homo_records = [u for u in report.urls if u.is_idn_homograph]
    assert len(homo_records) > 0
    assert "IDN_HOMOGRAPH_ATTACK" in homo_records[0].risk_flags


def test_edge_cases_and_ignorable_schemes(analyzer: URLAnalyzer) -> None:
    """Validate handling of non-hyperlink schemes, malformed inputs, and empty bodies."""
    html_edge = """
    <html>
      <body>
        <a href="mailto:support@example.com">Email Us</a>
        <a href="tel:+1234567890">Call Us</a>
        <a href="javascript:void(0)">Do Not Click</a>
        <a href="#section1">Top</a>
        <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="/>
      </body>
    </html>
    """
    email = CanonicalEmail(
        message_id="<empty-edge-test@example.com>",
        body_html=html_edge,
    )

    report = analyzer.extract_urls(email)
    # None of the mailto, tel, javascript, data URLs should be extracted as external web URLs
    assert report.total_urls_found == 0
    assert report.overall_url_risk == "CLEAN"

    # Empty email
    empty_email = CanonicalEmail(message_id="<empty@example.com>")
    empty_report = analyzer.extract_urls(empty_email)
    assert empty_report.total_urls_found == 0
    assert empty_report.overall_url_risk == "CLEAN"
