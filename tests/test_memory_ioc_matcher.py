"""Unit tests for MemoryIoCMatcher and memory IoC triage models."""

from pathlib import Path

import pytest

from eft.analysis.memory_analyzer import MemoryArtifactAnalyzer
from eft.analysis.memory_ioc_matcher import MemoryIoCMatcher
from eft.models.memory_forensics import (
    ExtractedStringItem,
    MemoryIoCType,
    StringEncoding,
)


@pytest.fixture
def ioc_matcher() -> MemoryIoCMatcher:
    """Provide a configured MemoryIoCMatcher instance."""
    return MemoryIoCMatcher()


def test_scan_string_ipv4_and_geoip(ioc_matcher: MemoryIoCMatcher) -> None:
    """Verify IPv4 detection, octet boundary validation, private flag, and Tor/VPN enrichment."""
    # 8.8.8.8 (US), 185.220.101.5 (Tor Exit), 192.168.1.1 (Private), 999.1.2.3 (Invalid)
    text = (
        "Connecting to DNS 8.8.8.8 and Tor proxy 185.220.101.5 from internal gateway 192.168.1.1 "
        "ignoring invalid 999.1.2.3"
    )
    item = ExtractedStringItem(
        offset=100,
        encoding=StringEncoding.ASCII,
        value=text,
        length=len(text),
    )

    matches = ioc_matcher.scan_string_item(item)
    ipv4_matches = [m for m in matches if m.ioc_type == MemoryIoCType.IPV4]

    assert len(ipv4_matches) == 3
    values = {m.value for m in ipv4_matches}
    assert "8.8.8.8" in values
    assert "185.220.101.5" in values
    assert "192.168.1.1" in values
    assert "999.1.2.3" not in values

    tor_match = next(m for m in ipv4_matches if m.value == "185.220.101.5")
    assert tor_match.is_known_malicious is True
    assert tor_match.enrichment.get("is_tor") is True
    assert tor_match.risk_score >= 80

    private_match = next(m for m in ipv4_matches if m.value == "192.168.1.1")
    assert private_match.enrichment.get("is_private") is True
    assert private_match.risk_score == 10


def test_scan_string_ipv6(ioc_matcher: MemoryIoCMatcher) -> None:
    """Verify IPv6 address extraction."""
    text = "Server listening on 2001:0db8:85a3:0000:0000:8a2e:0370:7334 port 443"
    item = ExtractedStringItem(
        offset=0,
        encoding=StringEncoding.ASCII,
        value=text,
        length=len(text),
    )
    matches = ioc_matcher.scan_string_item(item)
    ipv6 = [m for m in matches if m.ioc_type == MemoryIoCType.IPV6]
    assert len(ipv6) == 1
    assert ipv6[0].value == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"


def test_scan_string_urls_and_emails(ioc_matcher: MemoryIoCMatcher) -> None:
    """Verify URL and email address pattern matching and punctuation stripping."""
    text = (
        "Report bugs to secops-team@enterprise-defense.com. "
        "Exfiltration beacon reached https://c2.darknet-nexus.org/api/v2/drop?id=99."
    )
    item = ExtractedStringItem(
        offset=50,
        encoding=StringEncoding.ASCII,
        value=text,
        length=len(text),
    )
    matches = ioc_matcher.scan_string_item(item)

    urls = [m for m in matches if m.ioc_type == MemoryIoCType.URL]
    emails = [m for m in matches if m.ioc_type == MemoryIoCType.EMAIL]

    assert len(urls) == 1
    assert urls[0].value == "https://c2.darknet-nexus.org/api/v2/drop?id=99"

    assert len(emails) == 1
    assert emails[0].value == "secops-team@enterprise-defense.com"


def test_scan_string_crypto_wallets(ioc_matcher: MemoryIoCMatcher) -> None:
    """Verify Bitcoin Legacy/Bech32 and Ethereum cryptocurrency wallet address detection."""
    text = (
        "Send 0.5 BTC ransom to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or SegWit "
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq or ETH 0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
    )
    item = ExtractedStringItem(
        offset=200,
        encoding=StringEncoding.ASCII,
        value=text,
        length=len(text),
    )
    matches = ioc_matcher.scan_string_item(item)

    btc_matches = [m for m in matches if m.ioc_type == MemoryIoCType.CRYPTO_WALLET_BTC]
    eth_matches = [m for m in matches if m.ioc_type == MemoryIoCType.CRYPTO_WALLET_ETH]

    assert len(btc_matches) == 2
    btc_addrs = {m.value for m in btc_matches}
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in btc_addrs
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in btc_addrs

    assert len(eth_matches) == 1
    assert eth_matches[0].value == "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"


def test_scan_string_jwt_tokens(ioc_matcher: MemoryIoCMatcher) -> None:
    """Verify JWT token pattern extraction and payload claims parsing."""
    # Dummy valid JWT (header: {"alg":"HS256","typ":"JWT"}, payload: {"sub":"admin","aud":"api"})
    # eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImFwaSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
    jwt_str = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImFwaSJ9."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    text = f"Bearer {jwt_str} stored in memory cache"
    item = ExtractedStringItem(
        offset=10,
        encoding=StringEncoding.ASCII,
        value=text,
        length=len(text),
    )
    matches = ioc_matcher.scan_string_item(item)
    jwts = [m for m in matches if m.ioc_type == MemoryIoCType.JWT_TOKEN]

    assert len(jwts) == 1
    assert jwts[0].value == jwt_str
    assert jwts[0].enrichment.get("parsed_claims", {}).get("sub") == "admin"


def test_scan_string_private_keys(ioc_matcher: MemoryIoCMatcher) -> None:
    """Verify PEM Private Key detection."""
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y1+..."
    item = ExtractedStringItem(
        offset=500,
        encoding=StringEncoding.ASCII,
        value=text,
        length=len(text),
    )
    matches = ioc_matcher.scan_string_item(item)
    keys = [m for m in matches if m.ioc_type == MemoryIoCType.PRIVATE_KEY]

    assert len(keys) == 1
    assert "BEGIN RSA PRIVATE KEY" in keys[0].value
    assert keys[0].risk_score >= 90


def test_scan_string_base64_payloads(ioc_matcher: MemoryIoCMatcher) -> None:
    """Verify Base64 MZ executable headers and encoded PowerShell cradles."""
    mz_b64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAA"
    ps_cmd = "powershell.exe -encodedCommand JABzID0AIgBjDJ..."
    text = f"Payload: {mz_b64} and execution: {ps_cmd}"

    item = ExtractedStringItem(
        offset=1000,
        encoding=StringEncoding.ASCII,
        value=text,
        length=len(text),
    )
    matches = ioc_matcher.scan_string_item(item)
    payloads = [m for m in matches if m.ioc_type == MemoryIoCType.BASE64_PAYLOAD]

    assert len(payloads) >= 2


def test_scan_string_malicious_hashes(ioc_matcher: MemoryIoCMatcher) -> None:
    """Verify correlation against threat intelligence hash catalogues."""
    # 44d88612fea8a8f36de82e1278abb02f is in default known hashes
    known_md5 = "44d88612fea8a8f36de82e1278abb02f"
    custom_sha256 = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"

    text = f"Hash match 1: {known_md5}, Hash match 2: {custom_sha256}, benign hash: 00000000000000000000000000000000"
    item = ExtractedStringItem(
        offset=20,
        encoding=StringEncoding.ASCII,
        value=text,
        length=len(text),
    )

    custom_matcher = MemoryIoCMatcher(custom_known_hashes=[custom_sha256])
    matches = custom_matcher.scan_string_item(item)
    hash_matches = [m for m in matches if m.ioc_type == MemoryIoCType.KNOWN_MALICIOUS_HASH]

    assert len(hash_matches) == 2
    matched_vals = {m.value for m in hash_matches}
    assert known_md5 in matched_vals
    assert custom_sha256 in matched_vals
    assert "00000000000000000000000000000000" not in matched_vals


def test_scan_stream_full_report(tmp_path: Path) -> None:
    """Verify end-to-end memory dump file streaming and report synthesis."""
    dump_file = tmp_path / "memory_threat.dmp"
    raw_content = (
        b"\x00" * 32
        + b"MALWARE_HOST: https://eviltrojan.cc/gate.php\x00\x00"
        + b"C2_IPV4: 185.220.101.5\x00\x00"
        + b"-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI...\x00\x00"
        + "BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".encode("utf-16le")
        + b"\x00" * 64
    )
    dump_file.write_bytes(raw_content)

    matcher = MemoryIoCMatcher(memory_analyzer=MemoryArtifactAnalyzer(default_chunk_size=128))
    report = matcher.scan_stream(dump_file)

    assert report.evidence_path == str(dump_file)
    assert report.total_patterns_matched >= 4
    assert report.threat_level in {"HIGH", "CRITICAL"}
    assert len(report.high_risk_findings) >= 2
    assert "URL" in report.matches_by_type
    assert "IPV4" in report.matches_by_type
    assert "PRIVATE_KEY" in report.matches_by_type
