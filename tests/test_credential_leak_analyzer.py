"""Unit tests for Cleartext Credential & High-Risk Protocol forensics analyzer."""

import base64
import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

from eft.analysis.credential_leak_analyzer import CredentialLeakAnalyzer
from eft.models.credential_leak import (
    CleartextProtocol,
    SecretType,
)
from eft.models.pcap import (
    AppProtocol,
    HTTPRequestInfo,
    HTTPResponseInfo,
    PacketRecord,
    TransportProtocol,
)


@pytest.fixture
def analyzer() -> CredentialLeakAnalyzer:
    """Fixture providing an instance of CredentialLeakAnalyzer."""
    return CredentialLeakAnalyzer()


# -----------------------------------------------------------------------------
# 1. Defanging & Masking Tests
# -----------------------------------------------------------------------------


def test_defang_secret(analyzer: CredentialLeakAnalyzer) -> None:
    """Test safe defanging and SHA-256 fingerprinting for various secret types."""
    # Short password
    short_sec = analyzer.defang_secret("pwd", SecretType.PASSWORD)
    assert short_sec.masked_value == "***"
    assert len(short_sec.sha256_hash) == 64

    # Medium password
    med_sec = analyzer.defang_secret("secret", SecretType.PASSWORD)
    assert med_sec.masked_value == "s****t"
    assert med_sec.length == 6

    # AWS Access Key
    aws_sec = analyzer.defang_secret("AKIAIOSFODNN7EXAMPLE", SecretType.API_KEY)
    assert aws_sec.masked_value == "AKIA****MPLE"

    # GitHub PAT
    gh_sec = analyzer.defang_secret("ghp_1234567890abcdefghijklmnopqrstuvwxyz", SecretType.API_KEY)
    assert gh_sec.masked_value == "ghp_****wxyz"

    # Private Key Header
    pk_sec = analyzer.defang_secret(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...",
        SecretType.PRIVATE_KEY,
    )
    assert "[DEFANGED PRIVATE KEY]" in pk_sec.masked_value


# -----------------------------------------------------------------------------
# 2. HTTP Credentials & Session Cookie Tests
# -----------------------------------------------------------------------------


def test_http_basic_auth_extraction(analyzer: CredentialLeakAnalyzer) -> None:
    """Test extracting and decoding HTTP Basic Authentication credentials."""
    # admin:SuperSecret123
    auth_header = "Basic " + base64.b64encode(b"admin:SuperSecret123").decode("ascii")
    pkt = PacketRecord(
        packet_num=1,
        timestamp=datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc),
        wire_len=200,
        cap_len=200,
        link_type="Ethernet",
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_port=49152,
        dst_port=80,
        transport_protocol=TransportProtocol.TCP,
        app_protocol=AppProtocol.HTTP,
        http_request=HTTPRequestInfo(
            method="GET",
            uri="/admin/dashboard",
            headers={"Authorization": auth_header, "Host": "internal-portal.corp"},
        ),
    )

    report = analyzer.analyze_packets([pkt])
    assert report.total_credentials_leaked == 1
    cred = report.credentials[0]
    assert cred.protocol == CleartextProtocol.HTTP_BASIC_AUTH
    assert cred.username == "admin"
    assert cred.secret.masked_value == "Sup****123"
    assert cred.severity == "CRITICAL"
    assert report.threat_score >= 50.0


def test_http_bearer_and_cookie_extraction(
    analyzer: CredentialLeakAnalyzer,
) -> None:
    """Test extracting Bearer tokens and session cookies from HTTP requests."""
    pkt = PacketRecord(
        packet_num=2,
        timestamp=datetime(2026, 9, 21, 12, 1, 0, tzinfo=timezone.utc),
        wire_len=250,
        cap_len=250,
        link_type="Ethernet",
        src_ip="192.168.1.60",
        dst_ip="10.0.0.2",
        src_port=49153,
        dst_port=80,
        transport_protocol=TransportProtocol.TCP,
        app_protocol=AppProtocol.HTTP,
        http_request=HTTPRequestInfo(
            method="GET",
            uri="/api/v1/users",
            headers={
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisToken",
                "Cookie": "session_id=sess_9876543210abcdef; theme=dark",
                "Host": "api.corp.local",
            },
        ),
    )

    report = analyzer.analyze_packets([pkt])
    assert report.total_credentials_leaked == 2
    protocols = [c.protocol for c in report.credentials]
    assert CleartextProtocol.HTTP_BEARER_AUTH in protocols
    assert CleartextProtocol.HTTP_COOKIE_SESSION in protocols


def test_http_post_form_login(analyzer: CredentialLeakAnalyzer) -> None:
    """Test extracting cleartext credentials submitted via HTTP POST form."""
    pkt = PacketRecord(
        packet_num=3,
        timestamp=datetime(2026, 9, 21, 12, 2, 0, tzinfo=timezone.utc),
        wire_len=300,
        cap_len=300,
        link_type="Ethernet",
        src_ip="192.168.1.70",
        dst_ip="10.0.0.3",
        src_port=49154,
        dst_port=80,
        transport_protocol=TransportProtocol.TCP,
        app_protocol=AppProtocol.HTTP,
        http_request=HTTPRequestInfo(
            method="POST",
            uri="/login.php",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "login.example.com",
            },
            body_snippet="username=target_user%40corp.com&password=P%40ssw0rd2026%21&login_btn=Submit",
        ),
    )

    report = analyzer.analyze_packets([pkt])
    assert report.total_credentials_leaked == 1
    cred = report.credentials[0]
    assert cred.protocol == CleartextProtocol.HTTP_POST_BODY
    assert cred.username == "target_user@corp.com"
    assert cred.secret.secret_type == SecretType.PASSWORD


def test_http_post_json_login(analyzer: CredentialLeakAnalyzer) -> None:
    """Test extracting cleartext credentials submitted via HTTP POST JSON body."""
    pkt = PacketRecord(
        packet_num=4,
        timestamp=datetime(2026, 9, 21, 12, 3, 0, tzinfo=timezone.utc),
        wire_len=300,
        cap_len=300,
        link_type="Ethernet",
        src_ip="192.168.1.80",
        dst_ip="10.0.0.4",
        src_port=49155,
        dst_port=80,
        transport_protocol=TransportProtocol.TCP,
        app_protocol=AppProtocol.HTTP,
        http_request=HTTPRequestInfo(
            method="POST",
            uri="/auth/login",
            headers={
                "Content-Type": "application/json",
                "Host": "auth.example.com",
            },
            body_snippet='{"email": "sysadmin@enterprise.org", "password": "SecretMasterKey2026!"}',
        ),
    )

    report = analyzer.analyze_packets([pkt])
    assert report.total_credentials_leaked == 1
    cred = report.credentials[0]
    assert cred.username == "sysadmin@enterprise.org"


# -----------------------------------------------------------------------------
# 3. FTP & Telnet Tests
# -----------------------------------------------------------------------------


def test_ftp_credentials_extraction(analyzer: CredentialLeakAnalyzer) -> None:
    """Test extracting FTP USER and PASS cleartext credentials."""
    pkt_user = PacketRecord(
        packet_num=10,
        timestamp=datetime(2026, 9, 21, 12, 10, 0, tzinfo=timezone.utc),
        wire_len=80,
        cap_len=80,
        link_type="Ethernet",
        src_ip="192.168.1.90",
        dst_ip="10.0.0.5",
        src_port=50001,
        dst_port=21,
        transport_protocol=TransportProtocol.TCP,
        http_request=HTTPRequestInfo(
            method="USER", uri="anonymous", body_snippet="USER backup_operator\r\n"
        ),
    )
    pkt_pass = PacketRecord(
        packet_num=11,
        timestamp=datetime(2026, 9, 21, 12, 10, 1, tzinfo=timezone.utc),
        wire_len=80,
        cap_len=80,
        link_type="Ethernet",
        src_ip="192.168.1.90",
        dst_ip="10.0.0.5",
        src_port=50001,
        dst_port=21,
        transport_protocol=TransportProtocol.TCP,
        http_request=HTTPRequestInfo(
            method="PASS", uri="secret", body_snippet="PASS BackupPass2026!\r\n"
        ),
    )

    report = analyzer.analyze_packets([pkt_user, pkt_pass])
    assert report.total_credentials_leaked == 1
    cred = report.credentials[0]
    assert cred.protocol == CleartextProtocol.FTP
    assert cred.username == "backup_operator"


# -----------------------------------------------------------------------------
# 4. SMTP / POP3 / IMAP Tests
# -----------------------------------------------------------------------------


def test_smtp_auth_plain_extraction(analyzer: CredentialLeakAnalyzer) -> None:
    """Test decoding SMTP AUTH PLAIN authentication token."""
    # \0user@domain.com\0MyEmailPassword
    plain_bytes = b"\x00user@domain.com\x00MyEmailPassword"
    b64_str = base64.b64encode(plain_bytes).decode("ascii")

    pkt = PacketRecord(
        packet_num=20,
        timestamp=datetime(2026, 9, 21, 12, 20, 0, tzinfo=timezone.utc),
        wire_len=100,
        cap_len=100,
        link_type="Ethernet",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.25",
        src_port=51000,
        dst_port=25,
        transport_protocol=TransportProtocol.TCP,
        http_request=HTTPRequestInfo(
            method="AUTH", uri="PLAIN", body_snippet=f"AUTH PLAIN {b64_str}\r\n"
        ),
    )

    report = analyzer.analyze_packets([pkt])
    assert report.total_credentials_leaked == 1
    cred = report.credentials[0]
    assert cred.protocol == CleartextProtocol.SMTP
    assert cred.username == "user@domain.com"


def test_pop3_imap_credentials(analyzer: CredentialLeakAnalyzer) -> None:
    """Test POP3 and IMAP cleartext authentication commands."""
    pkt_pop = PacketRecord(
        packet_num=30,
        timestamp=datetime(2026, 9, 21, 12, 30, 0, tzinfo=timezone.utc),
        wire_len=80,
        cap_len=80,
        link_type="Ethernet",
        src_ip="192.168.1.110",
        dst_ip="10.0.0.110",
        src_port=52000,
        dst_port=110,
        transport_protocol=TransportProtocol.TCP,
        http_request=HTTPRequestInfo(
            method="USER",
            uri="mail",
            body_snippet="USER john.doe\r\nPASS Winter2026!\r\n",
        ),
    )

    pkt_imap = PacketRecord(
        packet_num=31,
        timestamp=datetime(2026, 9, 21, 12, 31, 0, tzinfo=timezone.utc),
        wire_len=80,
        cap_len=80,
        link_type="Ethernet",
        src_ip="192.168.1.111",
        dst_ip="10.0.0.143",
        src_port=52001,
        dst_port=143,
        transport_protocol=TransportProtocol.TCP,
        http_request=HTTPRequestInfo(
            method="LOGIN",
            uri="mail",
            body_snippet='a001 LOGIN "jane.doe" "ImapPassword123!"\r\n',
        ),
    )

    report = analyzer.analyze_packets([pkt_pop, pkt_imap])
    assert report.total_credentials_leaked == 2
    users = [c.username for c in report.credentials]
    assert "john.doe" in users
    assert "jane.doe" in users


# -----------------------------------------------------------------------------
# 5. API Keys & Token Pattern Matching Tests
# -----------------------------------------------------------------------------


def test_api_keys_in_raw_text(analyzer: CredentialLeakAnalyzer) -> None:
    """Test detecting high-entropy API key patterns in cleartext packet payloads."""
    raw_payload = (
        "Config update:\n"
        "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n"
        "OPENAI_KEY=sk-proj-1234567890abcdef1234567890\n"
    )

    pkt = PacketRecord(
        packet_num=40,
        timestamp=datetime(2026, 9, 21, 12, 40, 0, tzinfo=timezone.utc),
        wire_len=300,
        cap_len=300,
        link_type="Ethernet",
        src_ip="192.168.1.120",
        dst_ip="10.0.0.80",
        src_port=53000,
        dst_port=80,
        transport_protocol=TransportProtocol.TCP,
        http_request=HTTPRequestInfo(method="POST", uri="/api/config", body_snippet=raw_payload),
    )

    report = analyzer.analyze_packets([pkt])
    assert report.total_credentials_leaked >= 3
    masked_vals = [c.secret.masked_value for c in report.credentials]
    assert any("AKIA" in v for v in masked_vals)
    assert any("ghp_" in v for v in masked_vals)
    assert any("sk-" in v for v in masked_vals)


# -----------------------------------------------------------------------------
# 6. Unencrypted File Transfer Tests
# -----------------------------------------------------------------------------


def test_unencrypted_file_transfer(analyzer: CredentialLeakAnalyzer) -> None:
    """Test detecting cleartext downloads of sensitive files."""
    # Sensitive file: private key
    pkt_key = PacketRecord(
        packet_num=50,
        timestamp=datetime(2026, 9, 21, 12, 50, 0, tzinfo=timezone.utc),
        wire_len=500,
        cap_len=500,
        link_type="Ethernet",
        src_ip="10.0.0.80",
        dst_ip="192.168.1.130",
        src_port=80,
        dst_port=54000,
        transport_protocol=TransportProtocol.TCP,
        http_response=HTTPResponseInfo(
            version="HTTP/1.1",
            status_code=200,
            headers={
                "Content-Disposition": 'attachment; filename="server_private.key"',
                "Content-Type": "application/x-pem-file",
                "Content-Length": "1675",
            },
        ),
    )

    # Standard document: PDF
    pkt_pdf = PacketRecord(
        packet_num=51,
        timestamp=datetime(2026, 9, 21, 12, 51, 0, tzinfo=timezone.utc),
        wire_len=1000,
        cap_len=1000,
        link_type="Ethernet",
        src_ip="10.0.0.80",
        dst_ip="192.168.1.130",
        src_port=80,
        dst_port=54001,
        transport_protocol=TransportProtocol.TCP,
        http_response=HTTPResponseInfo(
            version="HTTP/1.1",
            status_code=200,
            headers={
                "Content-Disposition": 'attachment; filename="financial_report.pdf"',
                "Content-Type": "application/pdf",
                "Content-Length": "1048576",
            },
        ),
    )

    report = analyzer.analyze_packets([pkt_key, pkt_pdf])
    assert report.total_unencrypted_files == 2
    sensitive_files = [f for f in report.unencrypted_files if f.is_sensitive_file]
    assert len(sensitive_files) == 1
    assert sensitive_files[0].filename == "server_private.key"


# -----------------------------------------------------------------------------
# 7. High-Risk Protocol Exposure Tests
# -----------------------------------------------------------------------------


def test_high_risk_protocol_exposures(analyzer: CredentialLeakAnalyzer) -> None:
    """Test tracking exposed legacy protocols (Telnet 23, FTP 21, HTTP 80, SNMP 161)."""
    pkts = [
        PacketRecord(
            packet_num=60,
            timestamp=datetime(2026, 9, 21, 12, 55, 0, tzinfo=timezone.utc),
            wire_len=100,
            cap_len=100,
            link_type="Ethernet",
            src_ip="192.168.1.140",
            dst_ip="10.0.0.23",
            src_port=55000,
            dst_port=23,  # Telnet
            transport_protocol=TransportProtocol.TCP,
        ),
        PacketRecord(
            packet_num=61,
            timestamp=datetime(2026, 9, 21, 12, 55, 1, tzinfo=timezone.utc),
            wire_len=100,
            cap_len=100,
            link_type="Ethernet",
            src_ip="192.168.1.141",
            dst_ip="10.0.0.21",
            src_port=55001,
            dst_port=21,  # FTP
            transport_protocol=TransportProtocol.TCP,
        ),
    ]

    report = analyzer.analyze_packets(pkts)
    assert report.total_protocol_exposures == 2
    ports = [p.port for p in report.protocol_exposures]
    assert 23 in ports
    assert 21 in ports


# -----------------------------------------------------------------------------
# 8. End-to-End PCAP Ingestion Tests
# -----------------------------------------------------------------------------


def test_analyze_pcap_end_to_end(analyzer: CredentialLeakAnalyzer, tmp_path: Path) -> None:
    """Test end-to-end PCAP ingestion and credential extraction."""
    pcap_file = tmp_path / "creds_leak.pcap"

    # PCAP Global Header
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # Ethernet + IP + TCP + HTTP Request with Basic Auth
    eth_hdr = b"\x00\x0c\x29\x12\x34\x56\x00\x50\x56\xc0\x00\x08\x08\x00"

    http_payload = (
        b"GET /secret HTTP/1.1\r\n"
        b"Host: secret.corp\r\n"
        b"Authorization: Basic dXNlcjEyMzpwYXNzNDU2\r\n\r\n"
    )

    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        49152,
        80,
        1000,
        0,
        0x50,
        0x18,
        65535,
        0,
        0,
    )
    l4_data = tcp_hdr + http_payload

    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        len(l4_data) + 20,
        1,
        0,
        64,
        6,
        0,
        b"\xc0\xa8\x01\x32",
        b"\x0a\x00\x00\x01",
    )

    pkt_data = eth_hdr + ip_hdr + l4_data
    pkt_hdr = struct.pack("<IIII", 1700000000, 500000, len(pkt_data), len(pkt_data))

    pcap_file.write_bytes(global_hdr + pkt_hdr + pkt_data)

    report = analyzer.analyze_pcap(pcap_file)
    assert report.total_packets_scanned == 1
    assert report.total_credentials_leaked == 1
    assert report.credentials[0].username == "user123"
    assert report.verdict in ("SUSPICIOUS", "MALICIOUS")
