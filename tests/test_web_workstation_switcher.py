"""Comprehensive test suite for Multi-Tool Web Dashboard Workspace Switcher (Task 11.2).

Tests:
1. Frontend HTML layout, workspace switcher tab buttons, and air-gapped zero-CDN compliance.
2. Multi-modal API endpoints:
   - POST /api/osint/ip (IP Geolocation & ASN Intelligence)
   - POST /api/file/analyze (Binary Static, Artifact, Metadata Inspection)
   - POST /api/pcap/analyze (Network PCAP, DNS Exfiltration, Cleartext Credentials)
   - POST /api/log/analyze (EVTX, Windows Security, Cloud Audit Logs)
   - POST /api/mem/analyze (Volatile Memory Extraction, IoC regex, YARA rules)
"""

import io

import pytest
from fastapi.testclient import TestClient

from eft.server.app import create_app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_dashboard_html_workspace_switcher(client):
    """Ensure GET / serves all 6 workstation workspace tabs with zero external CDN dependencies."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # Verify all 6 workspace tab switcher buttons
    assert 'id="ws-btn-email"' in html
    assert 'id="ws-btn-file"' in html
    assert 'id="ws-btn-osint"' in html
    assert 'id="ws-btn-pcap"' in html
    assert 'id="ws-btn-log"' in html
    assert 'id="ws-btn-mem"' in html

    # Verify all 6 workspace panes
    assert 'id="ws-pane-email"' in html
    assert 'id="ws-pane-file"' in html
    assert 'id="ws-pane-osint"' in html
    assert 'id="ws-pane-pcap"' in html
    assert 'id="ws-pane-log"' in html
    assert 'id="ws-pane-mem"' in html

    # Verify Air-Gapped Zero-CDN Compliance (no http:// or https:// script/css/font imports)
    assert "https://cdn" not in html
    assert "https://cdnjs" not in html
    assert "https://fonts.googleapis.com" not in html
    assert "https://unpkg.com" not in html
    assert "https://code.jquery.com" not in html
    assert "https://cdn.jsdelivr.net" not in html


def test_osint_ip_endpoint(client):
    """Test POST /api/osint/ip with public and private IPs."""
    # 1. Public IP lookup
    res = client.post("/api/osint/ip", json={"ip": "8.8.8.8"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["ip"] == "8.8.8.8"
    assert "intelligence" in data

    # 2. Private RFC 1918 IP lookup
    res_priv = client.post("/api/osint/ip", json={"ip": "192.168.1.1"})
    assert res_priv.status_code == 200
    data_priv = res_priv.json()
    assert data_priv["success"] is True
    assert data_priv["is_private"] is True

    # 3. Empty IP validation
    res_err = client.post("/api/osint/ip", json={"ip": "   "})
    assert res_err.status_code == 400


def test_file_analyze_endpoint(client):
    """Test POST /api/file/analyze with binary/document file payload."""
    # Create mock PE header bytes: MZ header
    mock_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 100
    file_bytes = io.BytesIO(mock_pe)

    response = client.post(
        "/api/file/analyze",
        files={"file": ("sample_payload.exe", file_bytes, "application/octet-stream")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["filename"] == "sample_payload.exe"
    assert "sha256" in data
    assert "hashes" in data
    assert "static_report" in data
    assert "artifact_report" in data
    assert "metadata_report" in data


def test_pcap_analyze_endpoint(client):
    """Test POST /api/pcap/analyze with PCAP file payload and unsupported file type."""
    # 1. Valid PCAP format test
    # Create minimal PCAP header (24 bytes)
    pcap_magic = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
    file_bytes = io.BytesIO(pcap_magic)

    response = client.post(
        "/api/pcap/analyze",
        files={"file": ("traffic_capture.pcap", file_bytes, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["filename"] == "traffic_capture.pcap"
    assert "pcap_report" in data
    assert "dns_report" in data
    assert "credential_report" in data

    # 2. Unsupported format test
    invalid_file = io.BytesIO(b"random text")
    res_err = client.post(
        "/api/pcap/analyze",
        files={"file": ("not_a_pcap.txt", invalid_file, "text/plain")},
    )
    assert res_err.status_code == 400


def test_log_analyze_endpoint(client):
    """Test POST /api/log/analyze with JSON cloud audit log and EVTX format."""
    # 1. Cloud JSON Log
    mock_log = b'{"Records": [{"eventVersion": "1.08", "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com"}]}'
    file_bytes = io.BytesIO(mock_log)

    response = client.post(
        "/api/log/analyze",
        files={"file": ("cloudtrail_audit.json", file_bytes, "application/json")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "hashes" in data
    assert "sha256" in data

    # 2. Unsupported format
    invalid_file = io.BytesIO(b"data")
    res_err = client.post(
        "/api/log/analyze",
        files={"file": ("archive.bin", invalid_file, "application/octet-stream")},
    )
    assert res_err.status_code == 400


def test_mem_analyze_endpoint(client):
    """Test POST /api/mem/analyze with volatile memory stream dump."""
    mock_mem = (
        b"Global\\Session_0_Explorer_Active\x00http://c2-beacon.darknet.ru/gate.php\x00user@malicious.com\x00"
        + b"\x00" * 500
    )
    file_bytes = io.BytesIO(mock_mem)

    response = client.post(
        "/api/mem/analyze",
        files={"file": ("win10_lsass.dmp", file_bytes, "application/octet-stream")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["filename"] == "win10_lsass.dmp"
    assert "extraction_report" in data
    assert "ioc_report" in data
    assert "yara_report" in data
