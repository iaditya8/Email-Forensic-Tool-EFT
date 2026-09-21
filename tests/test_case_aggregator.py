"""Comprehensive test suite for Cross-Module Unified Evidence Ledger & Master Case Report (Task 11.3).

Tests:
1. MasterCaseAggregator multi-modal evidence ingestion (Email, File/Binary, PCAP, Log, Memory).
2. Pre- and post-analysis cryptographic multi-hashing (100% zero-byte mutation validation).
3. Cross-evidence correlation engine (Shared IoCs, Attack chain sequences).
4. MasterCaseExporter:
   - JSON export & validation
   - CSV IoC ledger export
   - STIX 2.1 Threat Bundle generation
   - Court-admissible PDF generation
5. CLI `eft case analyze` and `eft case report` commands.
6. Server REST API endpoints:
   - POST /api/case/analyze
   - POST /api/case/export/{format}
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from eft.cli.main import app
from eft.models.master_case import MasterCaseReport
from eft.reporting.case_aggregator import MasterCaseAggregator
from eft.reporting.case_exporter import MasterCaseExporter
from eft.server.app import create_app

runner = CliRunner()


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.fixture
def sample_evidence_files(tmp_path: Path):
    """Generate temporary fixture evidence files across different forensic domains."""
    # 1. Email evidence
    email_path = tmp_path / "phish_lure.eml"
    email_path.write_text(
        "From: attacker@evil-corp.com\n"
        "To: victim@company.com\n"
        "Subject: Urgent Wire Transfer Request\n"
        "Date: Mon, 21 Sep 2026 10:00:00 +0000\n"
        "Message-ID: <msg123@evil-corp.com>\n\n"
        "Please download the invoice at http://malicious-c2.net/payload.exe immediately.",
        encoding="utf-8",
    )

    # 2. Binary file evidence
    binary_path = tmp_path / "payload.exe"
    # MZ header bytes with some mock data
    binary_path.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x00" * 200)

    # 3. PCAP capture evidence (minimal 24-byte PCAP header)
    pcap_path = tmp_path / "traffic.pcap"
    pcap_magic = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
    pcap_path.write_bytes(pcap_magic)

    # 4. Cloud audit log evidence
    log_path = tmp_path / "cloud_audit.json"
    log_data = {
        "Records": [
            {
                "eventVersion": "1.08",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "userIdentity": {"type": "IAMUser", "userName": "attacker_compromised"},
                "sourceIPAddress": "198.51.100.45",
            }
        ]
    }
    log_path.write_text(json.dumps(log_data), encoding="utf-8")

    # 5. Volatile memory dump evidence
    mem_path = tmp_path / "memory.dmp"
    mem_path.write_bytes(
        b"Global\\LSASS_Beacon_Stream\x00http://malicious-c2.net/gate.php\x00" + b"\x00" * 300
    )

    return {
        "email": email_path,
        "binary": binary_path,
        "pcap": pcap_path,
        "log": log_path,
        "mem": mem_path,
    }


def test_master_case_aggregator_multi_evidence(sample_evidence_files):
    """Test full multi-modal evidence aggregation, zero-byte mutation validation, and correlation."""
    aggregator = MasterCaseAggregator(
        case_id="CASE-2026-MULTI",
        examiner_name="Special Agent Smith",
        examiner_agency="DFIR Cyber Crime Unit",
        case_title="Operation Phish-to-Egress Investigation",
    )

    # Ingest all 5 evidence files
    for key, f_path in sample_evidence_files.items():
        item = aggregator.add_evidence_file(f_path)
        assert item.item_id.startswith("EVID-")
        assert item.manifest.integrity_verified is True
        assert (
            item.manifest.pre_analysis_hashes["sha256"]
            == item.manifest.post_analysis_hashes["sha256"]
        )

    report: MasterCaseReport = aggregator.correlate_and_build_report()

    # Validate Master Case Report structure
    assert report.case_id == "CASE-2026-MULTI"
    assert len(report.evidence_items) == 5
    assert len(report.master_timeline) > 0
    assert len(report.master_ioc_ledger) > 0
    assert len(report.immutability_audit) == 5

    # Check zero-byte mutation across all items
    for item_id, audit in report.immutability_audit.items():
        assert audit["verified"] is True
        assert audit["pre_sha256"] == audit["post_sha256"]

    # Check that cross-module correlation identified the attack chain or shared URLs
    assert len(report.cross_module_correlations) > 0
    assert report.overall_composite_risk_score > 0.0


def test_master_case_exporter_json(sample_evidence_files, tmp_path):
    """Test MasterCaseExporter.export_json lossless serialization."""
    aggregator = MasterCaseAggregator(case_id="CASE-JSON-TEST", examiner_name="Examiner")
    aggregator.add_evidence_file(sample_evidence_files["email"])
    aggregator.add_evidence_file(sample_evidence_files["binary"])
    report = aggregator.correlate_and_build_report()

    out_json = tmp_path / "master_report.json"
    json_str = MasterCaseExporter.export_json(report, output_path=out_json)

    assert out_json.is_file()
    parsed = json.loads(json_str)
    assert parsed["case_id"] == "CASE-JSON-TEST"
    assert len(parsed["evidence_items"]) == 2


def test_master_case_exporter_csv(sample_evidence_files, tmp_path):
    """Test MasterCaseExporter.export_csv IoC ledger extraction."""
    aggregator = MasterCaseAggregator(case_id="CASE-CSV-TEST", examiner_name="Examiner")
    aggregator.add_evidence_file(sample_evidence_files["email"])
    aggregator.add_evidence_file(sample_evidence_files["binary"])
    report = aggregator.correlate_and_build_report()

    out_csv = tmp_path / "iocs.csv"
    csv_str = MasterCaseExporter.export_csv(report, output_path=out_csv)

    assert out_csv.is_file()
    assert "ioc_type,ioc_value,source_item_id" in csv_str
    assert "CASE-CSV-TEST" in csv_str


def test_master_case_exporter_stix(sample_evidence_files, tmp_path):
    """Test MasterCaseExporter.export_stix STIX 2.1 Threat Bundle generation."""
    aggregator = MasterCaseAggregator(case_id="CASE-STIX-TEST", examiner_name="Examiner")
    aggregator.add_evidence_file(sample_evidence_files["email"])
    aggregator.add_evidence_file(sample_evidence_files["mem"])
    report = aggregator.correlate_and_build_report()

    out_stix = tmp_path / "threat_bundle.json"
    stix_str = MasterCaseExporter.export_stix(report, output_path=out_stix)

    assert out_stix.is_file()
    bundle = json.loads(stix_str)
    assert bundle["type"] == "bundle"
    assert "objects" in bundle
    assert any(obj["type"] == "report" for obj in bundle["objects"])


def test_master_case_exporter_pdf(sample_evidence_files, tmp_path):
    """Test MasterCaseExporter.export_pdf Court-Admissible report compilation."""
    aggregator = MasterCaseAggregator(
        case_id="CASE-PDF-TEST",
        examiner_name="Special Agent Lead",
        examiner_agency="Federal Digital Forensics Lab",
    )
    for f_path in sample_evidence_files.values():
        aggregator.add_evidence_file(f_path)
    report = aggregator.correlate_and_build_report()

    out_pdf = tmp_path / "Court_Evidence_Report.pdf"
    res_path = MasterCaseExporter.export_pdf(report, output_path=out_pdf)

    assert res_path.is_file()
    assert res_path.stat().st_size > 1000  # PDF generated with content


def test_cli_case_analyze_and_report(sample_evidence_files, tmp_path):
    """Test CLI commands: `eft case analyze` and `eft case report`."""
    f1 = str(sample_evidence_files["email"])
    f2 = str(sample_evidence_files["binary"])

    # 1. `eft case analyze` (table)
    result_table = runner.invoke(app, ["case", "analyze", f1, f2, "--case-id", "CLI-CASE-01"])
    assert result_table.exit_code == 0
    assert "MASTER DIGITAL FORENSIC CASE REPORT" in result_table.stdout
    assert "CLI-CASE-01" in result_table.stdout

    # 2. `eft case analyze --json`
    result_json = runner.invoke(app, ["case", "analyze", f1, f2, "--json"])
    assert result_json.exit_code == 0
    parsed = json.loads(result_json.stdout)
    assert "evidence_items" in parsed

    # 3. `eft case report --format pdf`
    pdf_out = tmp_path / "cli_case_report.pdf"
    result_pdf = runner.invoke(
        app, ["case", "report", f1, f2, "--format", "pdf", "--output", str(pdf_out)]
    )
    assert result_pdf.exit_code == 0
    assert pdf_out.is_file()

    # 4. `eft case report --format csv`
    csv_out = tmp_path / "cli_iocs.csv"
    result_csv = runner.invoke(
        app, ["case", "report", f1, f2, "--format", "csv", "--output", str(csv_out)]
    )
    assert result_csv.exit_code == 0
    assert csv_out.is_file()


def test_server_case_api(client, sample_evidence_files):
    """Test FastAPI endpoints /api/case/analyze and /api/case/export/{format}."""
    # 1. POST /api/case/analyze
    files_payload = [
        ("files", ("lure.eml", sample_evidence_files["email"].read_bytes(), "message/rfc822")),
        (
            "files",
            (
                "payload.exe",
                sample_evidence_files["binary"].read_bytes(),
                "application/octet-stream",
            ),
        ),
    ]

    res = client.post(
        "/api/case/analyze",
        data={"case_id": "API-CASE-99", "examiner": "Web Analyst"},
        files=files_payload,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    report = data["report"]
    assert report["case_id"] == "API-CASE-99"
    assert len(report["evidence_items"]) == 2

    # 2. POST /api/case/export/json
    res_json = client.post("/api/case/export/json", json={"report": report})
    assert res_json.status_code == 200
    assert res_json.headers["content-type"] == "application/json"

    # 3. POST /api/case/export/csv
    res_csv = client.post("/api/case/export/csv", json={"report": report})
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]

    # 4. POST /api/case/export/stix
    res_stix = client.post("/api/case/export/stix", json={"report": report})
    assert res_stix.status_code == 200
    assert res_stix.headers["content-type"] == "application/json"

    # 5. POST /api/case/export/pdf
    res_pdf = client.post("/api/case/export/pdf", json={"report": report})
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"] == "application/pdf"
    assert len(res_pdf.content) > 1000
