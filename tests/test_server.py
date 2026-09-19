"""Integration tests for EFT Air-Gapped Web Server and API endpoints."""

from pathlib import Path
from typing import Any, Dict

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from eft.cli.main import app as cli_app
from eft.server.app import create_app

client = TestClient(create_app())
runner = CliRunner()

CORPUS_DIR = Path(__file__).parent / "fixtures" / "corpus"


def test_server_health() -> None:
    """Verify server healthcheck and air-gapped readiness probe."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["air_gapped"] is True
    assert data["version"] == "1.0.0"


def test_server_dashboard_html() -> None:
    """Verify GET / renders the self-contained forensic dashboard HTML."""
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Email Forensic Tool" in res.text
    assert "100% Air-Gapped" in res.text


def test_server_list_samples() -> None:
    """Verify GET /api/samples returns available corpus sample fixtures."""
    res = client.get("/api/samples")
    assert res.status_code == 200
    samples = res.json()
    assert isinstance(samples, list)
    assert len(samples) >= 7
    filenames = [s["filename"] for s in samples]
    assert "01_benign_corporate.eml" in filenames
    assert "03_bec_wire_fraud.eml" in filenames


def test_server_analyze_sample() -> None:
    """Verify GET /api/sample/{name} executes complete analysis on a corpus sample."""
    res = client.get("/api/sample/01_benign_corporate.eml")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["sample_name"] == "01_benign_corporate.eml"
    assert "sha256" in data
    assert "email" in data
    assert "risk_report" in data
    assert data["risk_report"]["risk_level"] == "CLEAN"


def test_server_analyze_sample_bec() -> None:
    """Verify GET /api/sample/{name} detects BEC risk in sample 03."""
    res = client.get("/api/sample/03_bec_wire_fraud.eml")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["risk_report"]["overall_score"] >= 20.0
    assert data["risk_report"]["risk_level"] != "CLEAN"


def test_server_analyze_sample_not_found() -> None:
    """Verify GET /api/sample/{name} returns 404 for unknown sample name."""
    res = client.get("/api/sample/non_existent_sample.eml")
    assert res.status_code == 404


def test_server_analyze_upload_eml() -> None:
    """Verify POST /api/analyze handles uploaded .eml file."""
    sample_file = CORPUS_DIR / "01_benign_corporate.eml"
    with open(sample_file, "rb") as f:
        res = client.post(
            "/api/analyze",
            files={"file": ("01_benign_corporate.eml", f, "message/rfc822")},
            data={"case_id": "CASE-TEST-001", "examiner": "Examiner Fox"},
        )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["filename"] == "01_benign_corporate.eml"
    assert data["manifest"]["case_id"] == "CASE-TEST-001"
    assert data["manifest"]["examiner_name"] == "Examiner Fox"


def test_server_analyze_upload_invalid_format() -> None:
    """Verify POST /api/analyze rejects unsupported file formats."""
    res = client.post(
        "/api/analyze",
        files={"file": ("malicious.exe", b"MZDummyContent", "application/octet-stream")},
    )
    assert res.status_code == 400
    assert "Unsupported file format" in res.json()["detail"]


def test_server_export_endpoints() -> None:
    """Verify POST /api/export/{format} for PDF, JSON, CSV, and STIX."""
    sample_res = client.get("/api/sample/01_benign_corporate.eml")
    payload: Dict[str, Any] = sample_res.json()

    # JSON export
    res_json = client.post("/api/export/json", json=payload)
    assert res_json.status_code == 200
    assert "application/json" in res_json.headers["content-type"]

    # CSV export
    res_csv = client.post("/api/export/csv", json=payload)
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]

    # STIX export
    res_stix = client.post("/api/export/stix", json=payload)
    assert res_stix.status_code == 200
    assert "application/json" in res_stix.headers["content-type"]

    # PDF export
    res_pdf = client.post("/api/export/pdf", json=payload)
    assert res_pdf.status_code == 200
    assert "application/pdf" in res_pdf.headers["content-type"]
    assert res_pdf.content.startswith(b"%PDF")

    # Invalid export
    res_inv = client.post("/api/export/unknown_fmt", json=payload)
    assert res_inv.status_code == 400


def test_server_inspect_endpoint() -> None:
    """Verify POST /api/inspect renders dual-pane HTML inspector."""
    sample_res = client.get("/api/sample/01_benign_corporate.eml")
    payload = sample_res.json()
    res = client.post("/api/inspect", json=payload)
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Dual-Pane Email Inspector" in res.text or "Forensic" in res.text


def test_server_map_endpoint() -> None:
    """Verify POST /api/map renders SVG transit map."""
    sample_res = client.get("/api/sample/01_benign_corporate.eml")
    payload = sample_res.json()
    res = client.post("/api/map", json=payload)
    assert res.status_code == 200
    assert "image/svg+xml" in res.headers["content-type"]
    assert "<svg" in res.text


def test_server_verify_endpoint() -> None:
    """Verify POST /api/verify performs cryptographic evidence comparison."""
    sample_res = client.get("/api/sample/01_benign_corporate.eml")
    sha = sample_res.json()["sha256"]

    # Match
    res_match = client.post(
        "/api/verify",
        json={"current_sha256": sha, "expected_sha256": sha},
    )
    assert res_match.status_code == 200
    assert res_match.json()["verified"] is True
    assert "VERIFIED" in res_match.json()["status"]

    # Mismatch
    res_mismatch = client.post(
        "/api/verify",
        json={
            "current_sha256": sha,
            "expected_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        },
    )
    assert res_mismatch.status_code == 200
    assert res_mismatch.json()["verified"] is False
    assert "TAMPERING" in res_mismatch.json()["status"]


def test_cli_serve_help() -> None:
    """Verify `eft serve --help` displays server CLI options."""
    res = runner.invoke(cli_app, ["serve", "--help"], color=False)
    assert res.exit_code == 0
    assert "host" in res.stdout.lower()
    assert "port" in res.stdout.lower()
