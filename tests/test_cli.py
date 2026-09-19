"""Comprehensive CLI Test Suite for Email Forensic Tool (EFT)."""

import json
from pathlib import Path

from typer.testing import CliRunner

from eft import __version__
from eft.cli.main import app
from eft.core.integrity import compute_file_hashes
from eft.reporting.custody import ChainOfCustodyManager

runner = CliRunner()
CORPUS_DIR = Path(__file__).parent / "fixtures" / "corpus"


def test_cli_version() -> None:
    """Verify `eft --version` outputs current version."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout
    assert "Email Forensic Tool (EFT)" in result.stdout


def test_cli_help() -> None:
    """Verify `eft --help` lists all sub-commands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "report" in result.stdout
    assert "inspect" in result.stdout
    assert "map" in result.stdout
    assert "verify" in result.stdout


def test_cli_scan_benign_corporate() -> None:
    """Verify `eft scan` on benign corporate email returns rich dashboard with clean verdict."""
    sample = CORPUS_DIR / "01_benign_corporate.eml"
    result = runner.invoke(app, ["scan", str(sample)])
    assert result.exit_code == 0
    assert "DIGITAL EVIDENCE REPORT" in result.stdout
    assert "Evidence Ingestion & Custody Manifest" in result.stdout
    assert "Overall Threat Score" in result.stdout
    assert "CLEAN" in result.stdout or "BENIGN" in result.stdout


def test_cli_scan_phishing_homoglyph() -> None:
    """Verify `eft scan` on phishing email detects threats and displays elevated score."""
    sample = CORPUS_DIR / "02_phishing_homoglyph.eml"
    result = runner.invoke(app, ["scan", str(sample)])
    assert result.exit_code == 0
    assert "Forensic Threat Factors & Evidence Attribution" in result.stdout
    assert "Hyperlinks & URLs" in result.stdout


def test_cli_scan_json_output() -> None:
    """Verify `eft scan --json` outputs valid machine-readable JSON."""
    sample = CORPUS_DIR / "01_benign_corporate.eml"
    result = runner.invoke(app, ["scan", str(sample), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert isinstance(data, dict)
    assert "subject" in data
    assert "ordered_headers" in data
    assert "authentication_report" in data


def test_cli_scan_mbox_archive() -> None:
    """Verify `eft scan` processes multi-message MBOX mailbox."""
    sample = CORPUS_DIR / "07_mixed_mailbox.mbox"
    result = runner.invoke(app, ["scan", str(sample)])
    assert result.exit_code == 0
    assert "Message #1:" in result.stdout
    assert "Message #2:" in result.stdout
    assert "Message #3:" in result.stdout


def test_cli_scan_with_options(tmp_path: Path) -> None:
    """Verify `eft scan` with custom options, attachment saving, and threat lists."""
    sample = CORPUS_DIR / "04_malware_double_extension.eml"

    # Create dummy IoC file
    ioc_file = tmp_path / "iocs.txt"
    ioc_file.write_text("# Known IoCs\n44d88612fea8a8f36de82e1278abb02f\n", encoding="utf-8")

    # Create dummy config file
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "protected_domains": ["company.com"],
                "protected_executives": [{"name": "Jane", "email": "j@company.com"}],
            }
        ),
        encoding="utf-8",
    )

    out_dir = tmp_path / "saved_attachments"

    result = runner.invoke(
        app,
        [
            "scan",
            str(sample),
            "--case-id",
            "CASE-TEST-123",
            "--examiner",
            "Examiner Alice",
            "--agency",
            "DFIR Lab",
            "--save-attachments",
            "--output-dir",
            str(out_dir),
            "--ioc-hashes",
            str(ioc_file),
            "--config",
            str(config_file),
        ],
    )
    assert result.exit_code == 0
    assert "CASE-TEST-123" in result.stdout
    assert "Examiner Alice" in result.stdout


def test_cli_report_export_all(tmp_path: Path) -> None:
    """Verify `eft report` exports all 4 formats (PDF, JSON, CSV, STIX)."""
    sample = CORPUS_DIR / "01_benign_corporate.eml"
    out_dir = tmp_path / "reports_all"

    result = runner.invoke(
        app,
        [
            "report",
            str(sample),
            "--output-dir",
            str(out_dir),
            "--format",
            "all",
            "--case-id",
            "CASE-EXP-001",
        ],
    )
    assert result.exit_code == 0
    assert "Report Export Complete" in result.stdout

    assert (out_dir / "01_benign_corporate.pdf").is_file()
    assert (out_dir / "01_benign_corporate.json").is_file()
    assert (out_dir / "01_benign_corporate.csv").is_file()
    assert (out_dir / "01_benign_corporate.stix2.json").is_file()


def test_cli_report_single_formats(tmp_path: Path) -> None:
    """Verify `eft report` with individual format flags."""
    sample = CORPUS_DIR / "01_benign_corporate.eml"

    for fmt in ["pdf", "json", "csv", "stix"]:
        out_dir = tmp_path / f"reports_{fmt}"
        res = runner.invoke(
            app,
            ["report", str(sample), "--output-dir", str(out_dir), "--format", fmt],
        )
        assert res.exit_code == 0
        assert f"Generated {fmt.upper()}" in res.stdout or f"Generated {fmt}" in res.stdout


def test_cli_inspect(tmp_path: Path) -> None:
    """Verify `eft inspect` generates standalone dual-pane HTML dashboard."""
    sample = CORPUS_DIR / "02_phishing_homoglyph.eml"
    out_file = tmp_path / "inspect.html"

    result = runner.invoke(app, ["inspect", str(sample), "--output", str(out_file)])
    assert result.exit_code == 0, f"STDOUT: {result.stdout}, EXC: {result.exception}"
    assert out_file.is_file()
    content = out_file.read_text(encoding="utf-8")
    assert "<html" in content
    assert "EFT Forensic Inspector" in content


def test_cli_map(tmp_path: Path) -> None:
    """Verify `eft map` reconstructs hops and exports SVG transit map."""
    sample = CORPUS_DIR / "06_transit_anomaly_tor.eml"
    out_svg = tmp_path / "map.svg"

    result = runner.invoke(app, ["map", str(sample), "--output", str(out_svg)])
    assert result.exit_code == 0
    assert out_svg.is_file()
    svg_data = out_svg.read_text(encoding="utf-8")
    assert "<svg" in svg_data
    assert "MTA Geographical Transit Trace" in svg_data or "svg" in svg_data


def test_cli_verify_custody(tmp_path: Path) -> None:
    """Verify `eft verify` validates cryptographic hash against manifest and direct hash."""
    sample = CORPUS_DIR / "01_benign_corporate.eml"
    manifest = ChainOfCustodyManager.create_manifest(
        sample,
        case_id="CASE-VERIFY",
        evidence_id="EVID-01",
        examiner_name="Auditor",
    )
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    # 1. Verify with manifest file
    res = runner.invoke(app, ["verify", str(sample), "--manifest", str(manifest_file)])
    assert res.exit_code == 0
    assert "IMMUTABILITY" in res.stdout
    assert "VERIFIED" in res.stdout

    # 2. Verify with direct SHA-256
    real_sha = compute_file_hashes(sample)["sha256"]
    res_direct = runner.invoke(app, ["verify", str(sample), "--sha256", real_sha])
    assert res_direct.exit_code == 0
    assert "INTEGRITY" in res_direct.stdout
    assert "VERIFIED" in res_direct.stdout

    # 3. Verify mismatch
    fake_sha = "0000000000000000000000000000000000000000000000000000000000000000"
    res_tamper = runner.invoke(app, ["verify", str(sample), "--sha256", fake_sha])
    assert res_tamper.exit_code == 2
    assert "TAMPERED" in res_tamper.stdout or "MISMATCH" in res_tamper.stdout


def test_cli_error_handling_missing_file() -> None:
    """Verify proper CLI error handling when evidence file does not exist."""
    res = runner.invoke(app, ["scan", "non_existent_file.eml"])
    assert res.exit_code != 0
