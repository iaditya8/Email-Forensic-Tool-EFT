"""Automated tests for Unified CLI Lookup & OSINT commands (eft lookup / eft osint)."""

import json
from pathlib import Path

from typer.testing import CliRunner

from eft.cli.main import app

runner = CliRunner()


def test_cli_lookup_in_help() -> None:
    """Verify `lookup` and `osint` appear in `eft --help`."""
    result = runner.invoke(app, ["--help"], color=False)
    assert result.exit_code == 0
    assert "lookup" in result.stdout
    assert "osint" in result.stdout


def test_cli_lookup_email_offline() -> None:
    """Verify `eft lookup` on email address in offline mode renders rich report."""
    result = runner.invoke(app, ["lookup", "analyst@target-domain.com", "--offline"])
    assert result.exit_code == 0
    assert "OSINT INTELLIGENCE REPORT: analyst@target-domain.com" in result.stdout
    assert "Executive Domain & Email Intelligence" in result.stdout
    assert "Domain Identity & Target Profile" in result.stdout
    assert "DNS Routing & Email Authentication Posture" in result.stdout
    assert "target-domain.com" in result.stdout


def test_cli_lookup_domain_offline() -> None:
    """Verify `eft lookup` on a raw domain name."""
    result = runner.invoke(app, ["lookup", "example.org", "--offline"])
    assert result.exit_code == 0
    assert "OSINT INTELLIGENCE REPORT: example.org" in result.stdout
    assert "example.org" in result.stdout
    assert "Domain Name" in result.stdout


def test_cli_lookup_json_output() -> None:
    """Verify `eft lookup --json` outputs valid machine-readable JSON."""
    result = runner.invoke(app, ["lookup", "user@corp-sample.com", "--offline", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert isinstance(data, dict)
    assert data["input_target"] == "user@corp-sample.com"
    assert data["analyzed_domain"] == "corp-sample.com"
    assert "dns_posture" in data
    assert "reputation_score" in data
    assert "risk_factors" in data


def test_cli_osint_alias() -> None:
    """Verify `eft osint lookup` works with JSON output."""
    result = runner.invoke(app, ["osint", "lookup", "security@partner.io", "--offline", "-j"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["input_target"] == "security@partner.io"
    assert data["analyzed_domain"] == "partner.io"


def test_cli_lookup_save_to_file(tmp_path: Path) -> None:
    """Verify `eft lookup --output <path>` saves JSON report to disk."""
    out_file = tmp_path / "osint_report.json"
    result = runner.invoke(
        app,
        ["lookup", "ceo@company.net", "--offline", "--output", str(out_file)],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["analyzed_domain"] == "company.net"
    assert "OSINT report saved to:" in result.stdout


def test_cli_lookup_custom_dns_timeout() -> None:
    """Verify `eft lookup --dns-timeout` option is accepted."""
    result = runner.invoke(
        app,
        ["lookup", "audit@secure.gov", "--offline", "--dns-timeout", "5.5"],
    )
    assert result.exit_code == 0
    assert "audit@secure.gov" in result.stdout
