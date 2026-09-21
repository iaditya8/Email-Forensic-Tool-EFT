"""Comprehensive test suite for Master Unified CLI Command Routing."""

import json
from pathlib import Path

from typer.testing import CliRunner

from eft.cli.main import app

runner = CliRunner()


def test_cli_root_help() -> None:
    """Verify root CLI help lists all 6 modular sub-apps and root commands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "email" in result.stdout
    assert "file" in result.stdout
    assert "osint" in result.stdout
    assert "pcap" in result.stdout
    assert "log" in result.stdout
    assert "mem" in result.stdout
    assert "serve" in result.stdout


def test_cli_version() -> None:
    """Verify --version flag displays version and exits."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "Email Forensic Tool" in result.stdout


def test_cli_email_commands(tmp_path: Path) -> None:
    """Verify 'eft email scan', 'eft email report', 'eft email inspect', and 'eft email map'."""
    eml_file = tmp_path / "sample.eml"
    eml_file.write_text(
        "From: sender@example.com\n"
        "To: recipient@example.com\n"
        "Subject: Forensic Test\n"
        "Date: Mon, 21 Sep 2026 12:00:00 +0000\n"
        "Message-ID: <msg123@example.com>\n"
        "Received: from mail.example.com (8.8.8.8) by mx.google.com; Mon, 21 Sep 2026 12:00:00 +0000\n\n"
        "Hello World\n",
        encoding="utf-8",
    )

    # 1. email scan
    res_scan = runner.invoke(app, ["email", "scan", str(eml_file)])
    assert res_scan.exit_code == 0
    assert "DIGITAL EVIDENCE REPORT" in res_scan.stdout

    # 2. email scan --json
    res_scan_json = runner.invoke(app, ["email", "scan", str(eml_file), "--json"])
    assert res_scan_json.exit_code == 0
    parsed = json.loads(res_scan_json.stdout)
    assert parsed.get("subject") == "Forensic Test"

    # 3. email report
    out_dir = tmp_path / "reports"
    res_rep = runner.invoke(
        app, ["email", "report", str(eml_file), "-o", str(out_dir), "-f", "json"]
    )
    assert res_rep.exit_code == 0
    assert (out_dir / "sample.json").exists()

    # 4. email inspect
    html_out = tmp_path / "inspect.html"
    res_ins = runner.invoke(app, ["email", "inspect", str(eml_file), "-o", str(html_out)])
    assert res_ins.exit_code == 0
    assert html_out.exists()

    # 5. email map
    svg_out = tmp_path / "map.svg"
    res_map = runner.invoke(app, ["email", "map", str(eml_file), "-o", str(svg_out)])
    assert res_map.exit_code == 0
    assert svg_out.exists()


def test_cli_file_commands(tmp_path: Path) -> None:
    """Verify 'eft file inspect', 'eft file entropy', and 'eft file exif'."""
    bin_file = tmp_path / "test.bin"
    bin_file.write_bytes(b"\x7fELF" + b"\x00" * 128 + b"SAMPLE_METADATA_AUTHOR: Examiner")

    # 1. file inspect
    res_ins = runner.invoke(app, ["file", "inspect", str(bin_file)])
    assert res_ins.exit_code == 0
    assert "FILE FORENSIC INSPECTION" in res_ins.stdout

    # 2. file entropy
    res_ent = runner.invoke(app, ["file", "entropy", str(bin_file)])
    assert res_ent.exit_code == 0
    assert "SHANNON ENTROPY PROFILE" in res_ent.stdout

    # 3. file exif
    res_exif = runner.invoke(app, ["file", "exif", str(bin_file)])
    assert res_exif.exit_code == 0
    assert "METADATA & EXIF EXTRACTION" in res_exif.stdout


def test_cli_osint_commands() -> None:
    """Verify 'eft osint lookup', 'eft osint domain', and 'eft osint ip'."""
    # 1. osint lookup
    res_look = runner.invoke(app, ["osint", "lookup", "security@google.com", "--offline"])
    assert res_look.exit_code == 0
    assert "OSINT INTELLIGENCE REPORT" in res_look.stdout

    # 2. osint domain
    res_dom = runner.invoke(app, ["osint", "domain", "microsoft.com", "--offline"])
    assert res_dom.exit_code == 0
    assert "OSINT INTELLIGENCE REPORT" in res_dom.stdout

    # 3. osint ip
    res_ip = runner.invoke(app, ["osint", "ip", "8.8.8.8"])
    assert res_ip.exit_code == 0
    assert "IP NETWORK INTELLIGENCE" in res_ip.stdout


def test_cli_pcap_commands(tmp_path: Path) -> None:
    """Verify 'eft pcap analyze', 'eft pcap dns', and 'eft pcap creds'."""
    # Create minimal PCAP file (24-byte global header)
    pcap_file = tmp_path / "test.pcap"
    pcap_header = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")
    pcap_file.write_bytes(pcap_header)

    # 1. pcap analyze
    res_ana = runner.invoke(app, ["pcap", "analyze", str(pcap_file)])
    assert res_ana.exit_code == 0
    assert "PCAP NETWORK STREAM ANALYSIS" in res_ana.stdout

    # 2. pcap dns
    res_dns = runner.invoke(app, ["pcap", "dns", str(pcap_file)])
    assert res_dns.exit_code == 0
    assert "DNS THREAT & EXFILTRATION TRIAGE" in res_dns.stdout

    # 3. pcap creds
    res_cred = runner.invoke(app, ["pcap", "creds", str(pcap_file)])
    assert res_cred.exit_code == 0
    assert "CLEARTEXT CREDENTIAL & SECRET LEAKAGE" in res_cred.stdout


def test_cli_log_commands(tmp_path: Path) -> None:
    """Verify 'eft log evtx', 'eft log sysmon', 'eft log m365', and 'eft log google'."""
    # 1. Dummy JSON event log for EVTX / Sysmon (since analyzer handles JSON lists)
    evtx_json = tmp_path / "security_log.json"
    evtx_json.write_text(
        json.dumps(
            [
                {
                    "EventID": 4624,
                    "Channel": "Security",
                    "TimeCreated": "2026-09-21T12:00:00Z",
                    "EventData": {
                        "TargetUserName": "admin",
                        "LogonType": 2,
                        "IpAddress": "192.168.1.50",
                    },
                }
            ]
        )
    )

    res_evtx = runner.invoke(app, ["log", "evtx", str(evtx_json)])
    assert res_evtx.exit_code == 0
    assert "WINDOWS SECURITY EVENT LOG TRIAGE" in res_evtx.stdout

    res_sysmon = runner.invoke(app, ["log", "sysmon", str(evtx_json)])
    assert res_sysmon.exit_code == 0
    assert "SYSMON PROCESS & THREAT CORRELATION" in res_sysmon.stdout

    # 2. M365 log
    m365_json = tmp_path / "m365_audit.json"
    m365_json.write_text(
        json.dumps(
            [
                {
                    "CreationTime": "2026-09-21T12:00:00Z",
                    "UserId": "admin@tenant.com",
                    "Operation": "New-InboxRule",
                    "RecordType": 1,
                    "Parameters": [{"Name": "ForwardTo", "Value": "attacker@evil.com"}],
                }
            ]
        )
    )

    res_m365 = runner.invoke(app, ["log", "m365", str(m365_json)])
    assert res_m365.exit_code == 0
    assert "MICROSOFT 365 AUDIT LOG TRIAGE" in res_m365.stdout

    # 3. Google log
    res_goog = runner.invoke(app, ["log", "google", str(m365_json)])
    assert res_goog.exit_code == 0
    assert "GOOGLE WORKSPACE AUDIT LOG TRIAGE" in res_goog.stdout


def test_cli_mem_commands(tmp_path: Path) -> None:
    """Verify 'eft mem scan', 'eft mem strings', 'eft mem iocs', and 'eft mem yara'."""
    dump_file = tmp_path / "memory.raw"
    dump_file.write_bytes(
        b"\x00" * 32
        + b"C2_HOST: https://darknet-c2.org/beacon\x00"
        + b"IP: 185.220.101.5\x00"
        + b"sekurlsa::logonpasswords gentilkiwi\x00"
    )

    # 1. mem scan
    res_scan = runner.invoke(app, ["mem", "scan", str(dump_file)])
    assert res_scan.exit_code == 0
    assert "VOLATILE MEMORY MASTER TRIAGE" in res_scan.stdout

    # 2. mem strings
    res_str = runner.invoke(app, ["mem", "strings", str(dump_file)])
    assert res_str.exit_code == 0
    assert "EXTRACTED STRINGS SAMPLE" in res_str.stdout

    # 3. mem iocs
    res_ioc = runner.invoke(app, ["mem", "iocs", str(dump_file)])
    assert res_ioc.exit_code == 0
    assert "IN-MEMORY IOC & PATTERN FINDINGS" in res_ioc.stdout

    # 4. mem yara
    res_yar = runner.invoke(app, ["mem", "yara", str(dump_file)])
    assert res_yar.exit_code == 0
    assert "VOLATILE MEMORY YARA SCAN" in res_yar.stdout


def test_cli_root_backward_compatibility(tmp_path: Path) -> None:
    """Verify root commands (scan, lookup, osint, verify) maintain 100% backward compatibility."""
    eml_file = tmp_path / "sample.eml"
    eml_file.write_text("From: a@b.com\nSubject: Test\n\nBody", encoding="utf-8")

    # Root scan
    res_scan = runner.invoke(app, ["scan", str(eml_file)])
    assert res_scan.exit_code == 0

    # Root lookup
    res_look = runner.invoke(app, ["lookup", "a@b.com", "--offline"])
    assert res_look.exit_code == 0

    # Sub-app osint lookup
    res_osint = runner.invoke(app, ["osint", "lookup", "a@b.com", "--offline"])
    assert res_osint.exit_code == 0

    # Root verify
    res_ver = runner.invoke(app, ["verify", str(eml_file)])
    assert res_ver.exit_code == 0
    assert "Evidence Integrity Verification" in res_ver.stdout
