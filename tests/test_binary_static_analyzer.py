"""Unit test suite for unified BinaryStaticAnalyzer dispatcher and reporter."""

import tempfile
from pathlib import Path

from eft.analysis.binary_static_analyzer import BinaryStaticAnalyzer
from eft.models.pe_ole import BinaryStaticReport
from eft.models.threat import RiskSeverity
from tests.test_pe_analyzer import build_synthetic_pe32plus


def test_generic_binary_entropy_analysis():
    """Verify static analysis on non-PE non-OLE raw binary stream."""
    analyzer = BinaryStaticAnalyzer()

    # Low entropy plain ASCII file
    data = b"Forensic Investigation Log Entry\nTimestamp: 2026-09-21\n" * 10
    report = analyzer.analyze(data, filename="sample.log")

    assert isinstance(report, BinaryStaticReport)
    assert report.filename == "sample.log"
    assert report.size_bytes == len(data)
    assert len(report.hashes["sha256"]) == 64
    assert len(report.hashes["md5"]) == 32
    assert report.pe_analysis is None
    assert report.ole_analysis is None
    assert report.threat_score == 0.0
    assert report.verdict == "BENIGN"
    assert report.threat_severity == RiskSeverity.CLEAN


def test_high_entropy_binary_blob():
    """Verify high entropy triggers suspicious verdict on generic binary blob."""
    analyzer = BinaryStaticAnalyzer()

    # High entropy encrypted payload
    encrypted_payload = bytes([((i * 137) ^ 0xA5) % 256 for i in range(2048)])
    report = analyzer.analyze(encrypted_payload, filename="payload.bin")

    assert report.overall_entropy >= 7.5
    assert report.is_suspicious is True
    assert report.verdict == "SUSPICIOUS"
    assert report.threat_severity == RiskSeverity.MALICIOUS_HIGH
    assert any(
        "High entropy suggests encrypted payload" in adv for adv in report.remediation_advice
    )


def test_pe_binary_file_path_analysis():
    """Verify analyzing PE binary from file system path."""
    pe_bytes = build_synthetic_pe32plus(
        machine=0x8664,
        imports_spec=[
            ("KERNEL32.dll", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]),
            ("URLMON.dll", ["URLDownloadToFileA"]),
        ],
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        temp_pe_path = Path(tmp_dir) / "suspicious_loader.exe"
        temp_pe_path.write_bytes(pe_bytes)

        analyzer = BinaryStaticAnalyzer()
        report = analyzer.analyze(temp_pe_path)

        assert report.file_path == str(temp_pe_path.resolve())
        assert report.filename == "suspicious_loader.exe"
        assert report.pe_analysis is not None
        assert report.pe_analysis.is_valid_pe is True
        assert report.format_category == "Windows Portable Executable (PE)"
        assert report.threat_score >= 70.0
        assert report.verdict == "MALICIOUS"
        assert report.threat_severity == RiskSeverity.CRITICAL
        assert len(report.remediation_advice) > 0

        # Verify JSON dictionary serialization
        report_dict = report.to_dict()
        assert report_dict["filename"] == "suspicious_loader.exe"
        assert report_dict["verdict"] == "MALICIOUS"
        assert "pe_analysis" in report_dict
        assert report_dict["pe_analysis"]["architecture"] == "PE32+ (64-bit AMD64)"


def test_ole_document_analysis_dispatch():
    """Verify dispatch and analysis for OLE documents."""
    malicious_ole = (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        + b"\x00" * 256
        + b'Attribute VB_Name = "DocMacro"\nSub Document_Open()\n  Shell "cmd.exe /c calc.exe"\nEnd Sub\n'
    )

    analyzer = BinaryStaticAnalyzer()
    report = analyzer.analyze(malicious_ole, filename="invoice.doc")

    assert report.format_category == "Microsoft OLE Compound Document"
    assert report.ole_analysis is not None
    assert report.ole_analysis.has_vba_macros is True
    assert report.verdict in ("SUSPICIOUS", "MALICIOUS")
    assert report.is_suspicious is True
    assert any(
        "macro" in adv.lower() or "attachment" in adv.lower() for adv in report.remediation_advice
    )
