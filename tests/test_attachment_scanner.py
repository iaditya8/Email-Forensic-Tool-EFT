"""Unit and integration tests for Attachment Static Threat Analysis & YARA Scanner."""

import hashlib
from pathlib import Path

import pytest

from eft.analysis.attachment_scanner import AttachmentThreatScanner
from eft.models.canonical import (
    AttachmentAnalysisReport,
    AttachmentThreatAnalysis,
    CanonicalEmail,
    ExtractedAttachment,
    FileTypeInspection,
)


@pytest.fixture
def scanner() -> AttachmentThreatScanner:
    return AttachmentThreatScanner()


def test_vba_macro_detection(scanner: AttachmentThreatScanner) -> None:
    """Validate detection of weaponized VBA macro hooks and process execution calls."""
    # Simulated macro payload inside binary
    vba_payload = b'PK\x03\x04...vbaProject.bin...Sub AutoOpen() CreateObject("WScript.Shell").Run "powershell.exe -enc ..." End Sub'

    att = ExtractedAttachment(
        filename="invoice_urgent.docm",
        safe_filename="invoice_urgent_docm",
        size_bytes=len(vba_payload),
        hashes={"sha256": hashlib.sha256(vba_payload).hexdigest()},
        file_type_inspection=FileTypeInspection(
            declared_extension="docm", detected_extension="docm"
        ),
    )

    analysis: AttachmentThreatAnalysis = scanner.scan_attachment(att, vba_payload)

    assert analysis.is_malicious is True
    assert analysis.threat_level == "MALICIOUS"
    assert "MACRO_VBA" in analysis.threat_categories
    assert any("VBA_MACRO" in ind or "YARA_MATCH" in ind for ind in analysis.threat_indicators)
    assert len(analysis.yara_matches) >= 1
    assert analysis.yara_matches[0].rule_name == "MALICIOUS_OFFICE_VBA_MACRO"


def test_pdf_exploit_detection(scanner: AttachmentThreatScanner) -> None:
    """Validate detection of suspicious PDF actions (/JavaScript, /Launch)."""
    pdf_payload = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (eval(unescape('%3Cscript%3E'))); >> /Launch << /F (cmd.exe) >> >>\nendobj"

    att = ExtractedAttachment(
        filename="scanned_statement.pdf",
        safe_filename="scanned_statement_pdf",
        size_bytes=len(pdf_payload),
        hashes={"sha256": hashlib.sha256(pdf_payload).hexdigest()},
        file_type_inspection=FileTypeInspection(declared_extension="pdf", detected_extension="pdf"),
    )

    analysis = scanner.scan_attachment(att, pdf_payload)

    assert "EXPLOIT_PDF" in analysis.threat_categories
    assert any("PDF_" in ind for ind in analysis.threat_indicators)
    assert any(y.rule_name == "MALICIOUS_PDF_EXPLOIT_OBJECTS" for y in analysis.yara_matches)


def test_pe_executable_header_detection(scanner: AttachmentThreatScanner) -> None:
    """Validate detection of Windows PE binaries with extension spoofing."""
    # Build a minimal PE header: MZ at 0, PE offset pointer at 0x3C pointing to offset 0x80
    pe_bytes = bytearray(256)
    pe_bytes[0:2] = b"MZ"
    pe_bytes[0x3C:0x40] = (0x80).to_bytes(4, byteorder="little")
    pe_bytes[0x80:0x84] = b"PE\x00\x00"
    pe_bytes.extend(b"VirtualAlloc WriteProcessMemory CreateRemoteThread")
    pe_payload = bytes(pe_bytes)

    att = ExtractedAttachment(
        filename="company_photo.jpg",  # Extension mismatch spoofing
        safe_filename="company_photo_jpg",
        size_bytes=len(pe_payload),
        hashes={"sha256": hashlib.sha256(pe_payload).hexdigest()},
        file_type_inspection=FileTypeInspection(
            declared_extension="jpg",
            detected_extension="exe",
            is_extension_mismatch=True,
            risk_level="CRITICAL",
        ),
    )

    analysis = scanner.scan_attachment(att, pe_payload)

    assert analysis.is_malicious is True
    assert "EMBEDDED_PE" in analysis.threat_categories
    assert "EXTENSION_MAGIC_MISMATCH" in analysis.threat_categories
    assert "ATTACHMENT_EXTENSION_SPOOFING" in analysis.threat_indicators
    assert any(y.rule_name == "SUSPICIOUS_WINDOWS_PE_EXECUTABLE" for y in analysis.yara_matches)


def test_dangerous_extension_flagging(scanner: AttachmentThreatScanner) -> None:
    """Validate automatic risk tagging for dangerous scripts and containers (.vbs, .iso, .hta, .scr)."""
    extensions = ["vbs", "iso", "hta", "scr", "ps1"]
    for ext in extensions:
        att = ExtractedAttachment(
            filename=f"payload.{ext}",
            safe_filename=f"payload_{ext}",
            size_bytes=50,
            file_type_inspection=FileTypeInspection(declared_extension=ext, detected_extension=ext),
        )
        analysis = scanner.scan_attachment(att, b"WScript.Echo 'test'")
        assert analysis.dangerous_extension is True
        assert "DANGEROUS_EXTENSION" in analysis.threat_categories


def test_ioc_hash_matching(scanner: AttachmentThreatScanner) -> None:
    """Validate correlation with known malicious threat intelligence hash feeds."""
    payload = b"Known ransomware loader binary payload"
    sha256_hash = hashlib.sha256(payload).hexdigest()
    known_bad_feed = {sha256_hash, "d41d8cd98f00b204e9800998ecf8427e"}

    att = ExtractedAttachment(
        filename="document.zip",
        safe_filename="document_zip",
        size_bytes=len(payload),
        hashes={"sha256": sha256_hash, "md5": hashlib.md5(payload).hexdigest()},
    )

    analysis = scanner.scan_attachment(att, payload, known_bad_hashes=known_bad_feed)

    assert analysis.is_malicious is True
    assert "KNOWN_THREAT_IOC" in analysis.threat_categories
    assert "IOC_THREAT_HASH_MATCH" in analysis.threat_indicators
    assert len(analysis.ioc_hashes_matched) >= 1


def test_eicar_test_file_signature(scanner: AttachmentThreatScanner) -> None:
    """Validate built-in YARA detection of standard EICAR anti-virus test file string."""
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    att = ExtractedAttachment(
        filename="eicar.com",
        safe_filename="eicar_com",
        size_bytes=len(eicar_bytes),
    )

    analysis = scanner.scan_attachment(att, eicar_bytes)

    assert analysis.is_malicious is True
    assert any(y.rule_name == "EICAR_STANDARD_AV_TEST_FILE" for y in analysis.yara_matches)


def test_clean_attachment_baseline(scanner: AttachmentThreatScanner) -> None:
    """Validate that benign files (plain text, clean documents) evaluate to BENIGN."""
    clean_bytes = b"Dear Team,\nHere is the meeting agenda for tomorrow's all-hands.\n1. Review Q3\n2. Q4 Roadmap\nBest, Ops."

    att = ExtractedAttachment(
        filename="agenda.txt",
        safe_filename="agenda_txt",
        size_bytes=len(clean_bytes),
        hashes={"sha256": hashlib.sha256(clean_bytes).hexdigest()},
        file_type_inspection=FileTypeInspection(declared_extension="txt", detected_extension="txt"),
    )

    analysis = scanner.scan_attachment(att, clean_bytes)

    assert analysis.is_malicious is False
    assert analysis.threat_level == "BENIGN"
    assert analysis.threat_score == 0.0
    assert len(analysis.threat_categories) == 0
    assert len(analysis.yara_matches) == 0


def test_scan_email_end_to_end(scanner: AttachmentThreatScanner, tmp_path: Path) -> None:
    """Validate full end-to-end scanning of CanonicalEmail with multiple attachments saved to disk."""
    # Attachment 1: Malicious macro
    att1_path = tmp_path / "malicious.docm"
    att1_bytes = b"vbaProject.bin AutoOpen() ShellExecute()"
    att1_path.write_bytes(att1_bytes)

    att1 = ExtractedAttachment(
        filename="malicious.docm",
        safe_filename="malicious_docm",
        saved_path=str(att1_path),
        size_bytes=len(att1_bytes),
        hashes={"sha256": hashlib.sha256(att1_bytes).hexdigest()},
        file_type_inspection=FileTypeInspection(
            declared_extension="docm", detected_extension="docm"
        ),
    )

    # Attachment 2: Clean image
    att2_path = tmp_path / "logo.png"
    att2_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    att2_path.write_bytes(att2_bytes)

    att2 = ExtractedAttachment(
        filename="logo.png",
        safe_filename="logo_png",
        saved_path=str(att2_path),
        size_bytes=len(att2_bytes),
        hashes={"sha256": hashlib.sha256(att2_bytes).hexdigest()},
        file_type_inspection=FileTypeInspection(declared_extension="png", detected_extension="png"),
    )

    email = CanonicalEmail(
        message_id="<test-email-attachments@example.com>",
        extracted_attachments=[att1, att2],
    )

    report: AttachmentAnalysisReport = scanner.scan_email(email)

    assert report.total_attachments_scanned == 2
    assert report.malicious_attachments_count == 1
    assert report.overall_attachment_risk == "MALICIOUS"
    assert email.attachment_threat_report is report
    assert email.extracted_attachments[0].threat_analysis is not None
    assert email.extracted_attachments[0].threat_analysis.is_malicious is True
    assert email.extracted_attachments[1].threat_analysis is not None
    assert email.extracted_attachments[1].threat_analysis.is_malicious is False
