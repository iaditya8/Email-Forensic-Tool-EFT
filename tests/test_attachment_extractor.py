"""Unit tests for forensic attachment extraction, fingerprinting, and magic byte inspection."""

import hashlib
from pathlib import Path

from eft.ingestion.attachment_extractor import AttachmentExtractor
from eft.models.canonical import AttachmentMetadata, CanonicalEmail


def test_sanitize_filename_edge_cases():
    """Test path traversal prevention, null byte stripping, and reserved name handling."""
    # 1. Empty or None filenames
    assert AttachmentExtractor.sanitize_filename(None, index=0) == "attachment_0.dat"
    assert AttachmentExtractor.sanitize_filename("", index=3) == "attachment_3.dat"
    assert AttachmentExtractor.sanitize_filename("   ", index=5) == "attachment_5.dat"

    # 2. Unix & Windows Path Traversal
    assert AttachmentExtractor.sanitize_filename("../../../../etc/passwd") == "passwd"
    assert AttachmentExtractor.sanitize_filename(r"..\..\..\Windows\System32\cmd.exe") == "cmd.exe"
    assert AttachmentExtractor.sanitize_filename(r"C:\Users\Admin\secrets.docx") == "secrets.docx"
    assert AttachmentExtractor.sanitize_filename("/var/mail/inbox.eml") == "inbox.eml"

    # 3. Windows Reserved Device Names
    assert AttachmentExtractor.sanitize_filename("CON.txt") == "_CON.txt"
    assert AttachmentExtractor.sanitize_filename("prn.pdf") == "_prn.pdf"
    assert AttachmentExtractor.sanitize_filename("aux.png") == "_aux.png"
    assert AttachmentExtractor.sanitize_filename("NUL") == "_NUL"
    assert AttachmentExtractor.sanitize_filename("com1.dat") == "_com1.dat"

    # 4. Null bytes and control characters
    assert AttachmentExtractor.sanitize_filename("malicious\x00file\r\n.pdf") == "maliciousfile.pdf"

    # 5. Filesystem illegal characters (< > : " / \ | ? *)
    assert (
        AttachmentExtractor.sanitize_filename('report<2024>:final"v1*?.pdf')
        == "report_2024__final_v1__.pdf"
    )

    # 6. Very long filename length boundary (<= 255 chars, preserving extension)
    long_name = "a" * 300 + ".pdf"
    sanitized_long = AttachmentExtractor.sanitize_filename(long_name)
    assert len(sanitized_long) <= 255
    assert sanitized_long.endswith(".pdf")


def test_magic_byte_inspection_benign_pdf():
    """Test magic byte inspection of a legitimate PDF document."""
    pdf_payload = b"%PDF-1.7\n3 0 obj\n<< /Type /Catalog >>\nendobj\n"
    inspection = AttachmentExtractor.inspect_payload(
        data=pdf_payload,
        declared_filename="invoice_2024.pdf",
        declared_content_type="application/pdf",
    )

    assert inspection.detected_extension == ".pdf"
    assert inspection.detected_mime_type == "application/pdf"
    assert inspection.is_extension_mismatch is False
    assert inspection.risk_level == "BENIGN"
    assert len(inspection.risk_reasons) == 0


def test_magic_byte_inspection_benign_images():
    """Test magic byte inspection for PNG and JPEG images."""
    png_payload = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    png_insp = AttachmentExtractor.inspect_payload(
        data=png_payload,
        declared_filename="screenshot.png",
        declared_content_type="image/png",
    )
    assert png_insp.detected_extension == ".png"
    assert png_insp.detected_mime_type == "image/png"
    assert png_insp.risk_level == "BENIGN"

    jpeg_payload = b"\xff\xd8\xff\xe0\x00\x10JFIF"
    jpeg_insp = AttachmentExtractor.inspect_payload(
        data=jpeg_payload,
        declared_filename="photo.jpg",
        declared_content_type="image/jpeg",
    )
    assert jpeg_insp.detected_extension == ".jpg"
    assert jpeg_insp.detected_mime_type == "image/jpeg"
    assert jpeg_insp.risk_level == "BENIGN"


def test_extension_spoofing_executable_as_pdf():
    """Test detection of Windows PE executable (.exe) masquerading as .pdf (CRITICAL)."""
    pe_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode."
    inspection = AttachmentExtractor.inspect_payload(
        data=pe_payload,
        declared_filename="court_summons.pdf",
        declared_content_type="application/pdf",
    )

    assert inspection.detected_extension == ".exe"
    assert inspection.detected_mime_type == "application/x-dosexec"
    assert inspection.is_extension_mismatch is True
    assert inspection.risk_level == "CRITICAL"
    assert any("CRITICAL EXTENSION SPOOFING" in reason for reason in inspection.risk_reasons)


def test_extension_spoofing_elf_as_docx():
    """Test detection of Linux ELF binary masquerading as .docx (CRITICAL)."""
    elf_payload = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    inspection = AttachmentExtractor.inspect_payload(
        data=elf_payload,
        declared_filename="confidential_contract.docx",
        declared_content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )

    assert inspection.detected_extension == ".elf"
    assert inspection.is_extension_mismatch is True
    assert inspection.risk_level == "CRITICAL"


def test_direct_dangerous_extension():
    """Test flagging of direct high-risk executable script extensions (e.g. .ps1, .bat)."""
    script_payload = b"Write-Host 'powershell payload executed'"
    inspection = AttachmentExtractor.inspect_payload(
        data=script_payload,
        declared_filename="run_patch.ps1",
        declared_content_type="text/plain",
    )

    assert inspection.risk_level == "HIGH"
    assert any(
        "high-risk executable or script extension" in reason for reason in inspection.risk_reasons
    )


def test_double_extension_detection():
    """Test detection of deceptive double extensions (e.g. invoice.pdf.exe)."""
    payload = b"MZ\x90\x00fake pe payload"
    inspection = AttachmentExtractor.inspect_payload(
        data=payload,
        declared_filename="invoice_march.pdf.exe",
        declared_content_type="application/octet-stream",
    )

    assert inspection.risk_level == "CRITICAL"
    assert any("Deceptive double extension" in reason for reason in inspection.risk_reasons)


def test_extract_attachment_in_memory():
    """Test extracting and fingerprinting an in-memory attachment without disk writes."""
    payload = b"%PDF-1.4 header text body trailer"
    att_meta = AttachmentMetadata(
        filename="financial_report.pdf",
        content_type="application/pdf",
        size_bytes=len(payload),
        raw_data=payload,
    )

    extracted = AttachmentExtractor.extract_attachment(
        attachment=att_meta,
        index=0,
        save_to_disk=False,
    )

    assert extracted.safe_filename == "financial_report.pdf"
    assert extracted.saved_path is None
    assert extracted.size_bytes == len(payload)
    assert extracted.hashes["md5"] == hashlib.md5(payload).hexdigest()
    assert extracted.hashes["sha1"] == hashlib.sha1(payload).hexdigest()
    assert extracted.hashes["sha256"] == hashlib.sha256(payload).hexdigest()
    assert extracted.file_type_inspection.risk_level == "BENIGN"


def test_extract_attachment_to_disk(tmp_path: Path):
    """Test saving extracted attachment to isolated filesystem directory."""
    payload = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    att_meta = AttachmentMetadata(
        filename="malicious/path/../../diagram.png",
        content_type="image/png",
        size_bytes=len(payload),
        raw_data=payload,
    )

    extracted = AttachmentExtractor.extract_attachment(
        attachment=att_meta,
        output_dir=tmp_path,
        index=2,
        save_to_disk=True,
    )

    assert extracted.safe_filename == "diagram.png"
    assert extracted.saved_path is not None
    saved_file = Path(extracted.saved_path)
    assert saved_file.is_file()
    assert saved_file.read_bytes() == payload
    assert saved_file.name == "02_diagram.png"


def test_extract_from_email():
    """Test batch extraction and risk analysis from a CanonicalEmail instance."""
    clean_pdf = b"%PDF-1.4 benign"
    malicious_pe = b"MZ\x00\x00 dangerous pe disguised as photo"

    email = CanonicalEmail(
        message_id="<test1234@evidence.local>",
        subject="Forensic Attachment Test",
        attachments=[
            AttachmentMetadata(
                filename="legit.pdf",
                content_type="application/pdf",
                raw_data=clean_pdf,
            ),
            AttachmentMetadata(
                filename="family_photo.jpg",
                content_type="image/jpeg",
                raw_data=malicious_pe,
            ),
        ],
    )

    results = AttachmentExtractor.extract_from_email(email)

    assert len(results) == 2
    assert len(email.extracted_attachments) == 2

    # Verify first attachment (clean PDF)
    assert results[0].safe_filename == "legit.pdf"
    assert results[0].file_type_inspection.risk_level == "BENIGN"

    # Verify second attachment (spoofed PE)
    assert results[1].safe_filename == "family_photo.jpg"
    assert results[1].file_type_inspection.risk_level == "CRITICAL"
    assert results[1].file_type_inspection.is_extension_mismatch is True
