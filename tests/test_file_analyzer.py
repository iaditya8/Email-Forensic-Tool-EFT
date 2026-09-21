"""Unit test suite for FileArtifactAnalyzer and binary forensic identification models."""

import io
import struct
import tempfile
import zipfile
from pathlib import Path

import pytest

from eft.analysis.file_analyzer import (
    FileArtifactAnalyzer,
)
from eft.models.binary import (
    FileArtifactReport,
    FileFormatCategory,
)
from eft.models.threat import RiskSeverity


@pytest.fixture
def analyzer() -> FileArtifactAnalyzer:
    """Fixture providing a fresh FileArtifactAnalyzer instance."""
    return FileArtifactAnalyzer()


def _create_minimal_pe() -> bytes:
    """Create a minimal valid Windows PE byte structure."""
    buf = bytearray(128)
    buf[0:2] = b"MZ"
    # Set e_lfanew at offset 0x3C (60) to 0x40 (64)
    struct.pack_into("<I", buf, 60, 64)
    # Put 'PE\0\0' at offset 64
    buf[64:68] = b"PE\x00\x00"
    return bytes(buf)


def _create_openxml_zip(subpath: str, content: bytes = b"<xml/>") -> bytes:
    """Create in-memory ZIP simulating Microsoft Office OpenXML document."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types></Types>")
        zf.writestr(subpath, content)
    return bio.getvalue()


class TestFileAnalyzerSignatures:
    """Test standard signature matching across file format categories."""

    def test_pe_binary_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        pe_data = _create_minimal_pe()
        ident = analyzer.identify_bytes(pe_data, filename="sample.exe")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.EXECUTABLE
        assert "Portable Executable" in ident.detected_format
        assert ident.is_extension_mismatch is False
        assert ident.confidence_score >= 0.95

    def test_elf_binary_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        elf_data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32
        ident = analyzer.identify_bytes(elf_data, filename="payload.bin")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.EXECUTABLE
        assert "ELF" in ident.detected_format
        assert ident.detected_mime == "application/x-executable"

    def test_macho_binary_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        macho_data = b"\xcf\xfa\xed\xfe" + b"\x00" * 32
        ident = analyzer.identify_bytes(macho_data, filename="macho_bin")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.EXECUTABLE
        assert "Mach-O" in ident.detected_format

    def test_wasm_binary_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        wasm_data = b"\x00asm\x01\x00\x00\x00" + b"\x00" * 16
        ident = analyzer.identify_bytes(wasm_data, filename="module.wasm")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.EXECUTABLE
        assert "WebAssembly" in ident.detected_format

    def test_dex_android_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        dex_data = b"dex\n035\x00" + b"\x00" * 16
        ident = analyzer.identify_bytes(dex_data, filename="classes.dex")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.EXECUTABLE
        assert "Dalvik Executable" in ident.detected_format

    def test_pdf_document_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        pdf_data = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj<</Type/Catalog>>endobj\nxref\n0 1\ntrailer<<>>\nstartxref\n9\n%%EOF"
        ident = analyzer.identify_bytes(pdf_data, filename="report.pdf")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.DOCUMENT
        assert "PDF" in ident.detected_format
        assert ident.detected_mime == "application/pdf"
        assert ident.is_extension_mismatch is False

    def test_rtf_document_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        rtf_data = b"{\\rtf1\\ansi\\ansicpg1252\\deff0\\deflang1033{\\fonttbl{\\f0\\fnil\\fcharset0 Calibri;}}\r\n\\viewkind4\\uc1\\pard\\sa200\\sl276\\slmult1\\lang9\\f0\\fs22 Sample\\par\r\n}"
        ident = analyzer.identify_bytes(rtf_data, filename="document.rtf")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.DOCUMENT
        assert "Rich Text Format" in ident.detected_format

    def test_ole_compound_doc_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        ole_data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512
        ident = analyzer.identify_bytes(ole_data, filename="invoice.doc")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.DOCUMENT
        assert "OLE Compound Document" in ident.detected_format
        assert ident.is_extension_mismatch is False


class TestArchiveAndOpenXML:
    """Test archive and Microsoft Office OpenXML deep inspection."""

    def test_docx_openxml_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        docx_data = _create_openxml_zip("word/document.xml")
        ident = analyzer.identify_bytes(docx_data, filename="invoice.docx")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.DOCUMENT
        assert "Word OpenXML" in ident.detected_format
        assert (
            ident.detected_mime
            == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        assert ident.is_extension_mismatch is False

    def test_xlsx_openxml_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        xlsx_data = _create_openxml_zip("xl/workbook.xml")
        ident = analyzer.identify_bytes(xlsx_data, filename="payroll.xlsx")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.DOCUMENT
        assert "Excel OpenXML" in ident.detected_format
        assert ident.is_extension_mismatch is False

    def test_pptx_openxml_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        pptx_data = _create_openxml_zip("ppt/presentation.xml")
        ident = analyzer.identify_bytes(pptx_data, filename="briefing.pptx")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.DOCUMENT
        assert "PowerPoint OpenXML" in ident.detected_format
        assert ident.is_extension_mismatch is False

    def test_epub_openxml_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        epub_data = _create_openxml_zip("mimetype", b"application/epub+zip")
        ident = analyzer.identify_bytes(epub_data, filename="book.epub")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.DOCUMENT
        assert "EPUB" in ident.detected_format
        assert ident.is_extension_mismatch is False

    def test_standard_zip_archive(self, analyzer: FileArtifactAnalyzer) -> None:
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("test.txt", b"plain text")
        zip_data = bio.getvalue()

        ident = analyzer.identify_bytes(zip_data, filename="backup.zip")
        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.ARCHIVE
        assert "ZIP Archive" in ident.detected_format
        assert ident.is_extension_mismatch is False

    def test_7zip_archive_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        seven_z = b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\x00" * 32
        ident = analyzer.identify_bytes(seven_z, filename="archive.7z")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.ARCHIVE
        assert "7-Zip" in ident.detected_format

    def test_gzip_archive_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        gz_data = b"\x1f\x8b\x08\x00" + b"\x00" * 32
        ident = analyzer.identify_bytes(gz_data, filename="archive.tar.gz")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.ARCHIVE
        assert "GZIP" in ident.detected_format

    def test_rar5_archive_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        rar5_data = b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32
        ident = analyzer.identify_bytes(rar5_data, filename="payload.rar")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.ARCHIVE
        assert "RAR" in ident.detected_format


class TestMediaAndImageSignatures:
    """Test image, audio, and video container signatures."""

    def test_png_image_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 32
        ident = analyzer.identify_bytes(png_data, filename="logo.png")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.IMAGE
        assert "PNG" in ident.detected_format
        assert ident.detected_mime == "image/png"
        assert ident.is_extension_mismatch is False

    def test_jpeg_image_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        ident = analyzer.identify_bytes(jpeg_data, filename="photo.jpg")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.IMAGE
        assert "JPEG" in ident.detected_format
        assert ident.is_extension_mismatch is False

    def test_riff_webp_image_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        webp_data = b"RIFF\x20\x00\x00\x00WEBPVP8 " + b"\x00" * 32
        ident = analyzer.identify_bytes(webp_data, filename="banner.webp")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.IMAGE
        assert "WebP" in ident.detected_format
        assert ident.is_extension_mismatch is False

    def test_riff_wav_audio_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        wav_data = b"RIFF\x20\x00\x00\x00WAVEfmt " + b"\x00" * 32
        ident = analyzer.identify_bytes(wav_data, filename="voicemail.wav")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.AUDIO_VIDEO
        assert "WAV" in ident.detected_format
        assert ident.is_extension_mismatch is False

    def test_riff_avi_video_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        avi_data = b"RIFF\x20\x00\x00\x00AVI LIST" + b"\x00" * 32
        ident = analyzer.identify_bytes(avi_data, filename="recording.avi")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.AUDIO_VIDEO
        assert "AVI" in ident.detected_format
        assert ident.is_extension_mismatch is False

    def test_isobmff_mp4_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        mp4_data = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00isommp42"
        ident = analyzer.identify_bytes(mp4_data, filename="video.mp4")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.AUDIO_VIDEO
        assert "MPEG-4" in ident.detected_format
        assert ident.is_extension_mismatch is False

    def test_isobmff_heic_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        heic_data = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic"
        ident = analyzer.identify_bytes(heic_data, filename="photo.heic")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.IMAGE
        assert "HEIC" in ident.detected_format
        assert ident.is_extension_mismatch is False


class TestPlaintextAndScripts:
    """Test plaintext and script heuristics."""

    def test_html_markup_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        html_data = b"<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Hello</h1></body></html>"
        ident = analyzer.identify_bytes(html_data, filename="index.html")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.DOCUMENT
        assert "HTML" in ident.detected_format

    def test_powershell_script_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        ps1_data = b"# PowerShell forensic collector\nparam([string]$target)\nWrite-Host $target"
        ident = analyzer.identify_bytes(ps1_data, filename="collector.ps1")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.SCRIPT
        assert "Script" in ident.detected_format

    def test_batch_script_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        bat_data = b"@echo off\nset VAR=123\necho %VAR%\npause"
        ident = analyzer.identify_bytes(bat_data, filename="launcher.bat")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.SCRIPT
        assert "Script" in ident.detected_format

    def test_plaintext_detection(self, analyzer: FileArtifactAnalyzer) -> None:
        text_data = b"This is a forensic analysis report summary.\nEverything is verified clean."
        ident = analyzer.identify_bytes(text_data, filename="notes.txt")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.DOCUMENT
        assert "Plaintext" in ident.detected_format


class TestEvasionAndExtensionSpoofing:
    """Test forensic detection of extension spoofing, double extensions, RLO, and null bytes."""

    def test_pe_disguised_as_png(self, analyzer: FileArtifactAnalyzer) -> None:
        pe_data = _create_minimal_pe()
        ident = analyzer.identify_bytes(pe_data, filename="company_logo.png")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.EXECUTABLE
        assert ident.is_extension_mismatch is True
        assert ident.declared_extension == ".png"
        assert ".exe" in ident.canonical_extensions
        assert any("CRITICAL EXTENSION SPOOFING" in alert for alert in ident.forensic_alerts)

    def test_pe_disguised_as_pdf(self, analyzer: FileArtifactAnalyzer) -> None:
        pe_data = _create_minimal_pe()
        ident = analyzer.identify_bytes(pe_data, filename="Urgent_Invoice.pdf")

        assert ident.is_identified is True
        assert ident.category == FileFormatCategory.EXECUTABLE
        assert ident.is_extension_mismatch is True
        assert ident.declared_extension == ".pdf"
        assert any("CRITICAL EXTENSION SPOOFING" in alert for alert in ident.forensic_alerts)

    def test_double_extension_spoofing(self, analyzer: FileArtifactAnalyzer) -> None:
        pe_data = _create_minimal_pe()
        ident = analyzer.identify_bytes(pe_data, filename="Important_Doc.pdf.exe")

        assert ident.is_double_extension is True
        assert ident.detected_inner_extension == ".pdf"
        assert any("double-extension spoofing" in alert for alert in ident.forensic_alerts)

    def test_right_to_left_override_attack(self, analyzer: FileArtifactAnalyzer) -> None:
        # Construct filename with RLO char \u202e
        # In visual render: "malware[RLO]fdp.exe" displays as "malwareexe.pdf"
        rlo_filename = "financial_statement\u202efdp.exe"
        pe_data = _create_minimal_pe()
        ident = analyzer.identify_bytes(pe_data, filename=rlo_filename)

        assert ident.has_right_to_left_override is True
        assert ident.rlo_clean_name is not None
        assert "\u202e" not in ident.rlo_clean_name
        assert any("Right-to-Left Override" in alert for alert in ident.forensic_alerts)

    def test_null_byte_injection_attack(self, analyzer: FileArtifactAnalyzer) -> None:
        null_filename = "malware.exe\x00.pdf"
        pe_data = _create_minimal_pe()
        ident = analyzer.identify_bytes(pe_data, filename=null_filename)

        assert ident.has_null_byte_injection is True
        assert ident.declared_extension == ".exe"
        assert any("Null-byte injection" in alert for alert in ident.forensic_alerts)

    def test_unidentified_binary_with_declared_extension(
        self, analyzer: FileArtifactAnalyzer
    ) -> None:
        random_bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 10
        ident = analyzer.identify_bytes(random_bytes, filename="document.pdf")

        assert ident.is_identified is False
        assert ident.is_extension_mismatch is True
        assert ident.category == FileFormatCategory.UNKNOWN


class TestThreatScoringAndArtifactReports:
    """Test full artifact analysis reports, threat scoring, and remediation advice."""

    def test_clean_pdf_report(self, analyzer: FileArtifactAnalyzer) -> None:
        pdf_data = (
            b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\n0 1\ntrailer<<>>\nstartxref\n9\n%%EOF"
        )
        report: FileArtifactReport = analyzer.analyze_bytes(pdf_data, filename="legit_invoice.pdf")

        assert report.is_suspicious is False
        assert report.threat_severity == RiskSeverity.CLEAN
        assert report.threat_score == 0.0
        assert report.hashes["sha256"] != ""
        assert report.hashes["md5"] != ""
        assert "CLEAN" in report.summary

    def test_malicious_pe_spoofing_report(self, analyzer: FileArtifactAnalyzer) -> None:
        pe_data = _create_minimal_pe()
        report: FileArtifactReport = analyzer.analyze_bytes(
            pe_data, filename="quarterly_results.xlsx"
        )

        assert report.is_suspicious is True
        assert report.threat_severity in (RiskSeverity.MALICIOUS_HIGH, RiskSeverity.CRITICAL)
        assert report.threat_score >= 80.0
        assert any("disguised as benign" in r for r in report.remediation_advice)
        assert "CRITICAL THREAT" in report.summary

    def test_rlo_double_ext_compound_threat(self, analyzer: FileArtifactAnalyzer) -> None:
        pe_data = _create_minimal_pe()
        rlo_name = "invoice\u202efdp.exe"
        report: FileArtifactReport = analyzer.analyze_bytes(pe_data, filename=rlo_name)

        assert report.is_suspicious is True
        assert report.threat_score >= 75.0
        assert report.threat_severity == RiskSeverity.MALICIOUS_HIGH

    def test_direct_executable_attachment_report(self, analyzer: FileArtifactAnalyzer) -> None:
        pe_data = _create_minimal_pe()
        report: FileArtifactReport = analyzer.analyze_bytes(pe_data, filename="installer.exe")

        assert report.is_suspicious is True
        assert report.threat_severity in (
            RiskSeverity.SUSPICIOUS_LOW,
            RiskSeverity.SUSPICIOUS_MEDIUM,
        )
        assert report.threat_score >= 35.0

    def test_analyze_file_from_disk(self, analyzer: FileArtifactAnalyzer) -> None:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            tmp.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 32)
            tmp_path = Path(tmp.name)

        try:
            report = analyzer.analyze_file(tmp_path)
            assert report.file_path == str(tmp_path.resolve())
            assert report.identification.category == FileFormatCategory.IMAGE
            assert report.threat_severity == RiskSeverity.CLEAN
            assert report.size_bytes == 48
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_analyze_nonexistent_file_raises(self, analyzer: FileArtifactAnalyzer) -> None:
        non_existent = Path("non_existent_forensic_artifact_12345.bin")
        with pytest.raises(FileNotFoundError):
            analyzer.analyze_file(non_existent)

    def test_empty_buffer_handling(self, analyzer: FileArtifactAnalyzer) -> None:
        report = analyzer.analyze_bytes(b"", filename="empty.dat")
        assert report.identification.is_identified is False
        assert report.size_bytes == 0
        assert report.threat_score == 0.0
        assert report.threat_severity == RiskSeverity.CLEAN
