"""Unit test suite for MetadataExtractor and canonical forensic metadata models."""

import io
import struct
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from eft.analysis.metadata_extractor import MetadataExtractor
from eft.models.threat import RiskSeverity


@pytest.fixture
def extractor() -> MetadataExtractor:
    """Fixture providing a fresh MetadataExtractor instance."""
    return MetadataExtractor()


def _build_minimal_exif_jpeg(
    make: str = "Sony",
    model: str = "Alpha 7 IV",
    dt_str: str = "2023:08:15 14:30:00",
    lat_deg: float = 37.774929,
    lon_deg: float = -122.419416,
) -> bytes:
    """Construct an in-memory JPEG byte buffer with TIFF IFD0 and GPS IFD."""
    # TIFF header (Little-endian 'II')
    tiff_buf = bytearray(512)
    tiff_buf[0:2] = b"II"
    struct.pack_into("<H", tiff_buf, 2, 42)
    struct.pack_into("<I", tiff_buf, 4, 8)  # IFD0 at offset 8

    # IFD0 entries
    # 0: Make (0x010F), 1: Model (0x0110), 2: DateTime (0x0132), 3: ExifOffset (0x8769), 4: GPSOffset (0x8825)
    struct.pack_into("<H", tiff_buf, 8, 5)  # 5 entries
    pos = 10

    # Make at offset 200
    make_bytes = make.encode("utf-8") + b"\x00"
    tiff_buf[200 : 200 + len(make_bytes)] = make_bytes
    struct.pack_into("<HHI I", tiff_buf, pos, 0x010F, 2, len(make_bytes), 200)
    pos += 12

    # Model at offset 230
    model_bytes = model.encode("utf-8") + b"\x00"
    tiff_buf[230 : 230 + len(model_bytes)] = model_bytes
    struct.pack_into("<HHI I", tiff_buf, pos, 0x0110, 2, len(model_bytes), 230)
    pos += 12

    # DateTime at offset 260
    dt_bytes = dt_str.encode("utf-8") + b"\x00"
    tiff_buf[260 : 260 + len(dt_bytes)] = dt_bytes
    struct.pack_into("<HHI I", tiff_buf, pos, 0x0132, 2, len(dt_bytes), 260)
    pos += 12

    # ExifOffset -> offset 80
    struct.pack_into("<HHI I", tiff_buf, pos, 0x8769, 4, 1, 80)
    pos += 12

    # GPSOffset -> offset 120
    struct.pack_into("<HHI I", tiff_buf, pos, 0x8825, 4, 1, 120)

    # Exif IFD at offset 80 (1 entry: DateTimeOriginal 0x9003)
    struct.pack_into("<H", tiff_buf, 80, 1)
    struct.pack_into("<HHI I", tiff_buf, 82, 0x9003, 2, len(dt_bytes), 260)

    # GPS IFD at offset 120
    # 0x0001: LatRef, 0x0002: Lat (3 rationals at 300), 0x0003: LonRef, 0x0004: Lon (3 rationals at 330)
    struct.pack_into("<H", tiff_buf, 120, 4)
    gpos = 122

    # LatRef ('N' if lat_deg >= 0 else 'S')
    lat_ref = "N" if lat_deg >= 0 else "S"
    struct.pack_into("<HHI I", tiff_buf, gpos, 0x0001, 2, 2, ord(lat_ref))
    gpos += 12

    # Lat (deg, min, sec at offset 300)
    abs_lat = abs(lat_deg)
    d_lat = int(abs_lat)
    m_lat = int((abs_lat - d_lat) * 60)
    s_lat = round(((abs_lat - d_lat) * 60 - m_lat) * 60 * 100)
    struct.pack_into("<II", tiff_buf, 300, d_lat, 1)
    struct.pack_into("<II", tiff_buf, 308, m_lat, 1)
    struct.pack_into("<II", tiff_buf, 316, s_lat, 100)
    struct.pack_into("<HHI I", tiff_buf, gpos, 0x0002, 5, 3, 300)
    gpos += 12

    # LonRef ('E' if lon_deg >= 0 else 'W')
    lon_ref = "E" if lon_deg >= 0 else "W"
    struct.pack_into("<HHI I", tiff_buf, gpos, 0x0003, 2, 2, ord(lon_ref))
    gpos += 12

    # Lon (deg, min, sec at offset 330)
    abs_lon = abs(lon_deg)
    d_lon = int(abs_lon)
    m_lon = int((abs_lon - d_lon) * 60)
    s_lon = round(((abs_lon - d_lon) * 60 - m_lon) * 60 * 100)
    struct.pack_into("<II", tiff_buf, 330, d_lon, 1)
    struct.pack_into("<II", tiff_buf, 338, m_lon, 1)
    struct.pack_into("<II", tiff_buf, 346, s_lon, 100)
    struct.pack_into("<HHI I", tiff_buf, gpos, 0x0004, 5, 3, 330)

    # Wrap in JPEG APP1 segment
    app1_payload = b"Exif\x00\x00" + bytes(tiff_buf)
    app1_segment = b"\xff\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload
    jpeg_data = b"\xff\xd8" + app1_segment + b"\xff\xd9"
    return jpeg_data


def _build_openxml_doc(
    title: str = "Quarterly Forensic Report",
    creator: str = "Alice Analyst",
    last_mod_by: str = "Bob Reviewer",
    created_iso: str = "2023-09-01T09:00:00Z",
    modified_iso: str = "2023-09-01T11:30:00Z",
    revision: int = 4,
    app_name: str = "Microsoft Word",
    total_time: int = 150,
) -> bytes:
    """Build in-memory OpenXML DOCX archive with core.xml and app.xml."""
    core_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">
        <dc:title>{title}</dc:title>
        <dc:creator>{creator}</dc:creator>
        <cp:lastModifiedBy>{last_mod_by}</cp:lastModifiedBy>
        <cp:revision>{revision}</cp:revision>
        <dcterms:created>{created_iso}</dcterms:created>
        <dcterms:modified>{modified_iso}</dcterms:modified>
    </cp:coreProperties>"""

    app_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
        <Application>{app_name}</Application>
        <TotalTime>{total_time}</TotalTime>
        <Pages>12</Pages>
        <Words>3450</Words>
        <Characters>21000</Characters>
        <Company>Acme Cyber Defense Corp</Company>
    </Properties>"""

    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types></Types>")
        zf.writestr("word/document.xml", b"<w:document></w:document>")
        zf.writestr("docProps/core.xml", core_xml.encode("utf-8"))
        zf.writestr("docProps/app.xml", app_xml.encode("utf-8"))
    return bio.getvalue()


class TestImageEXIFExtraction:
    """Test image EXIF, TIFF tag parsing, and decimal GPS coordinate computation."""

    def test_jpeg_exif_and_gps_extraction(self, extractor: MetadataExtractor) -> None:
        jpeg_bytes = _build_minimal_exif_jpeg(
            make="Apple",
            model="iPhone 15 Pro",
            dt_str="2023:10:20 18:45:12",
            lat_deg=37.774929,
            lon_deg=-122.419416,
        )

        report = extractor.extract_from_bytes(jpeg_bytes, filename="evidence_photo.jpg")

        assert report.file_type == "image/jpeg"
        assert report.exif is not None
        assert report.exif.camera_make == "Apple"
        assert report.exif.camera_model == "iPhone 15 Pro"
        assert report.exif.datetime_original == datetime(
            2023, 10, 20, 18, 45, 12, tzinfo=timezone.utc
        )

        # GPS Verification
        assert report.exif.gps is not None
        assert pytest.approx(report.exif.gps.latitude, 0.001) == 37.774929
        assert pytest.approx(report.exif.gps.longitude, 0.001) == -122.419416
        assert report.exif.gps.latitude_ref == "N"
        assert report.exif.gps.longitude_ref == "W"
        assert "https://www.google.com/maps?q=" in report.exif.gps.google_maps_url
        assert f"{report.exif.gps.latitude:.4f}" == "37.7749"
        assert f"{report.exif.gps.longitude:.4f}" == "-122.4194"

    def test_png_chunk_metadata_extraction(self, extractor: MetadataExtractor) -> None:
        # Construct PNG with IHDR and tEXt chunks
        png_header = b"\x89PNG\r\n\x1a\n"
        ihdr_data = struct.pack(">IIBBBBB", 1920, 1080, 8, 6, 0, 0, 0)
        ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"

        text_payload = b"Software\x00Adobe Photoshop 2024"
        text_chunk = (
            struct.pack(">I", len(text_payload)) + b"tEXt" + text_payload + b"\x00\x00\x00\x00"
        )

        text_author = b"Author\x00Forensic Investigator"
        author_chunk = (
            struct.pack(">I", len(text_author)) + b"tEXt" + text_author + b"\x00\x00\x00\x00"
        )

        iend_chunk = struct.pack(">I", 0) + b"IEND" + b"\x00\x00\x00\x00"

        png_bytes = png_header + ihdr_chunk + text_chunk + author_chunk + iend_chunk
        report = extractor.extract_from_bytes(png_bytes, filename="screenshot.png")

        assert report.file_type == "image/png"
        assert report.exif is not None
        assert report.exif.image_width == 1920
        assert report.exif.image_height == 1080
        assert report.exif.software == "Adobe Photoshop 2024"
        assert report.exif.camera_make == "Forensic Investigator"


class TestDocumentMetadataExtraction:
    """Test Microsoft Office OpenXML metadata extraction."""

    def test_docx_openxml_metadata(self, extractor: MetadataExtractor) -> None:
        doc_bytes = _build_openxml_doc(
            title="CONFIDENTIAL INCIDENT REPORT",
            creator="Alice Threat Hunter",
            last_mod_by="Bob CISO",
            created_iso="2023-11-01T10:00:00Z",
            modified_iso="2023-11-01T14:30:00Z",
            revision=7,
            app_name="Microsoft Word 16.0",
            total_time=270,
        )

        report = extractor.extract_from_bytes(doc_bytes, filename="incident.docx")

        assert report.document is not None
        assert report.document.title == "CONFIDENTIAL INCIDENT REPORT"
        assert report.document.creator == "Alice Threat Hunter"
        assert report.document.last_modified_by == "Bob CISO"
        assert report.document.revision == 7
        assert report.document.application == "Microsoft Word 16.0"
        assert report.document.total_editing_time_minutes == 270
        assert report.document.page_count == 12
        assert report.document.word_count == 3450
        assert report.document.company == "Acme Cyber Defense Corp"
        assert report.document.created == datetime(2023, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
        assert report.document.modified == datetime(2023, 11, 1, 14, 30, 0, tzinfo=timezone.utc)
        assert report.threat_severity == RiskSeverity.CLEAN


class TestPDFStructuralAndThreatForensics:
    """Test PDF /Info catalog parsing and weaponized structural element detection."""

    def test_clean_pdf_metadata(self, extractor: MetadataExtractor) -> None:
        pdf_data = b"%PDF-1.7\n1 0 obj<</Title (Financial Report)/Author (Jane Doe)/CreationDate (D:20230615103000)/Type /Page>>endobj\nxref\n0 1\ntrailer<</Info 1 0 R>>\nstartxref\n9\n%%EOF"
        report = extractor.extract_from_bytes(pdf_data, filename="finances.pdf")

        assert report.pdf is not None
        assert report.pdf.pdf_version == "1.7"
        assert report.pdf.title == "Financial Report"
        assert report.pdf.author == "Jane Doe"
        assert report.pdf.creation_date == datetime(2023, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert report.pdf.has_javascript is False
        assert report.pdf.has_launch_action is False
        assert report.threat_severity == RiskSeverity.CLEAN

    def test_weaponized_pdf_launch_action(self, extractor: MetadataExtractor) -> None:
        pdf_data = b"%PDF-1.4\n1 0 obj<</Title (Urgent Invoice)/Type /Action/S /Launch /F (powershell.exe -enc payload)>>endobj\n%%EOF"
        report = extractor.extract_from_bytes(pdf_data, filename="invoice.pdf")

        assert report.pdf is not None
        assert report.pdf.has_launch_action is True
        assert any(a.anomaly_type == "PDF_LAUNCH_ACTION" for a in report.anomalies)
        assert report.threat_score >= 50.0
        assert report.threat_severity in (RiskSeverity.CRITICAL, RiskSeverity.MALICIOUS_HIGH)

    def test_weaponized_pdf_javascript_and_open_action(self, extractor: MetadataExtractor) -> None:
        pdf_data = b"%PDF-1.6\n1 0 obj<</OpenAction 2 0 R>>endobj\n2 0 obj<</S /JavaScript /JS (app.alert('Compromised');)>>endobj\n%%EOF"
        report = extractor.extract_from_bytes(pdf_data, filename="malicious_form.pdf")

        assert report.pdf is not None
        assert report.pdf.has_javascript is True
        assert report.pdf.has_open_action is True
        assert any(a.anomaly_type == "PDF_EMBEDDED_JAVASCRIPT" for a in report.anomalies)
        assert any(a.anomaly_type == "PDF_AUTO_EXECUTION" for a in report.anomalies)
        assert report.threat_score >= 75.0
        assert report.threat_severity in (RiskSeverity.CRITICAL, RiskSeverity.MALICIOUS_HIGH)

    def test_metasploit_producer_toolkit_detection(self, extractor: MetadataExtractor) -> None:
        pdf_data = b"%PDF-1.4\n1 0 obj<</Producer (Metasploit Framework Evil-PDF)/Creator (msfvenom)>>endobj\n%%EOF"
        report = extractor.extract_from_bytes(pdf_data, filename="exploit.pdf")

        assert report.pdf is not None
        assert any(a.anomaly_type == "EXPLOIT_TOOLKIT_ATTRIBUTION" for a in report.anomalies)
        assert report.threat_score >= 50.0


class TestMultimediaMetadataExtraction:
    """Test audio and video container metadata extraction."""

    def test_mp3_id3v2_extraction(self, extractor: MetadataExtractor) -> None:
        # Construct minimal ID3v2.3 header
        frames = bytearray()

        def _add_frame(frame_id: bytes, text: str) -> None:
            txt_bytes = b"\x00" + text.encode("latin-1")
            frames.extend(frame_id + struct.pack(">I", len(txt_bytes)) + b"\x00\x00" + txt_bytes)

        _add_frame(b"TIT2", "Forensic Voice Recording")
        _add_frame(b"TPE1", "Target Suspect")
        _add_frame(b"TALB", "Wiretap Audio Archive")
        _add_frame(b"TYER", "2024")

        id3_header = b"ID3\x03\x00\x00" + struct.pack(">I", len(frames))
        mp3_data = id3_header + bytes(frames) + b"\xff\xfb\x90\x64" + b"\x00" * 64

        report = extractor.extract_from_bytes(mp3_data, filename="wiretap.mp3")

        assert report.file_type == "audio/mpeg"
        assert report.multimedia is not None
        assert report.multimedia.title == "Forensic Voice Recording"
        assert report.multimedia.artist == "Target Suspect"
        assert report.multimedia.album == "Wiretap Audio Archive"
        assert report.multimedia.year == "2024"

    def test_direct_tiff_and_gps_timestamp(self, extractor: MetadataExtractor) -> None:
        # Construct direct Big-Endian TIFF ('MM')
        tiff_buf = bytearray(512)
        tiff_buf[0:2] = b"MM"
        struct.pack_into(">H", tiff_buf, 2, 42)
        struct.pack_into(">I", tiff_buf, 4, 8)  # IFD0

        struct.pack_into(">H", tiff_buf, 8, 3)  # 3 entries
        pos = 10

        # Make at offset 350
        make_bytes = b"Nikon\x00"
        tiff_buf[350 : 350 + len(make_bytes)] = make_bytes
        struct.pack_into(">HHII", tiff_buf, pos, 0x010F, 2, len(make_bytes), 350)
        pos += 12

        # GPSOffset -> offset 80
        struct.pack_into(">HHII", tiff_buf, pos, 0x8825, 4, 1, 80)
        pos += 12

        # Orientation (SHORT count=1)
        struct.pack_into(">HHII", tiff_buf, pos, 0x0112, 3, 1, 1 << 16)

        # GPS IFD at offset 80
        # 0x0001: LatRef ('S'), 0x0002: Lat (3 rationals at 200), 0x0003: LonRef ('E'), 0x0004: Lon (3 rationals at 230),
        # 0x0005: AltRef (1 = below sea level), 0x0006: Alt (1 rational at 260), 0x0007: GPSTimeStamp (3 rationals at 270), 0x001D: GPSDateStamp (at 300)
        struct.pack_into(">H", tiff_buf, 80, 8)
        gpos = 82

        # LatRef 'S'
        struct.pack_into(">HHII", tiff_buf, gpos, 0x0001, 2, 2, ord("S") << 24)
        gpos += 12

        # Lat 33 deg 51 min 0 sec
        struct.pack_into(">II", tiff_buf, 200, 33, 1)
        struct.pack_into(">II", tiff_buf, 208, 51, 1)
        struct.pack_into(">II", tiff_buf, 216, 0, 1)
        struct.pack_into(">HHII", tiff_buf, gpos, 0x0002, 5, 3, 200)
        gpos += 12

        # LonRef 'E'
        struct.pack_into(">HHII", tiff_buf, gpos, 0x0003, 2, 2, ord("E") << 24)
        gpos += 12

        # Lon 151 deg 12 min 0 sec
        struct.pack_into(">II", tiff_buf, 230, 151, 1)
        struct.pack_into(">II", tiff_buf, 238, 12, 1)
        struct.pack_into(">II", tiff_buf, 246, 0, 1)
        struct.pack_into(">HHII", tiff_buf, gpos, 0x0004, 5, 3, 230)
        gpos += 12

        # AltRef 1 (below sea level)
        struct.pack_into(">HHII", tiff_buf, gpos, 0x0005, 1, 1, 1 << 24)
        gpos += 12

        # Alt 15 meters
        struct.pack_into(">II", tiff_buf, 260, 15, 1)
        struct.pack_into(">HHII", tiff_buf, gpos, 0x0006, 5, 1, 260)
        gpos += 12

        # GPSTimeStamp: 12, 30, 45
        struct.pack_into(">II", tiff_buf, 270, 12, 1)
        struct.pack_into(">II", tiff_buf, 278, 30, 1)
        struct.pack_into(">II", tiff_buf, 286, 45, 1)
        struct.pack_into(">HHII", tiff_buf, gpos, 0x0007, 5, 3, 270)
        gpos += 12

        # GPSDateStamp "2024:01:15"
        date_bytes = b"2024:01:15\x00"
        tiff_buf[300 : 300 + len(date_bytes)] = date_bytes
        struct.pack_into(">HHII", tiff_buf, gpos, 0x001D, 2, len(date_bytes), 300)

        report = extractor.extract_from_bytes(bytes(tiff_buf), filename="image.tiff")

        assert report.file_type == "image/tiff"
        assert report.exif is not None
        assert report.exif.camera_make == "Nikon"
        assert report.exif.gps is not None
        assert report.exif.gps.latitude < 0  # South is negative
        assert report.exif.gps.longitude > 0  # East is positive
        assert report.exif.gps.altitude_meters == -15.0  # Below sea level
        assert report.exif.gps.timestamp_utc == datetime(
            2024, 1, 15, 12, 30, 45, tzinfo=timezone.utc
        )

    def test_png_time_and_text_chunks(self, extractor: MetadataExtractor) -> None:
        png_header = b"\x89PNG\r\n\x1a\n"
        ihdr = (
            struct.pack(">I", 13)
            + b"IHDR"
            + struct.pack(">IIBBBBB", 800, 600, 8, 2, 0, 0, 0)
            + b"\x00" * 4
        )
        time_data = struct.pack(">HBBBBB", 2024, 6, 1, 14, 20, 30)
        time_chunk = struct.pack(">I", 7) + b"tIME" + time_data + b"\x00" * 4
        text_desc = b"Description\x00Crime Scene Photo"
        text_chunk = struct.pack(">I", len(text_desc)) + b"tEXt" + text_desc + b"\x00" * 4
        iend = struct.pack(">I", 0) + b"IEND" + b"\x00" * 4

        png_data = png_header + ihdr + time_chunk + text_chunk + iend
        report = extractor.extract_from_bytes(png_data, filename="scene.png")

        assert report.exif is not None
        assert report.exif.image_width == 800
        assert report.exif.datetime_original == datetime(
            2024, 6, 1, 14, 20, 30, tzinfo=timezone.utc
        )
        assert "Description" in report.exif.raw_tags

    def test_xlsx_and_pptx_openxml_types(self, extractor: MetadataExtractor) -> None:
        # Build XLSX
        bio_xlsx = io.BytesIO()
        with zipfile.ZipFile(bio_xlsx, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", b"<Types></Types>")
            zf.writestr("xl/workbook.xml", b"<workbook/>")
            zf.writestr(
                "docProps/core.xml",
                b'<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Finance Dept</dc:creator></cp:coreProperties>',
            )
            zf.writestr(
                "docProps/custom.xml",
                b'<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"><property name="Classification">Strictly Confidential</property></Properties>',
            )
        report_xlsx = extractor.extract_from_bytes(bio_xlsx.getvalue(), filename="ledger.xlsx")
        assert "spreadsheetml" in report_xlsx.file_type
        assert report_xlsx.document is not None
        assert report_xlsx.document.creator == "Finance Dept"
        assert (
            report_xlsx.document.custom_properties.get("Classification") == "Strictly Confidential"
        )

        # Build PPTX
        bio_pptx = io.BytesIO()
        with zipfile.ZipFile(bio_pptx, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", b"<Types></Types>")
            zf.writestr("ppt/presentation.xml", b"<presentation/>")
            zf.writestr(
                "docProps/core.xml",
                b'<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Briefing Deck</dc:title></cp:coreProperties>',
            )
        report_pptx = extractor.extract_from_bytes(bio_pptx.getvalue(), filename="slides.pptx")
        assert "presentationml" in report_pptx.file_type
        assert report_pptx.document is not None
        assert report_pptx.document.title == "Briefing Deck"

    def test_pdf_embedded_files_and_encryption(self, extractor: MetadataExtractor) -> None:
        pdf_data = b"%PDF-1.7\n1 0 obj<</Encrypt 2 0 R/EmbeddedFiles 3 0 R/XFA 4 0 R>>endobj\n%%EOF"
        report = extractor.extract_from_bytes(pdf_data, filename="secure.pdf")

        assert report.pdf is not None
        assert report.pdf.is_encrypted is True
        assert report.pdf.has_embedded_files is True
        assert any("embedded file payload" in s.lower() for s in report.pdf.suspicious_elements)

    def test_mp3_id3v1_only_trailer(self, extractor: MetadataExtractor) -> None:
        # Construct pure ID3v1 128 byte trailer
        payload = b"\x00" * 1024
        v1_trailer = bytearray(128)
        v1_trailer[0:3] = b"TAG"
        v1_trailer[3:33] = b"Retro Track                   "
        v1_trailer[33:63] = b"Synthwave Artist              "
        v1_trailer[63:93] = b"Cyber Album                   "
        v1_trailer[93:97] = b"1984"
        v1_data = payload + bytes(v1_trailer)

        report = extractor.extract_from_bytes(v1_data, filename="track.mp3")

        assert report.multimedia is not None
        assert report.multimedia.title == "Retro Track"
        assert report.multimedia.artist == "Synthwave Artist"
        assert report.multimedia.album == "Cyber Album"
        assert report.multimedia.year == "1984"

    def test_mp4_isobmff_duration_extraction(self, extractor: MetadataExtractor) -> None:
        # Build minimal MP4 container with ftyp, moov, and mvhd
        ftyp_data = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00isommp42"

        # mvhd box: timescale = 1000, duration = 65400 ticks (65.4 seconds)
        mvhd_payload = bytearray(100)
        struct.pack_into(">I", mvhd_payload, 12, 1000)  # timescale (offset 16 of box)
        struct.pack_into(">I", mvhd_payload, 16, 65400)  # duration (offset 20 of box)
        mvhd_box = struct.pack(">I", len(mvhd_payload) + 8) + b"mvhd" + bytes(mvhd_payload)

        moov_box = struct.pack(">I", len(mvhd_box) + 8) + b"moov" + mvhd_box
        mp4_data = ftyp_data + moov_box

        report = extractor.extract_from_bytes(mp4_data, filename="movie.mp4")

        assert report.file_type == "video/mp4"
        assert report.multimedia is not None
        assert report.multimedia.duration_seconds == 65.4


class TestTemporalAnomaliesAndFileOperations:
    """Test timestamp tampering, temporal inversion, and disk file analysis."""

    def test_temporal_inversion_anomaly(self, extractor: MetadataExtractor) -> None:
        # Modified earlier than created
        doc_bytes = _build_openxml_doc(
            created_iso="2023-12-01T15:00:00Z",
            modified_iso="2023-11-01T10:00:00Z",  # Earlier
        )

        report = extractor.extract_from_bytes(doc_bytes, filename="tampered.docx")

        assert any(a.anomaly_type == "TEMPORAL_INVERSION" for a in report.anomalies)
        assert report.threat_score >= 20.0

    def test_anachronistic_and_future_timestamps(self, extractor: MetadataExtractor) -> None:
        doc_bytes = _build_openxml_doc(
            created_iso="1972-05-10T08:00:00Z",  # Pre-1980
            modified_iso="2099-01-01T00:00:00Z",  # Far future
        )

        report = extractor.extract_from_bytes(doc_bytes, filename="time_travel.docx")

        assert any(a.anomaly_type == "ANACHRONISTIC_TIMESTAMP" for a in report.anomalies)
        assert report.threat_score >= 20.0

    def test_extract_from_disk_file(self, extractor: MetadataExtractor) -> None:
        jpeg_bytes = _build_minimal_exif_jpeg(make="Canon", model="EOS R5")
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            tmp.write(jpeg_bytes)
            tmp_path = Path(tmp.name)

        try:
            report = extractor.extract_from_file(tmp_path)
            assert report.file_path == str(tmp_path.resolve())
            assert report.exif is not None
            assert report.exif.camera_make == "Canon"
            assert report.exif.camera_model == "EOS R5"
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_extract_nonexistent_file_raises(self, extractor: MetadataExtractor) -> None:
        non_existent = Path("non_existent_metadata_artifact_9999.jpg")
        with pytest.raises(FileNotFoundError):
            extractor.extract_from_file(non_existent)
