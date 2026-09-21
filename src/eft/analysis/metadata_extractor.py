"""Forensic EXIF, Document, PDF, and Multimedia Metadata Extraction Engine.

Extracts author attribution, GPS coordinates, camera parameters, editing history,
and detects weaponized elements (PDF /Launch, /JavaScript, /EmbeddedFiles, temporal tampering).
"""

from __future__ import annotations

import io
import logging
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from eft.models.metadata import (
    AudioVideoMetadata,
    DocumentMetadata,
    ExtractedMetadataReport,
    GPSCoordinates,
    ImageEXIFMetadata,
    MetadataAnomaly,
    PDFStructureMetadata,
)
from eft.models.threat import RiskSeverity

logger = logging.getLogger(__name__)

# Known exploit tools and weaponization frameworks appearing in metadata
SUSPICIOUS_PRODUCERS: List[str] = [
    "metasploit",
    "msfvenom",
    "evil-pdf",
    "cobalt",
    "empire",
    "pdfstreamdumper",
    "setoolkit",
    "veil",
    "msoffice-crypt",
    "exploit",
    "payload",
]

# PDF active execution indicators
PDF_WEAPONIZED_TOKENS: Dict[str, str] = {
    "/Launch": "Arbitrary OS command launch action (/Launch)",
    "/JavaScript": "Embedded executable JavaScript stream (/JavaScript)",
    "/JS": "Embedded compact JavaScript stream (/JS)",
    "/EmbeddedFiles": "Hidden embedded file payload container (/EmbeddedFiles)",
    "/OpenAction": "Automatic execution trigger on document opening (/OpenAction)",
    "/AA": "Additional automatic event actions trigger (/AA)",
    "/RichMedia": "Flash/ActiveX rich media container (/RichMedia)",
    "/XFA": "Dynamic XML Forms Architecture with scripting capability (/XFA)",
}


class MetadataExtractor:
    """Enterprise-grade forensic metadata extraction and structural anomaly inspector."""

    def extract_from_bytes(
        self,
        data: bytes,
        filename: str = "evidence.bin",
    ) -> ExtractedMetadataReport:
        """Inspect and extract metadata from in-memory byte buffer."""
        file_ext = Path(filename).suffix.lower() if "." in filename else ""
        exif_meta: Optional[ImageEXIFMetadata] = None
        doc_meta: Optional[DocumentMetadata] = None
        pdf_meta: Optional[PDFStructureMetadata] = None
        media_meta: Optional[AudioVideoMetadata] = None
        anomalies: List[MetadataAnomaly] = []
        detected_type = "unknown"

        # 1. JPEG / TIFF EXIF
        if (
            data.startswith(b"\xff\xd8")
            or data.startswith(b"II*\x00")
            or data.startswith(b"MM\x00*")
        ):
            detected_type = "image/jpeg" if data.startswith(b"\xff\xd8") else "image/tiff"
            exif_meta = self._extract_jpeg_tiff_exif(data)

        # 2. PNG Chunk Metadata
        elif data.startswith(b"\x89PNG\r\n\x1a\n"):
            detected_type = "image/png"
            exif_meta = self._extract_png_metadata(data)

        # 3. Microsoft Office OpenXML (.docx, .xlsx, .pptx)
        elif data.startswith(b"PK\x03\x04"):
            doc_meta, doc_type = self._extract_openxml_metadata(data)
            if doc_meta:
                detected_type = doc_type

        # 4. Adobe PDF Structure & Active Elements
        elif data.startswith(b"%PDF"):
            detected_type = "application/pdf"
            pdf_meta = self._extract_pdf_metadata(data)

        # 5. Audio: MP3 ID3
        elif data.startswith(b"ID3") or (len(data) >= 128 and data[-128:-125] == b"TAG"):
            detected_type = "audio/mpeg"
            media_meta = self._extract_mp3_metadata(data)

        # 6. Video / Audio: MP4 / QuickTime ISO-BMFF
        elif len(data) >= 8 and data[4:8] == b"ftyp":
            detected_type = "video/mp4"
            media_meta = self._extract_isobmff_metadata(data)

        # 7. Audio: RIFF WAV
        elif data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WAVE":
            detected_type = "audio/wav"
            media_meta = self._extract_riff_wav_metadata(data)

        # Evaluate forensic anomalies across all extracted components
        self._evaluate_anomalies(
            exif=exif_meta,
            doc=doc_meta,
            pdf=pdf_meta,
            media=media_meta,
            anomalies=anomalies,
        )

        # Threat Scoring Logic
        threat_score, threat_severity, summary = self._score_metadata_threats(
            filename=filename,
            anomalies=anomalies,
            pdf=pdf_meta,
            doc=doc_meta,
            exif=exif_meta,
        )

        return ExtractedMetadataReport(
            file_path=None,
            filename=filename,
            file_type=detected_type if detected_type != "unknown" else file_ext or "binary",
            exif=exif_meta,
            document=doc_meta,
            pdf=pdf_meta,
            multimedia=media_meta,
            anomalies=anomalies,
            threat_score=threat_score,
            threat_severity=threat_severity,
            summary=summary,
        )

    def extract_from_file(
        self,
        file_path: Union[str, Path],
    ) -> ExtractedMetadataReport:
        """Inspect and extract metadata directly from a file path."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Evidence file not found: {path}")

        data = path.read_bytes()
        report = self.extract_from_bytes(data, filename=path.name)
        report.file_path = str(path)
        return report

    # =========================================================================
    # Internal Parsers: Image EXIF & TIFF
    # =========================================================================

    def _extract_jpeg_tiff_exif(self, data: bytes) -> Optional[ImageEXIFMetadata]:
        """Parse EXIF/TIFF IFD tags and compute decimal GPS coordinates."""
        try:
            tiff_bytes: Optional[bytes] = None

            if data.startswith(b"\xff\xd8"):
                # Scan JPEG APP1 segment
                pos = 2
                while pos < len(data) - 4:
                    if data[pos] != 0xFF:
                        pos += 1
                        continue
                    marker = data[pos + 1]
                    if marker in (0xDA, 0xD9):  # Start of Scan or End of Image
                        break
                    if pos + 4 > len(data):
                        break
                    length = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
                    if marker == 0xE1:  # APP1
                        app1_data = data[pos + 4 : pos + 2 + length]
                        if app1_data.startswith(b"Exif\x00\x00"):
                            tiff_bytes = app1_data[6:]
                            break
                    pos += 2 + length
            elif data.startswith(b"II*\x00") or data.startswith(b"MM\x00*"):
                tiff_bytes = data

            if not tiff_bytes or len(tiff_bytes) < 8:
                return None

            endian_str = "<" if tiff_bytes[:2] == b"II" else ">"
            if struct.unpack(f"{endian_str}H", tiff_bytes[2:4])[0] != 42:
                return None

            ifd0_offset = struct.unpack(f"{endian_str}I", tiff_bytes[4:8])[0]
            tags = self._parse_tiff_ifd(tiff_bytes, ifd0_offset, endian_str)

            # Check for Exif IFD pointer (0x8769)
            if 0x8769 in tags and isinstance(tags[0x8769], int):
                exif_ifd = self._parse_tiff_ifd(tiff_bytes, tags[0x8769], endian_str)
                tags.update(exif_ifd)

            # Check for GPS IFD pointer (0x8825)
            gps_coords: Optional[GPSCoordinates] = None
            if 0x8825 in tags and isinstance(tags[0x8825], int):
                gps_ifd = self._parse_tiff_ifd(tiff_bytes, tags[0x8825], endian_str)
                gps_coords = self._parse_gps_ifd(gps_ifd)

            # Map standard EXIF tags
            make = str(tags.get(0x010F, "")).strip() or None
            model = str(tags.get(0x0110, "")).strip() or None
            software = str(tags.get(0x0131, "")).strip() or None
            lens = str(tags.get(0xA434, "")).strip() or None

            dt_orig_raw = tags.get(0x9003) or tags.get(0x0132)
            dt_orig = self._parse_exif_datetime(dt_orig_raw) if dt_orig_raw else None

            dt_dig_raw = tags.get(0x9004)
            dt_dig = self._parse_exif_datetime(dt_dig_raw) if dt_dig_raw else None

            width = tags.get(0xA002) or tags.get(0x0100)
            height = tags.get(0xA003) or tags.get(0x0101)
            orientation = tags.get(0x0112)
            iso = tags.get(0x8827)

            f_num_val = tags.get(0x829D)
            f_number = float(f_num_val) if isinstance(f_num_val, (int, float)) else None

            focal_val = tags.get(0x920A)
            focal_length = float(focal_val) if isinstance(focal_val, (int, float)) else None

            exp_val = tags.get(0x829A)
            exposure_time = (
                f"1/{round(1.0 / exp_val)}s"
                if isinstance(exp_val, float) and 0 < exp_val < 1
                else str(exp_val)
                if exp_val
                else None
            )

            raw_dict = {f"0x{k:04X}": str(v) for k, v in tags.items()}

            return ImageEXIFMetadata(
                camera_make=make,
                camera_model=model,
                lens_model=lens,
                software=software,
                datetime_original=dt_orig,
                datetime_digitized=dt_dig,
                image_width=int(width) if isinstance(width, (int, float)) else None,
                image_height=int(height) if isinstance(height, (int, float)) else None,
                color_space="sRGB" if tags.get(0xA001) == 1 else None,
                orientation=int(orientation) if isinstance(orientation, int) else None,
                iso_speed=int(iso) if isinstance(iso, int) else None,
                exposure_time=exposure_time,
                f_number=f_number,
                focal_length_mm=focal_length,
                gps=gps_coords,
                raw_tags=raw_dict,
            )
        except Exception as e:
            logger.debug("Failed parsing EXIF structure: %s", e)
            return None

    def _parse_tiff_ifd(self, tiff: bytes, offset: int, endian: str) -> Dict[int, Any]:
        """Parse TIFF Image File Directory entries."""
        tags: Dict[int, Any] = {}
        if offset + 2 > len(tiff):
            return tags
        num_entries = struct.unpack(f"{endian}H", tiff[offset : offset + 2])[0]
        pos = offset + 2

        for _ in range(num_entries):
            if pos + 12 > len(tiff):
                break
            tag, tag_type, count, val_or_offset = struct.unpack(
                f"{endian}HHII", tiff[pos : pos + 12]
            )
            pos += 12

            val = self._resolve_tiff_value(tiff, tag_type, count, val_or_offset, endian)
            if val is not None:
                tags[tag] = val
        return tags

    def _resolve_tiff_value(
        self, tiff: bytes, tag_type: int, count: int, val_offset: int, endian: str
    ) -> Any:
        """Resolve TIFF tag value based on type definition and byte offset."""
        try:
            # 1: BYTE, 2: ASCII, 3: SHORT, 4: LONG, 5: RATIONAL
            if tag_type == 2:  # ASCII
                if count <= 4:
                    raw_ascii = struct.pack(f"{endian}I", val_offset)[:count]
                elif val_offset + count <= len(tiff):
                    raw_ascii = tiff[val_offset : val_offset + count]
                else:
                    return None
                return raw_ascii.decode("utf-8", errors="ignore").rstrip("\x00").strip()

            elif tag_type == 3:  # SHORT
                if count == 1:
                    packed = struct.pack(f"{endian}I", val_offset)
                    return struct.unpack(f"{endian}H", packed[:2])[0]
                elif val_offset + (count * 2) <= len(tiff):
                    return [
                        struct.unpack(
                            f"{endian}H", tiff[val_offset + i * 2 : val_offset + (i + 1) * 2]
                        )[0]
                        for i in range(count)
                    ]

            elif tag_type == 4:  # LONG
                if count == 1:
                    return val_offset
                elif val_offset + (count * 4) <= len(tiff):
                    return [
                        struct.unpack(
                            f"{endian}I", tiff[val_offset + i * 4 : val_offset + (i + 1) * 4]
                        )[0]
                        for i in range(count)
                    ]

            elif tag_type == 5:  # RATIONAL (numerator/denominator)
                if val_offset + 8 <= len(tiff):
                    if count == 1:
                        num, den = struct.unpack(f"{endian}II", tiff[val_offset : val_offset + 8])
                        return (num / den) if den != 0 else 0.0
                    else:
                        res = []
                        for i in range(count):
                            sub = val_offset + (i * 8)
                            if sub + 8 <= len(tiff):
                                num, den = struct.unpack(f"{endian}II", tiff[sub : sub + 8])
                                res.append((num / den) if den != 0 else 0.0)
                        return res
            elif tag_type == 1:  # BYTE
                packed = struct.pack(f"{endian}I", val_offset)
                return packed[0]
        except Exception:
            pass
        return None

    def _parse_gps_ifd(self, gps_tags: Dict[int, Any]) -> Optional[GPSCoordinates]:
        """Convert GPS IFD tags to decimal coordinates and Google Maps URL."""
        try:
            lat_ref = str(gps_tags.get(0x0001, "N")).upper().strip()
            lat_vals = gps_tags.get(0x0002)
            lon_ref = str(gps_tags.get(0x0003, "E")).upper().strip()
            lon_vals = gps_tags.get(0x0004)

            if not lat_vals or not lon_vals or len(lat_vals) < 3 or len(lon_vals) < 3:
                return None

            lat_dec = (
                float(lat_vals[0]) + (float(lat_vals[1]) / 60.0) + (float(lat_vals[2]) / 3600.0)
            )
            if lat_ref == "S":
                lat_dec = -lat_dec

            lon_dec = (
                float(lon_vals[0]) + (float(lon_vals[1]) / 60.0) + (float(lon_vals[2]) / 3600.0)
            )
            if lon_ref == "W":
                lon_dec = -lon_dec

            alt_val = gps_tags.get(0x0006)
            alt_ref = gps_tags.get(0x0005, 0)
            alt_meters = float(alt_val) if isinstance(alt_val, (int, float)) else None
            if alt_meters is not None and alt_ref == 1:
                alt_meters = -alt_meters

            # Construct clickable Google Maps link
            maps_url = f"https://www.google.com/maps?q={lat_dec:.6f},{lon_dec:.6f}"

            # GPS Timestamp
            gps_dt: Optional[datetime] = None
            date_stamp = gps_tags.get(0x001D)
            time_stamp = gps_tags.get(0x0007)
            if date_stamp and time_stamp and len(time_stamp) >= 3:
                try:
                    ds = str(date_stamp).replace(":", "-").strip()
                    h, m, s = int(time_stamp[0]), int(time_stamp[1]), int(time_stamp[2])
                    gps_dt = datetime.strptime(
                        f"{ds} {h:02d}:{m:02d}:{s:02d}", "%Y-%m-%d %H:%M:%S"
                    ).replace(tzinfo=timezone.utc)
                except Exception:
                    pass

            return GPSCoordinates(
                latitude=round(lat_dec, 6),
                longitude=round(lon_dec, 6),
                altitude_meters=round(alt_meters, 2) if alt_meters is not None else None,
                latitude_ref=lat_ref,
                longitude_ref=lon_ref,
                google_maps_url=maps_url,
                timestamp_utc=gps_dt,
            )
        except Exception:
            return None

    def _parse_exif_datetime(self, val: Any) -> Optional[datetime]:
        """Parse standard EXIF datetime string 'YYYY:MM:DD HH:MM:SS'."""
        try:
            s = str(val).strip()
            match = re.match(r"^(\d{4})[:\-](\d{2})[:\-](\d{2})\s+(\d{2}):(\d{2}):(\d{2})", s)
            if match:
                y, m, d, hh, mm, ss = (int(x) for x in match.groups())
                return datetime(y, m, d, hh, mm, ss, tzinfo=timezone.utc)
        except Exception:
            pass
        return None

    # =========================================================================
    # Internal Parsers: PNG Chunk Metadata
    # =========================================================================

    def _extract_png_metadata(self, data: bytes) -> Optional[ImageEXIFMetadata]:
        """Parse PNG text and timestamp chunks (tEXt, iTXt, tIME, IHDR)."""
        try:
            pos = 8
            raw_tags: Dict[str, Any] = {}
            width: Optional[int] = None
            height: Optional[int] = None
            dt_created: Optional[datetime] = None
            software: Optional[str] = None
            make: Optional[str] = None
            model: Optional[str] = None

            while pos + 8 <= len(data):
                chunk_len = struct.unpack(">I", data[pos : pos + 4])[0]
                chunk_type = data[pos + 4 : pos + 8]
                pos += 8
                if pos + chunk_len > len(data):
                    break
                chunk_data = data[pos : pos + chunk_len]
                pos += chunk_len + 4  # Skip CRC

                if chunk_type == b"IHDR" and len(chunk_data) >= 8:
                    width, height = struct.unpack(">II", chunk_data[:8])

                elif chunk_type == b"tIME" and len(chunk_data) >= 7:
                    y, m, d, hh, mm, ss = struct.unpack(">HBBBBB", chunk_data[:7])
                    try:
                        dt_created = datetime(y, m, d, hh, mm, ss, tzinfo=timezone.utc)
                    except Exception:
                        pass

                elif chunk_type == b"tEXt":
                    parts = chunk_data.split(b"\x00", 1)
                    if len(parts) == 2:
                        k = parts[0].decode("utf-8", errors="ignore").strip()
                        v = parts[1].decode("utf-8", errors="ignore").strip()
                        raw_tags[k] = v
                        if k.lower() == "software":
                            software = v
                        elif k.lower() == "author":
                            make = v
                        elif k.lower() in ("creation time", "date"):
                            if not dt_created:
                                dt_created = self._parse_exif_datetime(v)

            if not raw_tags and not dt_created and not width:
                return None

            return ImageEXIFMetadata(
                camera_make=make,
                camera_model=model,
                software=software,
                datetime_original=dt_created,
                image_width=width,
                image_height=height,
                raw_tags=raw_dict if (raw_dict := {k: str(v) for k, v in raw_tags.items()}) else {},
            )
        except Exception:
            return None

    # =========================================================================
    # Internal Parsers: Microsoft Office OpenXML (.docx, .xlsx, .pptx)
    # =========================================================================

    def _extract_openxml_metadata(self, data: bytes) -> Tuple[Optional[DocumentMetadata], str]:
        """Extract core.xml, app.xml, and custom.xml properties from Office OpenXML archive."""
        doc_type = "application/vnd.openxmlformats-officedocument"
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                namelist = set(zf.namelist())
                if any(n.startswith("word/") for n in namelist):
                    doc_type = (
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    )
                elif any(n.startswith("xl/") for n in namelist):
                    doc_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                elif any(n.startswith("ppt/") for n in namelist):
                    doc_type = (
                        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                    )

                title: Optional[str] = None
                subject: Optional[str] = None
                creator: Optional[str] = None
                last_mod_by: Optional[str] = None
                created: Optional[datetime] = None
                modified: Optional[datetime] = None
                revision: Optional[int] = None
                app: Optional[str] = None
                app_version: Optional[str] = None
                total_time: Optional[int] = None
                pages: Optional[int] = None
                words: Optional[int] = None
                characters: Optional[int] = None
                company: Optional[str] = None
                custom_props: Dict[str, str] = {}

                # 1. docProps/core.xml (Dublin Core & OpenXML Core)
                if "docProps/core.xml" in namelist:
                    core_xml = zf.read("docProps/core.xml")
                    try:
                        root = ET.fromstring(core_xml)
                        for elem in root:
                            tag_local = (
                                elem.tag.split("}")[-1].lower()
                                if "}" in elem.tag
                                else elem.tag.lower()
                            )
                            text = (elem.text or "").strip()
                            if tag_local == "title" and text:
                                title = text
                            elif tag_local == "subject" and text:
                                subject = text
                            elif tag_local == "creator" and text:
                                creator = text
                            elif tag_local == "lastmodifiedby" and text:
                                last_mod_by = text
                            elif tag_local == "revision" and text:
                                try:
                                    revision = int(text)
                                except ValueError:
                                    pass
                            elif tag_local == "created" and text:
                                created = self._parse_iso8601_date(text)
                            elif tag_local == "modified" and text:
                                modified = self._parse_iso8601_date(text)
                    except Exception as e:
                        logger.debug("Failed parsing docProps/core.xml: %s", e)

                # 2. docProps/app.xml (Extended Application Properties)
                if "docProps/app.xml" in namelist:
                    app_xml = zf.read("docProps/app.xml")
                    try:
                        root = ET.fromstring(app_xml)
                        for elem in root:
                            tag_local = (
                                elem.tag.split("}")[-1].lower()
                                if "}" in elem.tag
                                else elem.tag.lower()
                            )
                            text = (elem.text or "").strip()
                            if tag_local == "application" and text:
                                app = text
                            elif tag_local == "appversion" and text:
                                app_version = text
                            elif tag_local == "totaltime" and text:
                                try:
                                    total_time = int(text)
                                except ValueError:
                                    pass
                            elif tag_local == "pages" and text:
                                try:
                                    pages = int(text)
                                except ValueError:
                                    pass
                            elif tag_local == "words" and text:
                                try:
                                    words = int(text)
                                except ValueError:
                                    pass
                            elif tag_local == "characters" and text:
                                try:
                                    characters = int(text)
                                except ValueError:
                                    pass
                            elif tag_local == "company" and text:
                                company = text
                    except Exception as e:
                        logger.debug("Failed parsing docProps/app.xml: %s", e)

                # 3. docProps/custom.xml
                if "docProps/custom.xml" in namelist:
                    custom_xml = zf.read("docProps/custom.xml")
                    try:
                        root = ET.fromstring(custom_xml)
                        for elem in root:
                            name = elem.attrib.get("name")
                            if name:
                                val_text = "".join(elem.itertext()).strip()
                                custom_props[name] = val_text
                    except Exception:
                        pass

                return DocumentMetadata(
                    title=title,
                    subject=subject,
                    creator=creator,
                    last_modified_by=last_mod_by,
                    created=created,
                    modified=modified,
                    revision=revision,
                    application=app,
                    app_version=app_version,
                    total_editing_time_minutes=total_time,
                    page_count=pages,
                    word_count=words,
                    character_count=characters,
                    company=company,
                    custom_properties=custom_props,
                ), doc_type
        except Exception:
            return None, "application/octet-stream"

    def _parse_iso8601_date(self, text: str) -> Optional[datetime]:
        """Parse ISO-8601 UTC timestamp format 'YYYY-MM-DDTHH:MM:SSZ'."""
        try:
            s = text.strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            return datetime.fromisoformat(s).astimezone(timezone.utc)
        except Exception:
            return None

    # =========================================================================
    # Internal Parsers: Adobe PDF Structure & Active Threat Scanner
    # =========================================================================

    def _extract_pdf_metadata(self, data: bytes) -> Optional[PDFStructureMetadata]:
        """Extract PDF /Info dictionary and detect weaponized structural action tokens."""
        try:
            # 1. Version extraction
            version_match = re.search(rb"%PDF-(\d+\.\d+)", data[:32])
            pdf_version = version_match.group(1).decode("ascii") if version_match else "1.4"

            # 2. Extract /Info dictionary values
            title: Optional[str] = None
            author: Optional[str] = None
            subject: Optional[str] = None
            keywords: Optional[str] = None
            creator: Optional[str] = None
            producer: Optional[str] = None
            created: Optional[datetime] = None
            modified: Optional[datetime] = None

            def _get_pdf_field(field_name: bytes) -> Optional[str]:
                pattern = rb"/" + field_name + rb"\s*\((.*?)\)"
                m = re.search(pattern, data, re.DOTALL)
                if m:
                    return m.group(1).decode("utf-8", errors="ignore").strip()
                # Hex string format: <FEFF...>
                m_hex = re.search(rb"/" + field_name + rb"\s*<([0-9a-fA-F]+)>", data)
                if m_hex:
                    try:
                        return (
                            bytes.fromhex(m_hex.group(1).decode("ascii"))
                            .decode("utf-16-be", errors="ignore")
                            .strip()
                        )
                    except Exception:
                        pass
                return None

            title = _get_pdf_field(b"Title")
            author = _get_pdf_field(b"Author")
            subject = _get_pdf_field(b"Subject")
            keywords = _get_pdf_field(b"Keywords")
            creator = _get_pdf_field(b"Creator")
            producer = _get_pdf_field(b"Producer")

            raw_created = _get_pdf_field(b"CreationDate")
            if raw_created:
                created = self._parse_pdf_date(raw_created)

            raw_mod = _get_pdf_field(b"ModDate")
            if raw_mod:
                modified = self._parse_pdf_date(raw_mod)

            # 3. Active weaponization indicator scanning
            suspicious: List[str] = []
            has_js = bool(re.search(rb"/(JavaScript|JS)\b", data))
            has_launch = bool(re.search(rb"/Launch\b", data))
            has_embedded = bool(re.search(rb"/EmbeddedFiles\b", data))
            has_open_action = bool(re.search(rb"/OpenAction\b", data))
            has_acroform = bool(re.search(rb"/AcroForm\b", data))
            is_encrypted = bool(re.search(rb"/Encrypt\b", data))

            for token, desc in PDF_WEAPONIZED_TOKENS.items():
                if re.search(rb"" + token.encode("ascii") + rb"\b", data):
                    suspicious.append(desc)

            # Count pages (/Type /Page)
            page_count = len(re.findall(rb"/Type\s*/Page\b", data))

            return PDFStructureMetadata(
                title=title,
                author=author,
                subject=subject,
                keywords=keywords,
                creator=creator,
                producer=producer,
                creation_date=created,
                mod_date=modified,
                pdf_version=pdf_version,
                page_count=page_count if page_count > 0 else None,
                is_encrypted=is_encrypted,
                has_javascript=has_js,
                has_launch_action=has_launch,
                has_embedded_files=has_embedded,
                has_open_action=has_open_action,
                has_acroform=has_acroform,
                suspicious_elements=suspicious,
            )
        except Exception as e:
            logger.debug("Failed parsing PDF metadata: %s", e)
            return None

    def _parse_pdf_date(self, date_str: str) -> Optional[datetime]:
        """Parse PDF date format 'D:YYYYMMDDHHmmSSOHH\'mm\'\'."""
        try:
            s = date_str.strip()
            if s.startswith("D:"):
                s = s[2:]
            match = re.match(r"^(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?", s)
            if match:
                y = int(match.group(1))
                m = int(match.group(2) or 1)
                d = int(match.group(3) or 1)
                hh = int(match.group(4) or 0)
                mm = int(match.group(5) or 0)
                ss = int(match.group(6) or 0)
                return datetime(y, m, d, hh, mm, ss, tzinfo=timezone.utc)
        except Exception:
            pass
        return None

    # =========================================================================
    # Internal Parsers: Audio & Video Containers
    # =========================================================================

    def _extract_mp3_metadata(self, data: bytes) -> Optional[AudioVideoMetadata]:
        """Extract ID3v1 and ID3v2 metadata frames from MP3 audio."""
        title: Optional[str] = None
        artist: Optional[str] = None
        album: Optional[str] = None
        year: Optional[str] = None
        comment: Optional[str] = None
        encoder: Optional[str] = None

        try:
            # 1. ID3v2 header
            if data.startswith(b"ID3") and len(data) >= 10:
                tag_size = (
                    ((data[6] & 0x7F) << 21)
                    | ((data[7] & 0x7F) << 14)
                    | ((data[8] & 0x7F) << 7)
                    | (data[9] & 0x7F)
                )
                pos = 10
                end_pos = min(len(data), 10 + tag_size)
                while pos + 10 <= end_pos:
                    frame_id = data[pos : pos + 4]
                    if frame_id[0] == 0:  # Padding reached
                        break
                    frame_len = struct.unpack(">I", data[pos + 4 : pos + 8])[0]
                    pos += 10
                    if pos + frame_len > end_pos:
                        break
                    frame_data = data[pos : pos + frame_len]
                    pos += frame_len

                    # Text frames begin with encoding byte (0=latin1, 1=utf16, 3=utf8)
                    if len(frame_data) > 1:
                        txt = frame_data[1:].decode("utf-8", errors="ignore").rstrip("\x00").strip()
                        if frame_id == b"TIT2":
                            title = txt
                        elif frame_id == b"TPE1":
                            artist = txt
                        elif frame_id == b"TALB":
                            album = txt
                        elif frame_id in (b"TYER", b"TDRC"):
                            year = txt[:4]
                        elif frame_id == b"TSSE":
                            encoder = txt

            # 2. Fallback to ID3v1 (128 bytes from end of file)
            if (not title or not artist) and len(data) >= 128 and data[-128:-125] == b"TAG":
                v1 = data[-128:]
                if not title:
                    title = (
                        v1[3:33].decode("latin-1", errors="ignore").rstrip("\x00").strip() or None
                    )
                if not artist:
                    artist = (
                        v1[33:63].decode("latin-1", errors="ignore").rstrip("\x00").strip() or None
                    )
                if not album:
                    album = (
                        v1[63:93].decode("latin-1", errors="ignore").rstrip("\x00").strip() or None
                    )
                if not year:
                    year = (
                        v1[93:97].decode("latin-1", errors="ignore").rstrip("\x00").strip() or None
                    )

            if not title and not artist and not album:
                return None

            return AudioVideoMetadata(
                title=title,
                artist=artist,
                album=album,
                year=year,
                encoder=encoder,
                comment=comment,
            )
        except Exception:
            return None

    def _extract_isobmff_metadata(self, data: bytes) -> Optional[AudioVideoMetadata]:
        """Extract quick tags from MP4/MOV ISO-BMFF container."""
        title: Optional[str] = None
        artist: Optional[str] = None
        duration: Optional[float] = None
        encoder: Optional[str] = None

        try:
            mvhd_idx = data.find(b"mvhd")
            if mvhd_idx != -1 and mvhd_idx + 24 <= len(data):
                # mvhd layout: 4 bytes tag ('mvhd'), 1 byte version, 3 bytes flags
                version = data[mvhd_idx + 4]
                if version == 1 and mvhd_idx + 36 <= len(data):
                    timescale = struct.unpack(">I", data[mvhd_idx + 24 : mvhd_idx + 28])[0]
                    duration_ticks = struct.unpack(">Q", data[mvhd_idx + 28 : mvhd_idx + 36])[0]
                else:
                    timescale = struct.unpack(">I", data[mvhd_idx + 16 : mvhd_idx + 20])[0]
                    duration_ticks = struct.unpack(">I", data[mvhd_idx + 20 : mvhd_idx + 24])[0]
                if timescale > 0:
                    duration = round(duration_ticks / timescale, 2)

            if duration is not None or title or artist:
                return AudioVideoMetadata(
                    title=title,
                    artist=artist,
                    duration_seconds=duration,
                    encoder=encoder,
                )
        except Exception:
            pass
        return None

    def _extract_riff_wav_metadata(self, data: bytes) -> Optional[AudioVideoMetadata]:
        """Extract INFO chunk tags from WAV RIFF audio."""
        title: Optional[str] = None
        artist: Optional[str] = None
        year: Optional[str] = None
        software: Optional[str] = None

        try:
            info_idx = data.find(b"LIST")
            if (
                info_idx != -1
                and info_idx + 12 <= len(data)
                and data[info_idx + 8 : info_idx + 12] == b"INFO"
            ):
                list_len = struct.unpack("<I", data[info_idx + 4 : info_idx + 8])[0]
                sub_pos = info_idx + 12
                end_pos = min(len(data), info_idx + 8 + list_len)
                while sub_pos + 8 <= end_pos:
                    sub_tag = data[sub_pos : sub_pos + 4]
                    sub_len = struct.unpack("<I", data[sub_pos + 4 : sub_pos + 8])[0]
                    sub_pos += 8
                    if sub_pos + sub_len > end_pos:
                        break
                    val = (
                        data[sub_pos : sub_pos + sub_len]
                        .decode("utf-8", errors="ignore")
                        .rstrip("\x00")
                        .strip()
                    )
                    sub_pos += sub_len + (sub_len % 2)  # Word align

                    if sub_tag == b"INAM":
                        title = val
                    elif sub_tag == b"IART":
                        artist = val
                    elif sub_tag == b"ICRD":
                        year = val[:4]
                    elif sub_tag == b"ISFT":
                        software = val

            if not title and not artist and not software:
                return None

            return AudioVideoMetadata(
                title=title,
                artist=artist,
                year=year,
                encoder=software,
            )
        except Exception:
            return None

    # =========================================================================
    # Anomaly Detection & Threat Evaluation
    # =========================================================================

    def _evaluate_anomalies(
        self,
        exif: Optional[ImageEXIFMetadata],
        doc: Optional[DocumentMetadata],
        pdf: Optional[PDFStructureMetadata],
        media: Optional[AudioVideoMetadata],
        anomalies: List[MetadataAnomaly],
    ) -> None:
        """Inspect extracted metadata for temporal tampering, weaponization, and exploit tool signatures."""
        now_utc = datetime.now(timezone.utc)

        # 1. Document temporal tampering & author anomalies
        if doc:
            if doc.created and doc.created.year < 1980:
                anomalies.append(
                    MetadataAnomaly(
                        anomaly_type="ANACHRONISTIC_TIMESTAMP",
                        severity=RiskSeverity.SUSPICIOUS_MEDIUM,
                        description=f"Document creation timestamp ({doc.created.isoformat()}) predates the modern computing epoch (<1980).",
                        field_name="created",
                    )
                )
            if doc.created and doc.created.timestamp() > now_utc.timestamp() + 86400:
                anomalies.append(
                    MetadataAnomaly(
                        anomaly_type="FUTURE_TIMESTAMP",
                        severity=RiskSeverity.SUSPICIOUS_MEDIUM,
                        description=f"Document creation timestamp ({doc.created.isoformat()}) is set in the future.",
                        field_name="created",
                    )
                )
            if doc.created and doc.modified and doc.modified < doc.created:
                anomalies.append(
                    MetadataAnomaly(
                        anomaly_type="TEMPORAL_INVERSION",
                        severity=RiskSeverity.SUSPICIOUS_MEDIUM,
                        description="Document modification timestamp is chronologically earlier than creation timestamp.",
                        field_name="modified",
                    )
                )

        # 2. PDF Active Content & Weaponization Actions
        if pdf:
            if pdf.has_launch_action:
                anomalies.append(
                    MetadataAnomaly(
                        anomaly_type="PDF_LAUNCH_ACTION",
                        severity=RiskSeverity.CRITICAL,
                        description="PDF contains weaponized /Launch action capable of executing arbitrary operating system commands.",
                        field_name="has_launch_action",
                    )
                )
            if pdf.has_javascript:
                anomalies.append(
                    MetadataAnomaly(
                        anomaly_type="PDF_EMBEDDED_JAVASCRIPT",
                        severity=RiskSeverity.MALICIOUS_HIGH,
                        description="PDF contains embedded /JavaScript or /JS active execution code streams.",
                        field_name="has_javascript",
                    )
                )
            if pdf.has_embedded_files:
                anomalies.append(
                    MetadataAnomaly(
                        anomaly_type="PDF_EMBEDDED_FILES",
                        severity=RiskSeverity.SUSPICIOUS_MEDIUM,
                        description="PDF embeds arbitrary /EmbeddedFiles payloads within document streams.",
                        field_name="has_embedded_files",
                    )
                )
            if pdf.has_open_action and (pdf.has_javascript or pdf.has_launch_action):
                anomalies.append(
                    MetadataAnomaly(
                        anomaly_type="PDF_AUTO_EXECUTION",
                        severity=RiskSeverity.CRITICAL,
                        description="PDF combines /OpenAction automatic trigger with active execution payloads.",
                        field_name="has_open_action",
                    )
                )

            # Check for suspicious producer / creator toolchains
            creator_text = f"{pdf.creator or ''} {pdf.producer or ''}".lower()
            for susp in SUSPICIOUS_PRODUCERS:
                if susp in creator_text:
                    anomalies.append(
                        MetadataAnomaly(
                            anomaly_type="EXPLOIT_TOOLKIT_ATTRIBUTION",
                            severity=RiskSeverity.CRITICAL,
                            description=f"PDF metadata was produced by known offensive exploitation toolchain: '{susp}'.",
                            field_name="producer",
                        )
                    )

        # 3. EXIF Anachronisms & Geo Alerts
        if exif:
            if exif.datetime_original and exif.datetime_original.year < 1980:
                anomalies.append(
                    MetadataAnomaly(
                        anomaly_type="ANACHRONISTIC_TIMESTAMP",
                        severity=RiskSeverity.SUSPICIOUS_LOW,
                        description=f"Image capture timestamp ({exif.datetime_original.isoformat()}) predates modern camera sensors.",
                        field_name="datetime_original",
                    )
                )
            if (
                exif.datetime_original
                and exif.datetime_original.timestamp() > now_utc.timestamp() + 86400
            ):
                anomalies.append(
                    MetadataAnomaly(
                        anomaly_type="FUTURE_TIMESTAMP",
                        severity=RiskSeverity.SUSPICIOUS_LOW,
                        description=f"Image capture timestamp ({exif.datetime_original.isoformat()}) is set in the future.",
                        field_name="datetime_original",
                    )
                )

    def _score_metadata_threats(
        self,
        filename: str,
        anomalies: List[MetadataAnomaly],
        pdf: Optional[PDFStructureMetadata],
        doc: Optional[DocumentMetadata],
        exif: Optional[ImageEXIFMetadata],
    ) -> Tuple[float, RiskSeverity, str]:
        """Compute composite metadata threat score and assign severity tier."""
        score = 0.0
        max_severity = RiskSeverity.CLEAN

        for a in anomalies:
            if a.severity == RiskSeverity.CRITICAL:
                score += 50.0
                max_severity = RiskSeverity.CRITICAL
            elif a.severity == RiskSeverity.MALICIOUS_HIGH:
                score += 35.0
                if max_severity not in (RiskSeverity.CRITICAL,):
                    max_severity = RiskSeverity.MALICIOUS_HIGH
            elif a.severity == RiskSeverity.SUSPICIOUS_MEDIUM:
                score += 20.0
                if max_severity not in (RiskSeverity.CRITICAL, RiskSeverity.MALICIOUS_HIGH):
                    max_severity = RiskSeverity.SUSPICIOUS_MEDIUM
            elif a.severity == RiskSeverity.SUSPICIOUS_LOW:
                score += 10.0
                if max_severity not in (
                    RiskSeverity.CRITICAL,
                    RiskSeverity.MALICIOUS_HIGH,
                    RiskSeverity.SUSPICIOUS_MEDIUM,
                ):
                    max_severity = RiskSeverity.SUSPICIOUS_LOW

        score = min(100.0, max(0.0, score))

        severity: RiskSeverity
        if max_severity in (RiskSeverity.CRITICAL, RiskSeverity.MALICIOUS_HIGH):
            severity = max_severity
        elif score >= 75.0:
            severity = RiskSeverity.MALICIOUS_HIGH
        elif score >= 40.0:
            severity = RiskSeverity.SUSPICIOUS_MEDIUM
        elif score >= 15.0:
            severity = RiskSeverity.SUSPICIOUS_LOW
        else:
            severity = RiskSeverity.CLEAN

        if severity in (RiskSeverity.CRITICAL, RiskSeverity.MALICIOUS_HIGH):
            summary = f"CRITICAL: Weaponized active metadata or offensive toolkit indicators detected in '{filename}' (Threat Score: {score:.1f}/100)."
        elif severity == RiskSeverity.SUSPICIOUS_MEDIUM:
            summary = f"SUSPICIOUS: File '{filename}' exhibits metadata anomalies or active PDF scripting (Threat Score: {score:.1f}/100)."
        elif severity == RiskSeverity.SUSPICIOUS_LOW:
            summary = f"LOW RISK: Minor metadata anomalies or timestamp inconsistencies found in '{filename}' (Threat Score: {score:.1f}/100)."
        else:
            summary = f"CLEAN: Metadata for '{filename}' extracted successfully with zero malicious indicators."

        return score, severity, summary
