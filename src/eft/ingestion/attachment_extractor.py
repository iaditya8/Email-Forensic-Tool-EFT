"""Automated attachment extraction, cryptographic fingerprinting, and magic byte inspection engine."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set, Tuple, Union

try:
    import puremagic  # type: ignore
except ImportError:  # pragma: no cover
    puremagic = None  # type: ignore[assignment]

from eft.core.integrity import compute_bytes_hashes
from eft.models.canonical import (
    AttachmentMetadata,
    CanonicalEmail,
    ExtractedAttachment,
    FileTypeInspection,
)

# High-risk executable and script extensions
DANGEROUS_EXTENSIONS: Set[str] = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".cpl",
    ".com",
    ".pif",
    ".bat",
    ".cmd",
    ".ps1",
    ".ps2",
    ".psc1",
    ".psc2",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".msc",
    ".msi",
    ".msp",
    ".reg",
    ".jar",
    ".iso",
    ".img",
    ".vhd",
    ".vhdx",
    ".lnk",
    ".xlsm",
    ".docm",
    ".pptm",
    ".dotm",
    ".xltm",
    ".xlam",
    ".sldm",
}

# Windows reserved device names
WINDOWS_RESERVED_NAMES: Set[str] = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
}

# Common benign document/media extensions frequently targeted by spoofing
BENIGN_EXTENSIONS: Set[str] = {
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
    ".doc",
    ".xls",
    ".ppt",
    ".txt",
    ".csv",
    ".rtf",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".webp",
    ".tiff",
    ".mp3",
    ".mp4",
    ".wav",
}

# Double extension pattern detection (e.g. invoice.pdf.exe or photo.jpg.scr)
DOUBLE_EXT_PATTERN = re.compile(
    r"\.([a-zA-Z0-9]{2,5})\.([a-zA-Z0-9]{2,5})$",
    re.IGNORECASE,
)

# Native magic signature fallbacks for high-confidence forensic identification
KNOWN_MAGIC_SIGNATURES: List[Tuple[bytes, str, str, str]] = [
    # (magic_bytes, extension, mime_type, format_name)
    (b"MZ", ".exe", "application/x-dosexec", "Windows Executable/DLL (PE)"),
    (b"\x7fELF", ".elf", "application/x-executable", "Linux Executable (ELF)"),
    (b"\xfe\xed\xfa\xce", ".macho", "application/x-mach-binary", "Mach-O Binary (32-bit)"),
    (b"\xfe\xed\xfa\xcf", ".macho", "application/x-mach-binary", "Mach-O Binary (64-bit)"),
    (
        b"\xca\xfe\xba\xbe",
        ".macho",
        "application/x-mach-binary",
        "Mach-O Universal Binary / Java Class",
    ),
    (b"%PDF-", ".pdf", "application/pdf", "Adobe PDF Document"),
    (b"\x89PNG\r\n\x1a\n", ".png", "image/png", "PNG Image"),
    (b"\xff\xd8\xff", ".jpg", "image/jpeg", "JPEG Image"),
    (b"GIF87a", ".gif", "image/gif", "GIF Image"),
    (b"GIF89a", ".gif", "image/gif", "GIF Image"),
    (b"PK\x03\x04", ".zip", "application/zip", "ZIP Archive / Office XML"),
    (b"PK\x05\x06", ".zip", "application/zip", "Empty ZIP Archive"),
    (b"PK\x07\x08", ".zip", "application/zip", "Spanned ZIP Archive"),
    (b"7z\xbc\xaf\x27\x1c", ".7z", "application/x-7z-compressed", "7-Zip Archive"),
    (b"Rar!\x1a\x07\x00", ".rar", "application/x-rar-compressed", "RAR Archive (v4)"),
    (b"Rar!\x1a\x07\x01\x00", ".rar", "application/x-rar-compressed", "RAR Archive (v5)"),
    (b"\x1f\x8b", ".gz", "application/gzip", "GZIP Compressed Archive"),
    (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        ".doc",
        "application/msword",
        "Microsoft Compound File (OLE/DOC/XLS/PPT)",
    ),
    (b"BM", ".bmp", "image/bmp", "BMP Image"),
]


class AttachmentExtractor:
    """Forensic attachment extractor, multi-hashing engine, and magic byte inspector."""

    @classmethod
    def sanitize_filename(cls, filename: Optional[str], index: int = 0) -> str:
        """Sanitize raw attachment filename to prevent path traversal and filesystem injection.

        Protections:
        - Strips directory path components (e.g. `../../`, `C:\\Windows\\`).
        - Strips null bytes (`\\x00`) and control characters (`\\x00-\\x1f`, `\\x7f-\\x9f`).
        - Replaces invalid characters (`<`, `>`, `:`, `"`, `/`, `\\`, `|`, `?`, `*`) with `_`.
        - Defends against Windows reserved device names (e.g. `CON`, `PRN`, `AUX`, `NUL`).
        - Ensures non-empty, safe filename with maximum safe length.

        Args:
            filename: Raw declared filename from email headers or MIME parts.
            index: Positional index used for fallback naming if filename is empty.

        Returns:
            Sanitized, filesystem-safe filename string.
        """
        if not filename or not filename.strip():
            return f"attachment_{index}.dat"

        # Remove control characters and null bytes
        sanitized = "".join(ch for ch in filename if ord(ch) >= 32 and ord(ch) != 127)

        # Strip any absolute or relative path structure
        sanitized = os.path.basename(sanitized)
        sanitized = sanitized.replace("\\", "/").split("/")[-1]

        # Remove filesystem illegal characters
        sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", sanitized).strip()

        if not sanitized or sanitized in {".", ".."}:
            return f"attachment_{index}.dat"

        # Check Windows reserved base names
        stem = Path(sanitized).stem.upper()
        if stem in WINDOWS_RESERVED_NAMES:
            sanitized = f"_{sanitized}"

        # Limit overall filename length to 255 characters while preserving extension
        if len(sanitized) > 255:
            ext = Path(sanitized).suffix
            stem_allowed = 255 - len(ext)
            sanitized = sanitized[:stem_allowed] + ext

        return sanitized

    @classmethod
    def inspect_payload(
        cls,
        data: bytes,
        declared_filename: str,
        declared_content_type: str = "application/octet-stream",
    ) -> FileTypeInspection:
        """Inspect payload binary data against declared extension and MIME type.

        Performs:
        - Magic byte inspection using puremagic and native forensic signature tables.
        - Extension spoofing detection (e.g., `.exe` masked as `.pdf` or `.docx`).
        - Double extension detection (e.g., `report.pdf.exe`).
        - Risk scoring (BENIGN, LOW, MEDIUM, HIGH, CRITICAL) and risk diagnostic logging.

        Args:
            data: Raw binary byte stream of the attachment.
            declared_filename: Declared filename from email headers.
            declared_content_type: Declared MIME Content-Type.

        Returns:
            FileTypeInspection containing detected types, mismatch flags, risk level, and diagnostics.
        """
        declared_ext = Path(declared_filename).suffix.lower()
        declared_mime = declared_content_type.split(";")[0].strip().lower()

        detected_ext: Optional[str] = None
        detected_mime: Optional[str] = None
        match_desc: Optional[str] = None

        # 1. Native signature table lookup (fast and precise for critical binary formats)
        for sig, ext, mime, desc in KNOWN_MAGIC_SIGNATURES:
            if data.startswith(sig):
                detected_ext = ext
                detected_mime = mime
                match_desc = desc
                break

        # 2. Check puremagic if available and native match was not found or needs enrichment
        if puremagic is not None and len(data) > 0:
            try:
                magic_results = puremagic.magic_string(data)
                if magic_results and not detected_ext:
                    best_match = magic_results[0]
                    detected_ext = best_match.extension
                    detected_mime = best_match.mime_type
                    match_desc = best_match.name
            except Exception:
                pass

        # 3. Analyze Mismatches & Risk Level
        risk_reasons: List[str] = []
        is_ext_mismatch = False
        is_mime_mismatch = False
        risk_level = "BENIGN"

        # Check for double extension deception
        double_ext_match = DOUBLE_EXT_PATTERN.search(declared_filename)
        if double_ext_match:
            inner_ext = f".{double_ext_match.group(1).lower()}"
            outer_ext = f".{double_ext_match.group(2).lower()}"
            if inner_ext in BENIGN_EXTENSIONS and outer_ext in DANGEROUS_EXTENSIONS:
                risk_reasons.append(
                    f"Deceptive double extension detected ({declared_filename}): outer extension '{outer_ext}' is executable/script."
                )
                risk_level = "CRITICAL"
            elif inner_ext in BENIGN_EXTENSIONS:
                risk_reasons.append(f"Potential double extension detected ({declared_filename}).")
                if risk_level != "CRITICAL":
                    risk_level = "HIGH"

        # Check for direct dangerous extension
        if declared_ext in DANGEROUS_EXTENSIONS:
            risk_reasons.append(
                f"Attachment has high-risk executable or script extension: '{declared_ext}'."
            )
            if risk_level != "CRITICAL":
                risk_level = "HIGH"

        # Check detected vs declared extension mismatch
        if detected_ext and declared_ext:
            # Normalize extension comparison (e.g. .jpeg vs .jpg, .zip vs .docx)
            is_compatible = cls._are_extensions_compatible(declared_ext, detected_ext)
            if not is_compatible:
                is_ext_mismatch = True

                # CRITICAL: Benign declared extension masking executable binary payload
                if declared_ext in BENIGN_EXTENSIONS and detected_ext in {
                    ".exe",
                    ".elf",
                    ".macho",
                    ".dll",
                }:
                    risk_reasons.append(
                        f"CRITICAL EXTENSION SPOOFING: Declared '{declared_ext}' masquerades true binary payload '{detected_ext}' ({match_desc})."
                    )
                    risk_level = "CRITICAL"
                elif declared_ext in BENIGN_EXTENSIONS and detected_ext in DANGEROUS_EXTENSIONS:
                    risk_reasons.append(
                        f"HIGH RISK EXTENSION SPOOFING: Declared '{declared_ext}' masks dangerous payload '{detected_ext}'."
                    )
                    if risk_level != "CRITICAL":
                        risk_level = "HIGH"
                else:
                    risk_reasons.append(
                        f"Extension mismatch: declared '{declared_ext}' but magic bytes indicate '{detected_ext}' ({match_desc})."
                    )
                    if risk_level in {"BENIGN", "LOW"}:
                        risk_level = "MEDIUM"

        # Check MIME type mismatch
        if detected_mime and declared_mime and declared_mime != "application/octet-stream":
            if not cls._are_mimes_compatible(declared_mime, detected_mime):
                is_mime_mismatch = True
                risk_reasons.append(
                    f"MIME type mismatch: declared '{declared_mime}' vs detected '{detected_mime}'."
                )
                if risk_level == "BENIGN":
                    risk_level = "LOW"

        return FileTypeInspection(
            declared_extension=declared_ext,
            detected_extension=detected_ext,
            declared_mime_type=declared_mime,
            detected_mime_type=detected_mime,
            is_extension_mismatch=is_ext_mismatch,
            is_mime_mismatch=is_mime_mismatch,
            match_description=match_desc,
            risk_level=risk_level,
            risk_reasons=risk_reasons,
        )

    @classmethod
    def _are_extensions_compatible(cls, ext1: str, ext2: str) -> bool:
        """Check if two file extensions are logically compatible aliases."""
        e1 = ext1.lower().lstrip(".")
        e2 = ext2.lower().lstrip(".")
        if e1 == e2:
            return True

        # Equivalent families
        jpeg_family = {"jpg", "jpeg", "jpe", "jfif"}
        tiff_family = {"tif", "tiff"}
        zip_office_family = {"zip", "docx", "xlsx", "pptx", "jar", "apk", "odt", "ods", "odp"}
        ole_office_family = {"doc", "xls", "ppt", "msg", "dot", "xlt"}
        text_family = {"txt", "csv", "log", "tsv", "json", "xml", "html", "htm", "eml"}

        for family in [jpeg_family, tiff_family, zip_office_family, ole_office_family, text_family]:
            if e1 in family and e2 in family:
                return True

        return False

    @classmethod
    def _are_mimes_compatible(cls, mime1: str, mime2: str) -> bool:
        """Check if two MIME types represent compatible representations."""
        m1 = mime1.lower().strip()
        m2 = mime2.lower().strip()
        if m1 == m2 or m1 == "application/octet-stream" or m2 == "application/octet-stream":
            return True

        # Known compatible mappings
        if ("zip" in m1 or "openxmlformats" in m1) and ("zip" in m2 or "openxmlformats" in m2):
            return True
        if "text/" in m1 and "text/" in m2:
            return True
        if "image/jpeg" in m1 and "image/jpeg" in m2:
            return True

        return False

    @classmethod
    def extract_attachment(
        cls,
        attachment: AttachmentMetadata,
        output_dir: Optional[Union[str, Path]] = None,
        index: int = 0,
        save_to_disk: bool = False,
    ) -> ExtractedAttachment:
        """Extract a single attachment, sanitize filename, compute multi-hashes, and inspect magic bytes.

        Args:
            attachment: Raw AttachmentMetadata container.
            output_dir: Optional destination directory for isolated evidence storage.
            index: Positional attachment index.
            save_to_disk: Whether to physically persist payload bytes to disk.

        Returns:
            ExtractedAttachment forensic model with hashes, inspection results, and file path.
        """
        raw_data = attachment.raw_data or b""
        safe_name = cls.sanitize_filename(attachment.filename, index=index)
        hashes = attachment.hashes if attachment.hashes else compute_bytes_hashes(raw_data)

        # Deep magic byte inspection
        inspection = cls.inspect_payload(
            data=raw_data,
            declared_filename=safe_name,
            declared_content_type=attachment.content_type,
        )

        saved_path: Optional[str] = None

        if save_to_disk and output_dir:
            out_path = Path(output_dir)
            out_path.mkdir(parents=True, exist_ok=True)

            # Prevent collisions by prefixing index if file already exists
            target_file = out_path / f"{index:02d}_{safe_name}"
            # Ensure target_file is strictly inside out_path (sandbox enforcement)
            target_file_resolved = target_file.resolve()
            if not str(target_file_resolved).startswith(str(out_path.resolve())):
                target_file = out_path / f"isolated_att_{index:02d}.dat"

            target_file.write_bytes(raw_data)
            saved_path = str(target_file.resolve())

        return ExtractedAttachment(
            attachment_index=index,
            filename=attachment.filename,
            safe_filename=safe_name,
            saved_path=saved_path,
            size_bytes=len(raw_data) if raw_data else attachment.size_bytes,
            content_type=attachment.content_type,
            content_id=attachment.content_id,
            content_disposition=attachment.content_disposition,
            is_inline=attachment.is_inline,
            hashes=hashes,
            file_type_inspection=inspection,
            extracted_timestamp_utc=datetime.now(timezone.utc),
        )

    @classmethod
    def extract_from_email(
        cls,
        email: CanonicalEmail,
        output_dir: Optional[Union[str, Path]] = None,
        save_to_disk: bool = False,
    ) -> List[ExtractedAttachment]:
        """Extract, fingerprint, and inspect all attachments from a CanonicalEmail instance.

        Also updates `email.extracted_attachments` in place.

        Args:
            email: CanonicalEmail containing ingested raw attachment metadata.
            output_dir: Optional destination directory for saved payload files.
            save_to_disk: Whether to physically write extracted payloads to disk.

        Returns:
            List of ExtractedAttachment records.
        """
        extracted_list: List[ExtractedAttachment] = []

        for idx, att in enumerate(email.attachments):
            extracted = cls.extract_attachment(
                attachment=att,
                output_dir=output_dir,
                index=idx,
                save_to_disk=save_to_disk,
            )
            extracted_list.append(extracted)

        email.extracted_attachments = extracted_list
        return extracted_list
