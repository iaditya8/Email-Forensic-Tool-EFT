"""Standalone Binary File Magic Byte & True Extension Identification Engine.

ISO/IEC 27037 compliant forensic artifact inspector detecting header spoofing,
double-extension deception, Right-to-Left Override (RLO) attacks, and payload masquerading.
"""

from __future__ import annotations

import io
import logging
import re
import struct
import zipfile
from pathlib import Path
from typing import List, Optional, Set, Tuple, Union

from eft.core.integrity import compute_bytes_hashes, compute_file_hashes
from eft.models.binary import (
    FileArtifactReport,
    FileFormatCategory,
    FileTypeIdentification,
    MagicByteSignature,
)
from eft.models.threat import RiskSeverity

logger = logging.getLogger(__name__)

# Dangerous executable extensions frequently targeted by disguised attachments
DANGEROUS_EXECUTABLE_EXTENSIONS: Set[str] = {
    ".exe",
    ".dll",
    ".scr",
    ".cpl",
    ".ocx",
    ".sys",
    ".drv",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".jar",
    ".iso",
    ".img",
    ".vhd",
    ".vhdx",
    ".lnk",
    ".pif",
    ".chm",
    ".com",
    ".elf",
    ".so",
    ".dylib",
    ".macho",
    ".wasm",
    ".dex",
}

# Common document and media extensions attackers impersonate
BENIGN_CARRIER_EXTENSIONS: Set[str] = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".txt",
    ".rtf",
    ".csv",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".webp",
    ".tiff",
    ".mp3",
    ".mp4",
    ".wav",
    ".avi",
}

# Double extension pattern (e.g. invoice.pdf.exe or scan.jpg.scr)
DOUBLE_EXT_PATTERN = re.compile(
    r"\.([a-zA-Z0-9]{2,5})\.([a-zA-Z0-9]{2,5})$",
    re.IGNORECASE,
)

# Right-to-Left Override Unicode codepoints
RLO_CODEPOINTS = {"\u202e", "\u202d", "\u202c", "\u202b", "\u202a"}


class FileArtifactAnalyzer:
    """Enterprise-grade binary file and artifact forensic analysis engine."""

    def __init__(self, custom_signatures: Optional[List[MagicByteSignature]] = None) -> None:
        self.signatures = self._init_signatures()
        if custom_signatures:
            self.signatures.extend(custom_signatures)

    @staticmethod
    def _init_signatures() -> List[MagicByteSignature]:
        """Initialize built-in signature database covering major binary, container, document, and media formats."""
        return [
            # -------------------------------------------------------------
            # Executables & Binary Payloads
            # -------------------------------------------------------------
            MagicByteSignature(
                name="Windows Portable Executable (PE32/PE64)",
                mime_type="application/vnd.microsoft.portable-executable",
                category=FileFormatCategory.EXECUTABLE,
                magic_hex="4D5A",  # MZ
                offset=0,
                canonical_extensions=[".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv"],
                description="DOS/PE executable binary header",
            ),
            MagicByteSignature(
                name="Linux Executable & Linkable Format (ELF)",
                mime_type="application/x-executable",
                category=FileFormatCategory.EXECUTABLE,
                magic_hex="7F454C46",  # \x7fELF
                offset=0,
                canonical_extensions=[".elf", ".so", ".o", ".bin", ""],
                description="Unix/Linux ELF binary executable or shared library",
            ),
            MagicByteSignature(
                name="macOS Mach-O Binary (64-bit Big-Endian)",
                mime_type="application/x-mach-binary",
                category=FileFormatCategory.EXECUTABLE,
                magic_hex="FEEDFACF",
                offset=0,
                canonical_extensions=[".dylib", ".macho", ".bin", ""],
                description="macOS 64-bit Mach-O executable (Big-Endian)",
            ),
            MagicByteSignature(
                name="macOS Mach-O Binary (64-bit Little-Endian)",
                mime_type="application/x-mach-binary",
                category=FileFormatCategory.EXECUTABLE,
                magic_hex="CFFAEDFE",
                offset=0,
                canonical_extensions=[".dylib", ".macho", ".bin", ""],
                description="macOS 64-bit Mach-O executable (Little-Endian)",
            ),
            MagicByteSignature(
                name="macOS Mach-O Binary (32-bit Big-Endian)",
                mime_type="application/x-mach-binary",
                category=FileFormatCategory.EXECUTABLE,
                magic_hex="FEEDFACE",
                offset=0,
                canonical_extensions=[".dylib", ".macho", ".bin", ""],
                description="macOS 32-bit Mach-O executable (Big-Endian)",
            ),
            MagicByteSignature(
                name="macOS Mach-O Binary (32-bit Little-Endian)",
                mime_type="application/x-mach-binary",
                category=FileFormatCategory.EXECUTABLE,
                magic_hex="CEFAEDFE",
                offset=0,
                canonical_extensions=[".dylib", ".macho", ".bin", ""],
                description="macOS 32-bit Mach-O executable (Little-Endian)",
            ),
            MagicByteSignature(
                name="macOS Mach-O Universal / Fat Binary",
                mime_type="application/x-mach-binary",
                category=FileFormatCategory.EXECUTABLE,
                magic_hex="CAFEBABF",
                offset=0,
                canonical_extensions=[".dylib", ".macho", ".bin", ""],
                description="macOS Universal multi-architecture fat binary",
            ),
            MagicByteSignature(
                name="WebAssembly Binary (Wasm)",
                mime_type="application/wasm",
                category=FileFormatCategory.EXECUTABLE,
                magic_hex="0061736D",  # \0asm
                offset=0,
                canonical_extensions=[".wasm"],
                description="Compiled WebAssembly binary module",
            ),
            MagicByteSignature(
                name="Android Dalvik Executable (DEX)",
                mime_type="application/vnd.android.dex",
                category=FileFormatCategory.EXECUTABLE,
                magic_hex="6465780A",  # dex\n
                offset=0,
                canonical_extensions=[".dex"],
                description="Android Dalvik compiled bytecode",
            ),
            MagicByteSignature(
                name="Java Class Bytecode",
                mime_type="application/java-vm",
                category=FileFormatCategory.EXECUTABLE,
                magic_hex="CAFEBABE",
                offset=0,
                canonical_extensions=[".class"],
                description="Compiled Java JVM bytecode class file",
            ),
            MagicByteSignature(
                name="Windows Shell Link Shortcut (LNK)",
                mime_type="application/x-ms-shortcut",
                category=FileFormatCategory.SCRIPT,
                magic_hex="4C00000001140200",
                offset=0,
                canonical_extensions=[".lnk"],
                description="Windows shell link shortcut payload",
            ),
            MagicByteSignature(
                name="Compiled HTML Help File (CHM)",
                mime_type="application/vnd.ms-htmlhelp",
                category=FileFormatCategory.EXECUTABLE,
                magic_hex="4954534603000000",  # ITSF
                offset=0,
                canonical_extensions=[".chm"],
                description="Microsoft Compiled HTML Help container",
            ),
            # -------------------------------------------------------------
            # Documents & Structured Office Formats
            # -------------------------------------------------------------
            MagicByteSignature(
                name="Adobe Portable Document Format (PDF)",
                mime_type="application/pdf",
                category=FileFormatCategory.DOCUMENT,
                magic_hex="25504446",  # %PDF
                offset=0,
                canonical_extensions=[".pdf"],
                description="Adobe PDF document",
            ),
            MagicByteSignature(
                name="Microsoft Office OLE Compound Document (CFBF)",
                mime_type="application/x-ole-storage",
                category=FileFormatCategory.DOCUMENT,
                magic_hex="D0CF11E0A1B11AE1",
                offset=0,
                canonical_extensions=[".doc", ".xls", ".ppt", ".msg", ".vsd"],
                description="Microsoft Office 97-2003 OLE Compound Document",
            ),
            MagicByteSignature(
                name="Rich Text Format (RTF)",
                mime_type="application/rtf",
                category=FileFormatCategory.DOCUMENT,
                magic_hex="7B5C727466",  # {\rtf
                offset=0,
                canonical_extensions=[".rtf"],
                description="Rich Text Format document",
            ),
            MagicByteSignature(
                name="PostScript Document",
                mime_type="application/postscript",
                category=FileFormatCategory.DOCUMENT,
                magic_hex="25215053",  # %!PS
                offset=0,
                canonical_extensions=[".ps", ".eps"],
                description="Adobe PostScript document",
            ),
            # -------------------------------------------------------------
            # Archives & Containers
            # -------------------------------------------------------------
            MagicByteSignature(
                name="ZIP Archive / OpenXML Document",
                mime_type="application/zip",
                category=FileFormatCategory.ARCHIVE,
                magic_hex="504B0304",  # PK\x03\x04
                offset=0,
                canonical_extensions=[
                    ".zip",
                    ".docx",
                    ".xlsx",
                    ".pptx",
                    ".jar",
                    ".apk",
                    ".odt",
                    ".ods",
                    ".odp",
                    ".epub",
                ],
                description="ZIP container or Microsoft Office OpenXML package",
            ),
            MagicByteSignature(
                name="7-Zip Compressed Archive",
                mime_type="application/x-7z-compressed",
                category=FileFormatCategory.ARCHIVE,
                magic_hex="377ABCAF271C",  # 7z\xbc\xaf'\x1c
                offset=0,
                canonical_extensions=[".7z"],
                description="7-Zip high-compression archive",
            ),
            MagicByteSignature(
                name="RAR Compressed Archive (v5.0+)",
                mime_type="application/vnd.rar",
                category=FileFormatCategory.ARCHIVE,
                magic_hex="526172211A070100",  # Rar!\x1a\x07\x01\x00
                offset=0,
                canonical_extensions=[".rar"],
                description="RAR archive version 5.0+",
            ),
            MagicByteSignature(
                name="RAR Compressed Archive (v4.x)",
                mime_type="application/vnd.rar",
                category=FileFormatCategory.ARCHIVE,
                magic_hex="526172211A0700",  # Rar!\x1a\x07\x00
                offset=0,
                canonical_extensions=[".rar"],
                description="RAR archive legacy version 4.x",
            ),
            MagicByteSignature(
                name="GZIP Compressed File",
                mime_type="application/gzip",
                category=FileFormatCategory.ARCHIVE,
                magic_hex="1F8B",
                offset=0,
                canonical_extensions=[".gz", ".tgz", ".gzip"],
                description="GNU zip compressed stream",
            ),
            MagicByteSignature(
                name="BZIP2 Compressed File",
                mime_type="application/x-bzip2",
                category=FileFormatCategory.ARCHIVE,
                magic_hex="425A68",  # BZh
                offset=0,
                canonical_extensions=[".bz2", ".tbz2"],
                description="Bzip2 compressed stream",
            ),
            MagicByteSignature(
                name="XZ Compressed Archive",
                mime_type="application/x-xz",
                category=FileFormatCategory.ARCHIVE,
                magic_hex="FD377A585A00",  # \xfd7zXZ\0
                offset=0,
                canonical_extensions=[".xz", ".txz"],
                description="XZ compressed archive",
            ),
            MagicByteSignature(
                name="ISO 9660 CD/DVD Disk Image",
                mime_type="application/x-iso9660-image",
                category=FileFormatCategory.ARCHIVE,
                magic_hex="4344303031",  # CD001
                offset=32769,
                canonical_extensions=[".iso", ".img"],
                description="ISO 9660 Optical Disc Image",
            ),
            MagicByteSignature(
                name="Microsoft Cabinet (CAB) File",
                mime_type="application/vnd.ms-cab-compressed",
                category=FileFormatCategory.ARCHIVE,
                magic_hex="4D534346",  # MSCF
                offset=0,
                canonical_extensions=[".cab"],
                description="Microsoft Cabinet archive",
            ),
            MagicByteSignature(
                name="Zstandard Compressed File",
                mime_type="application/zstd",
                category=FileFormatCategory.ARCHIVE,
                magic_hex="28B52FFD",
                offset=0,
                canonical_extensions=[".zst"],
                description="Zstandard fast compression stream",
            ),
            # -------------------------------------------------------------
            # Raster & Vector Images
            # -------------------------------------------------------------
            MagicByteSignature(
                name="Portable Network Graphics (PNG)",
                mime_type="image/png",
                category=FileFormatCategory.IMAGE,
                magic_hex="89504E470D0A1A0A",  # \x89PNG\r\n\x1a\n
                offset=0,
                canonical_extensions=[".png"],
                description="PNG lossless raster image",
            ),
            MagicByteSignature(
                name="JPEG Image (JFIF/EXIF)",
                mime_type="image/jpeg",
                category=FileFormatCategory.IMAGE,
                magic_hex="FFD8FF",
                offset=0,
                canonical_extensions=[".jpg", ".jpeg", ".jpe", ".jif", ".jfif"],
                description="JPEG lossy photographic image",
            ),
            MagicByteSignature(
                name="Graphics Interchange Format (GIF89a)",
                mime_type="image/gif",
                category=FileFormatCategory.IMAGE,
                magic_hex="474946383961",  # GIF89a
                offset=0,
                canonical_extensions=[".gif"],
                description="GIF animated/palette image (89a)",
            ),
            MagicByteSignature(
                name="Graphics Interchange Format (GIF87a)",
                mime_type="image/gif",
                category=FileFormatCategory.IMAGE,
                magic_hex="474946383761",  # GIF87a
                offset=0,
                canonical_extensions=[".gif"],
                description="GIF palette image (87a)",
            ),
            MagicByteSignature(
                name="Windows Bitmap Image (BMP)",
                mime_type="image/bmp",
                category=FileFormatCategory.IMAGE,
                magic_hex="424D",  # BM
                offset=0,
                canonical_extensions=[".bmp", ".dib"],
                description="Windows Device-Independent Bitmap",
            ),
            MagicByteSignature(
                name="TIFF Image (Little-Endian)",
                mime_type="image/tiff",
                category=FileFormatCategory.IMAGE,
                magic_hex="49492A00",  # II*\0
                offset=0,
                canonical_extensions=[".tiff", ".tif"],
                description="Tagged Image File Format (Intel)",
            ),
            MagicByteSignature(
                name="TIFF Image (Big-Endian)",
                mime_type="image/tiff",
                category=FileFormatCategory.IMAGE,
                magic_hex="4D4D002A",  # MM\0*
                offset=0,
                canonical_extensions=[".tiff", ".tif"],
                description="Tagged Image File Format (Motorola)",
            ),
            MagicByteSignature(
                name="Windows Icon Image (ICO)",
                mime_type="image/x-icon",
                category=FileFormatCategory.IMAGE,
                magic_hex="00000100",
                offset=0,
                canonical_extensions=[".ico"],
                description="Windows Icon resource",
            ),
            MagicByteSignature(
                name="Adobe Photoshop Document (PSD)",
                mime_type="image/vnd.adobe.photoshop",
                category=FileFormatCategory.IMAGE,
                magic_hex="38425053",  # 8BPS
                offset=0,
                canonical_extensions=[".psd"],
                description="Photoshop Layered Image Document",
            ),
            # -------------------------------------------------------------
            # Audio & Video Media
            # -------------------------------------------------------------
            MagicByteSignature(
                name="MP3 Audio with ID3v2 Tag",
                mime_type="audio/mpeg",
                category=FileFormatCategory.AUDIO_VIDEO,
                magic_hex="494433",  # ID3
                offset=0,
                canonical_extensions=[".mp3"],
                description="MPEG Audio Layer III with ID3v2 container",
            ),
            MagicByteSignature(
                name="Free Lossless Audio Codec (FLAC)",
                mime_type="audio/flac",
                category=FileFormatCategory.AUDIO_VIDEO,
                magic_hex="664C6143",  # fLaC
                offset=0,
                canonical_extensions=[".flac"],
                description="FLAC Lossless Audio stream",
            ),
            MagicByteSignature(
                name="Ogg Media Container",
                mime_type="audio/ogg",
                category=FileFormatCategory.AUDIO_VIDEO,
                magic_hex="4F676753",  # OggS
                offset=0,
                canonical_extensions=[".ogg", ".oga", ".ogv"],
                description="Ogg Vorbis/Theora multimedia container",
            ),
            MagicByteSignature(
                name="Matroska / WebM Video Container",
                mime_type="video/x-matroska",
                category=FileFormatCategory.AUDIO_VIDEO,
                magic_hex="1A45DFA3",
                offset=0,
                canonical_extensions=[".mkv", ".webm", ".mka"],
                description="Matroska multimedia container",
            ),
            # -------------------------------------------------------------
            # Scripts & Text Formats
            # -------------------------------------------------------------
            MagicByteSignature(
                name="Unix Shell Script (Shebang)",
                mime_type="text/x-shellscript",
                category=FileFormatCategory.SCRIPT,
                magic_hex="2321",  # #!
                offset=0,
                canonical_extensions=[".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ""],
                description="Executable script with shebang header",
            ),
            MagicByteSignature(
                name="Extensible Markup Language (XML)",
                mime_type="application/xml",
                category=FileFormatCategory.DOCUMENT,
                magic_hex="3C3F786D6C",  # <?xml
                offset=0,
                canonical_extensions=[".xml", ".svg", ".plist", ".config"],
                description="XML structured markup document",
            ),
            MagicByteSignature(
                name="HyperText Markup Language (HTML)",
                mime_type="text/html",
                category=FileFormatCategory.DOCUMENT,
                magic_hex="3C21444F4354595045",  # <!DOCTYPE
                offset=0,
                canonical_extensions=[".html", ".htm", ".xhtml"],
                description="HTML web document",
            ),
            # -------------------------------------------------------------
            # Databases & Storage
            # -------------------------------------------------------------
            MagicByteSignature(
                name="SQLite Database (v3)",
                mime_type="application/vnd.sqlite3",
                category=FileFormatCategory.DATABASE,
                magic_hex="53514C69746520666F726D6174203300",  # SQLite format 3\0
                offset=0,
                canonical_extensions=[".sqlite", ".db", ".sqlite3", ".db3"],
                description="SQLite embedded database file",
            ),
        ]

    def identify_bytes(
        self,
        data: bytes,
        filename: str = "unknown",
    ) -> FileTypeIdentification:
        """Inspect raw bytes against signature definitions and detect file deception tricks."""
        alerts: List[str] = []
        is_mismatch = False

        # 1. Check for Right-to-Left Override (RLO) character attack
        has_rlo = any(rlo in filename for rlo in RLO_CODEPOINTS)
        clean_name: Optional[str] = None
        if has_rlo:
            clean_name = filename
            for rlo in RLO_CODEPOINTS:
                clean_name = clean_name.replace(rlo, "")
            alerts.append(
                f"Unicode Right-to-Left Override (RLO) detected in filename: '{filename}' disguised as reverse extension"
            )

        # 2. Check for Null-Byte injection attack in filename
        has_null = "\x00" in filename or "%00" in filename
        if has_null:
            alerts.append("Null-byte injection detected in filename")

        # Determine effective declared extension based on sanitized filename
        base_name_for_ext = filename.split("\x00")[0].split("%00")[0]
        if has_rlo and clean_name:
            base_name_for_ext = clean_name.split("\x00")[0].split("%00")[0]
        declared_ext = Path(base_name_for_ext).suffix.lower() if "." in base_name_for_ext else ""

        # 3. Check for Double Extension deception
        is_double_ext = False
        inner_ext: Optional[str] = None
        double_match = DOUBLE_EXT_PATTERN.search(base_name_for_ext)
        if double_match:
            cand_inner = f".{double_match.group(1).lower()}"
            cand_outer = f".{double_match.group(2).lower()}"
            if (
                cand_inner in BENIGN_CARRIER_EXTENSIONS
                and cand_outer in DANGEROUS_EXECUTABLE_EXTENSIONS
            ):
                is_double_ext = True
                inner_ext = cand_inner
                alerts.append(
                    f"Dangerous double-extension spoofing detected: inner benign extension '{cand_inner}' masked by executable '{cand_outer}'"
                )

        # Early exit for empty byte buffer
        if not data:
            return FileTypeIdentification(
                is_identified=False,
                detected_format="Empty / Zero-Byte Artifact",
                detected_mime="application/x-empty",
                category=FileFormatCategory.UNKNOWN,
                declared_extension=declared_ext,
                canonical_extensions=[],
                is_extension_mismatch=False,
                is_double_extension=is_double_ext,
                detected_inner_extension=inner_ext,
                has_null_byte_injection=has_null,
                has_right_to_left_override=has_rlo,
                rlo_clean_name=clean_name,
                confidence_score=1.0,
                forensic_alerts=alerts,
            )

        # 4. Special check: RIFF Container (WebP vs WAV vs AVI)
        if data.startswith(b"RIFF") and len(data) >= 12:
            riff_type = data[8:12]
            if riff_type == b"WEBP":
                return self._build_result(
                    format_name="Google WebP Image",
                    mime="image/webp",
                    category=FileFormatCategory.IMAGE,
                    declared_ext=declared_ext,
                    canonical_exts=[".webp"],
                    has_rlo=has_rlo,
                    clean_name=clean_name,
                    has_null=has_null,
                    is_double_ext=is_double_ext,
                    inner_ext=inner_ext,
                    alerts=alerts,
                )
            elif riff_type == b"WAVE":
                return self._build_result(
                    format_name="Waveform Audio File (WAV)",
                    mime="audio/wav",
                    category=FileFormatCategory.AUDIO_VIDEO,
                    declared_ext=declared_ext,
                    canonical_exts=[".wav"],
                    has_rlo=has_rlo,
                    clean_name=clean_name,
                    has_null=has_null,
                    is_double_ext=is_double_ext,
                    inner_ext=inner_ext,
                    alerts=alerts,
                )
            elif riff_type == b"AVI ":
                return self._build_result(
                    format_name="Audio Video Interleave (AVI)",
                    mime="video/x-msvideo",
                    category=FileFormatCategory.AUDIO_VIDEO,
                    declared_ext=declared_ext,
                    canonical_exts=[".avi"],
                    has_rlo=has_rlo,
                    clean_name=clean_name,
                    has_null=has_null,
                    is_double_ext=is_double_ext,
                    inner_ext=inner_ext,
                    alerts=alerts,
                )

        # 5. Special check: ISO-BMFF / MP4 Container (ftyp at offset 4)
        if len(data) >= 8 and data[4:8] == b"ftyp":
            brand = data[8:12] if len(data) >= 12 else b""
            if brand in [b"heic", b"mif1", b"msf1", b"heix"]:
                return self._build_result(
                    format_name="High Efficiency Image Container (HEIC)",
                    mime="image/heic",
                    category=FileFormatCategory.IMAGE,
                    declared_ext=declared_ext,
                    canonical_exts=[".heic", ".heif"],
                    has_rlo=has_rlo,
                    clean_name=clean_name,
                    has_null=has_null,
                    is_double_ext=is_double_ext,
                    inner_ext=inner_ext,
                    alerts=alerts,
                )
            else:
                return self._build_result(
                    format_name="MPEG-4 Part 14 Video (MP4/QuickTime)",
                    mime="video/mp4",
                    category=FileFormatCategory.AUDIO_VIDEO,
                    declared_ext=declared_ext,
                    canonical_exts=[".mp4", ".m4v", ".mov", ".m4a"],
                    has_rlo=has_rlo,
                    clean_name=clean_name,
                    has_null=has_null,
                    is_double_ext=is_double_ext,
                    inner_ext=inner_ext,
                    alerts=alerts,
                )

        # 6. Special check: OpenXML Deep Inspection (ZIP containing [Content_Types].xml)
        if data.startswith(b"PK\x03\x04"):
            openxml_info = self._inspect_openxml(data)
            if openxml_info:
                fmt_name, mime, cat, canon_exts = openxml_info
                return self._build_result(
                    format_name=fmt_name,
                    mime=mime,
                    category=cat,
                    declared_ext=declared_ext,
                    canonical_exts=canon_exts,
                    has_rlo=has_rlo,
                    clean_name=clean_name,
                    has_null=has_null,
                    is_double_ext=is_double_ext,
                    inner_ext=inner_ext,
                    alerts=alerts,
                )

        # 7. Special check: Windows PE e_lfanew secondary check
        if data.startswith(b"MZ") and len(data) >= 64:
            try:
                e_lfanew = struct.unpack_from("<I", data, 60)[0]
                if 0 < e_lfanew < len(data) - 4 and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                    return self._build_result(
                        format_name="Windows Portable Executable (PE32/PE64)",
                        mime="application/vnd.microsoft.portable-executable",
                        category=FileFormatCategory.EXECUTABLE,
                        declared_ext=declared_ext,
                        canonical_exts=[
                            ".exe",
                            ".dll",
                            ".sys",
                            ".scr",
                            ".cpl",
                            ".ocx",
                            ".drv",
                        ],
                        has_rlo=has_rlo,
                        clean_name=clean_name,
                        has_null=has_null,
                        is_double_ext=is_double_ext,
                        inner_ext=inner_ext,
                        alerts=alerts,
                    )
            except Exception:
                pass

        # 8. Signature Match loop
        matched_sig: Optional[MagicByteSignature] = None
        for sig in self.signatures:
            try:
                magic_bytes = bytes.fromhex(sig.magic_hex)
                offset = sig.offset
                if len(data) >= offset + len(magic_bytes):
                    if data[offset : offset + len(magic_bytes)] == magic_bytes:
                        matched_sig = sig
                        break
            except Exception:
                continue

        if matched_sig:
            return self._build_result(
                format_name=matched_sig.name,
                mime=matched_sig.mime_type,
                category=matched_sig.category,
                declared_ext=declared_ext,
                canonical_exts=matched_sig.canonical_extensions,
                has_rlo=has_rlo,
                clean_name=clean_name,
                has_null=has_null,
                is_double_ext=is_double_ext,
                inner_ext=inner_ext,
                alerts=alerts,
            )

        # 9. Plaintext / Script heuristic fallback
        if self._is_printable_text(data[:1024]):
            first_line = data[:256].decode("utf-8", errors="ignore").strip().lower()
            if first_line.startswith(("<html", "<!doctype", "<?xml")):
                return self._build_result(
                    format_name="HTML / XML Web Markup",
                    mime="text/html",
                    category=FileFormatCategory.DOCUMENT,
                    declared_ext=declared_ext,
                    canonical_exts=[".html", ".htm", ".xml", ".svg"],
                    has_rlo=has_rlo,
                    clean_name=clean_name,
                    has_null=has_null,
                    is_double_ext=is_double_ext,
                    inner_ext=inner_ext,
                    alerts=alerts,
                )
            elif (
                "powershell" in first_line
                or "param(" in first_line
                or first_line.startswith(("@echo", "set ", "rem "))
            ):
                return self._build_result(
                    format_name="Windows Shell / Batch Script",
                    mime="text/x-batch",
                    category=FileFormatCategory.SCRIPT,
                    declared_ext=declared_ext,
                    canonical_exts=[".bat", ".cmd", ".ps1"],
                    has_rlo=has_rlo,
                    clean_name=clean_name,
                    has_null=has_null,
                    is_double_ext=is_double_ext,
                    inner_ext=inner_ext,
                    alerts=alerts,
                )
            else:
                return self._build_result(
                    format_name="Plaintext ASCII/UTF-8 Document",
                    mime="text/plain",
                    category=FileFormatCategory.DOCUMENT,
                    declared_ext=declared_ext,
                    canonical_exts=[".txt", ".log", ".csv", ".json", ".md", ".yml", ".yaml"],
                    has_rlo=has_rlo,
                    clean_name=clean_name,
                    has_null=has_null,
                    is_double_ext=is_double_ext,
                    inner_ext=inner_ext,
                    alerts=alerts,
                )

        # 10. Unidentified raw binary
        if declared_ext:
            is_mismatch = True
            alerts.append(
                f"Unidentified binary stream masquerading under declared extension '{declared_ext}'"
            )

        return FileTypeIdentification(
            is_identified=False,
            detected_format="Unrecognized Binary Stream",
            detected_mime="application/octet-stream",
            category=FileFormatCategory.UNKNOWN,
            declared_extension=declared_ext,
            canonical_extensions=[],
            is_extension_mismatch=is_mismatch,
            is_double_extension=is_double_ext,
            detected_inner_extension=inner_ext,
            has_null_byte_injection=has_null,
            has_right_to_left_override=has_rlo,
            rlo_clean_name=clean_name,
            confidence_score=0.1,
            forensic_alerts=alerts,
        )

    @classmethod
    def _inspect_openxml(
        cls, data: bytes
    ) -> Optional[Tuple[str, str, FileFormatCategory, List[str]]]:
        """Inspect internal ZIP table to identify specific Microsoft Office OpenXML format."""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                namelist = set(zf.namelist())
                if any(n.startswith("word/") for n in namelist):
                    return (
                        "Microsoft Word OpenXML Document (DOCX)",
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        FileFormatCategory.DOCUMENT,
                        [".docx", ".docm", ".dotx", ".dotm"],
                    )
                elif any(n.startswith("xl/") for n in namelist):
                    return (
                        "Microsoft Excel OpenXML Workbook (XLSX)",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        FileFormatCategory.DOCUMENT,
                        [".xlsx", ".xlsm", ".xltx", ".xltm"],
                    )
                elif any(n.startswith("ppt/") for n in namelist):
                    return (
                        "Microsoft PowerPoint OpenXML Presentation (PPTX)",
                        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                        FileFormatCategory.DOCUMENT,
                        [".pptx", ".pptm", ".potx", ".potm"],
                    )
                elif "mimetype" in namelist:
                    try:
                        mimetype_content = zf.read("mimetype").decode("utf-8", errors="ignore")
                        if "epub" in mimetype_content:
                            return (
                                "Electronic Publication (EPUB)",
                                "application/epub+zip",
                                FileFormatCategory.DOCUMENT,
                                [".epub"],
                            )
                    except Exception:
                        pass
        except Exception:
            pass
        return None

    @classmethod
    def _is_printable_text(cls, sample: bytes) -> bool:
        """Check if byte sample consists predominantly of printable ASCII / UTF-8 characters."""
        if not sample:
            return False
        printable_count = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
        return (printable_count / len(sample)) > 0.85

    @classmethod
    def _build_result(
        cls,
        format_name: str,
        mime: str,
        category: FileFormatCategory,
        declared_ext: str,
        canonical_exts: List[str],
        has_rlo: bool,
        clean_name: Optional[str],
        has_null: bool,
        is_double_ext: bool,
        inner_ext: Optional[str],
        alerts: List[str],
    ) -> FileTypeIdentification:
        """Build FileTypeIdentification model and evaluate extension spoofing mismatch."""
        local_alerts = list(alerts)
        is_mismatch = False

        if declared_ext:
            # Check if declared extension matches any canonical extensions for this true type
            if canonical_exts and declared_ext not in canonical_exts:
                is_mismatch = True
                if (
                    category == FileFormatCategory.EXECUTABLE
                    and declared_ext in BENIGN_CARRIER_EXTENSIONS
                ):
                    local_alerts.append(
                        f"CRITICAL EXTENSION SPOOFING: True file format '{format_name}' ({mime}) disguised as benign extension '{declared_ext}'"
                    )
                else:
                    local_alerts.append(
                        f"[HIGH] True file format '{format_name}' ({mime}) mismatches declared extension '{declared_ext}'"
                    )

        return FileTypeIdentification(
            is_identified=True,
            detected_format=format_name,
            detected_mime=mime,
            category=category,
            declared_extension=declared_ext,
            canonical_extensions=canonical_exts,
            is_extension_mismatch=is_mismatch,
            is_double_extension=is_double_ext,
            detected_inner_extension=inner_ext,
            has_null_byte_injection=has_null,
            has_right_to_left_override=has_rlo,
            rlo_clean_name=clean_name,
            confidence_score=0.95,
            forensic_alerts=local_alerts,
        )

    def analyze_bytes(
        self,
        data: bytes,
        filename: str = "evidence.bin",
    ) -> FileArtifactReport:
        """Analyze raw byte buffer, compute multi-algorithm cryptographic hashes, and evaluate threat score."""
        hashes = compute_bytes_hashes(data)
        ident = self.identify_bytes(data, filename=filename)

        # Threat Scoring Logic
        score = 0.0
        remediation: List[str] = []

        if ident.is_extension_mismatch:
            if (
                ident.category == FileFormatCategory.EXECUTABLE
                and ident.declared_extension in BENIGN_CARRIER_EXTENSIONS
            ):
                score += 85.0
                remediation.append(
                    f"CRITICAL: Isolate file immediately. Disguised binary executable payload disguised as benign '{ident.declared_extension}' format."
                )
            else:
                score += 45.0
                remediation.append(
                    "Investigate extension mismatch. File header does not match declared extension."
                )

        if ident.has_right_to_left_override:
            score += 75.0
            remediation.append(
                "Block attachment. Unicode Right-to-Left Override (RLO) indicates intentional user deception."
            )

        if ident.is_double_extension:
            score += 65.0
            remediation.append(
                "Block attachment. Double-extension pattern used to trick email recipients into executing payloads."
            )

        if ident.has_null_byte_injection:
            score += 50.0
            remediation.append(
                "Null-byte injection in filename indicates evasion attempt against legacy forensic tools."
            )

        if (
            ident.category == FileFormatCategory.EXECUTABLE
            and ident.declared_extension in DANGEROUS_EXECUTABLE_EXTENSIONS
        ):
            score = max(score, 35.0)
            remediation.append(
                "Direct executable attachment. Ensure binary static analysis and dynamic sandbox detonation."
            )

        score = min(100.0, max(0.0, score))
        is_suspicious = score >= 25.0

        if score >= 75.0:
            severity = RiskSeverity.MALICIOUS_HIGH
            summary = f"CRITICAL THREAT: File '{filename}' is a disguised executable or malicious payload (Score: {score:.1f}/100)."
        elif score >= 50.0:
            severity = RiskSeverity.SUSPICIOUS_MEDIUM
            summary = f"HIGH SUSPICION: File '{filename}' exhibits extension mismatch or evasion indicators (Score: {score:.1f}/100)."
        elif score >= 25.0:
            severity = RiskSeverity.SUSPICIOUS_LOW
            summary = f"SUSPICIOUS: File '{filename}' has anomalous naming or dangerous executable format (Score: {score:.1f}/100)."
        else:
            severity = RiskSeverity.CLEAN
            summary = f"CLEAN: File '{filename}' verified as authentic '{ident.detected_format}' with zero tampering indicators."

        if not remediation:
            remediation.append(
                "No immediate binary anomalies detected. Maintain standard file execution controls."
            )

        return FileArtifactReport(
            file_path=None,
            filename=filename,
            size_bytes=len(data),
            hashes=hashes,
            identification=ident,
            is_suspicious=is_suspicious,
            threat_severity=severity,
            threat_score=score,
            summary=summary,
            remediation_advice=remediation,
        )

    def analyze_file(
        self,
        file_path: Union[str, Path],
    ) -> FileArtifactReport:
        """Analyze a file from disk, guaranteeing zero byte mutation (ISO/IEC 27037)."""
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"Target binary artifact file not found: {file_path}")

        hashes = compute_file_hashes(p)
        data = p.read_bytes()
        report = self.analyze_bytes(data, filename=p.name)
        report.file_path = str(p.resolve())
        report.hashes = hashes
        return report
