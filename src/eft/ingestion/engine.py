"""Master Ingestion Engine for Email Forensic Tool (EFT)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional, Union

from eft.core.exceptions import (
    CorruptFileError,
    EvidenceTamperedException,
    ForensicIngestionError,
    UnsupportedFormatError,
)
from eft.core.integrity import compute_bytes_hashes, compute_file_hashes
from eft.ingestion.base import BaseEmailParser
from eft.ingestion.eml_parser import EMLParser
from eft.ingestion.mbox_parser import MBOXParser
from eft.ingestion.msg_parser import MSGParser
from eft.models.canonical import IngestionResult, SourceFileInfo

logger = logging.getLogger(__name__)

# Standard OLE Compound File Binary Format magic signature
OLE_MAGIC_HEADER = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class EmailIngester:
    """Forensic ingestion engine supporting multi-format parsing with immutability guarantees."""

    def __init__(self) -> None:
        self._parsers: Dict[str, BaseEmailParser] = {
            "eml": EMLParser(),
            "msg": MSGParser(),
            "mbox": MBOXParser(),
        }

    def register_parser(self, format_name: str, parser: BaseEmailParser) -> None:
        """Register or override a parser for a specific email format."""
        self._parsers[format_name.lower()] = parser

    def ingest_file(self, file_path: Union[str, Path]) -> IngestionResult:
        """Ingest an email evidence file from disk.

        Performs:
        1. Pre-analysis cryptographic multi-hashing (MD5, SHA-1, SHA-256).
        2. Format detection via extension and magic byte validation.
        3. Strict read-only ingestion into CanonicalEmail models.
        4. Post-analysis hash validation to ensure zero evidence contamination.

        Args:
            file_path: Path to the target evidence file.

        Returns:
            IngestionResult containing parsed CanonicalEmail list and evidence metadata.

        Raises:
            FileNotFoundError: If the file does not exist.
            UnsupportedFormatError: If format cannot be determined or supported.
            EvidenceTamperedException: If post-analysis hash differs from pre-analysis hash.
            CorruptFileError: If file structure is corrupt or invalid.
        """
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Target email evidence file not found: {path}")
        if not path.is_file():
            raise ForensicIngestionError(f"Target path is not a regular file: {path}")

        file_size = path.stat().st_size
        if file_size == 0:
            raise CorruptFileError(f"Evidence file is empty (0 bytes): {path.name}")

        # Step 1: Pre-analysis cryptographic multi-hashing
        pre_hashes = compute_file_hashes(path)
        file_format = self._detect_format_from_file(path)

        source_info = SourceFileInfo(
            file_path=str(path),
            file_name=path.name,
            file_format=file_format,
            file_size_bytes=file_size,
            hashes=pre_hashes,
        )

        logger.info(
            "Ingesting %s (format=%s, size=%d bytes, sha256=%s)",
            source_info.file_name,
            source_info.file_format,
            source_info.file_size_bytes,
            source_info.hashes.get("sha256"),
        )

        parser = self._parsers.get(file_format)
        if not parser:
            raise UnsupportedFormatError(
                f"Unsupported email format '{file_format}' for file {path.name}"
            )

        # Step 2: Parse file strictly in read-only mode
        try:
            messages = parser.parse(path, source_info)
        except (CorruptFileError, UnsupportedFormatError, ForensicIngestionError):
            raise
        except Exception as e:
            raise ForensicIngestionError(f"Unexpected ingestion failure on {path.name}: {e}") from e

        # Step 3: Post-analysis tamper verification
        post_hashes = compute_file_hashes(path)
        if post_hashes["sha256"] != pre_hashes["sha256"]:
            logger.critical(
                "EVIDENCE TAMPERING DETECTED for %s! Pre SHA-256=%s, Post SHA-256=%s",
                path.name,
                pre_hashes["sha256"],
                post_hashes["sha256"],
            )
            raise EvidenceTamperedException(
                f"Evidence integrity violation: Checksum changed during parsing of {path.name}"
            )

        return IngestionResult(
            source_file=source_info,
            messages=messages,
            total_messages=len(messages),
            success=True,
            errors=[],
            post_analysis_hash=post_hashes["sha256"],
            tamper_verified=True,
        )

    def ingest_bytes(
        self,
        data: bytes,
        file_name: str = "stream_evidence.eml",
        forced_format: Optional[str] = None,
    ) -> IngestionResult:
        """Ingest raw email binary data directly from memory."""
        if not data:
            raise CorruptFileError("Provided byte buffer is empty (0 bytes).")

        hashes = compute_bytes_hashes(data)
        file_format = (
            forced_format.lower()
            if forced_format
            else self._detect_format_from_bytes(data, file_name)
        )

        source_info = SourceFileInfo(
            file_path="<memory>",
            file_name=file_name,
            file_format=file_format,
            file_size_bytes=len(data),
            hashes=hashes,
        )

        parser = self._parsers.get(file_format)
        if not parser:
            raise UnsupportedFormatError(
                f"Unsupported email format '{file_format}' for stream buffer."
            )

        messages = parser.parse(data, source_info)

        return IngestionResult(
            source_file=source_info,
            messages=messages,
            total_messages=len(messages),
            success=True,
            errors=[],
            post_analysis_hash=hashes["sha256"],
            tamper_verified=True,
        )

    def _detect_format_from_file(self, path: Path) -> str:
        """Determine email format based on file extension and magic byte heuristics."""
        ext = path.suffix.lower().lstrip(".")
        if ext in ["eml", "msg", "mbox"]:
            return ext

        # Inspect header bytes if extension is missing or non-standard
        try:
            with open(path, "rb") as f:
                header_bytes = f.read(512)
            return self._detect_format_from_bytes(header_bytes, path.name)
        except Exception as e:
            raise UnsupportedFormatError(
                f"Cannot determine email format for {path.name}: {e}"
            ) from e

    def _detect_format_from_bytes(self, header_bytes: bytes, file_name: str) -> str:
        """Inspect magic bytes and text patterns to deduce format."""
        if header_bytes.startswith(OLE_MAGIC_HEADER):
            return "msg"

        if header_bytes.startswith(b"From ") or b"\nFrom " in header_bytes:
            return "mbox"

        # Check for typical RFC 5322 headers
        sample_text = header_bytes[:512].decode("latin-1", errors="ignore").lower()
        rfc_headers = [
            "received:",
            "from:",
            "to:",
            "subject:",
            "date:",
            "message-id:",
            "mime-version:",
        ]
        if any(h in sample_text for h in rfc_headers):
            return "eml"

        # Fallback to extension if present in filename
        if "." in file_name:
            ext = file_name.rsplit(".", 1)[-1].lower()
            if ext in ["eml", "msg", "mbox"]:
                return ext

        raise UnsupportedFormatError(
            f"Unable to recognize email format from file signature or contents: {file_name}"
        )
