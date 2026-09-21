"""Memory Dump Ingestion & High-Speed Binary String Extractor."""

from __future__ import annotations

import hashlib
import io
import re
import struct
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from eft.models.memory_forensics import (
    ExtractedStringItem,
    MemoryDumpFormat,
    MemoryDumpMetadata,
    MemoryExtractionReport,
    StringEncoding,
    StringStatistics,
)


class MemoryArtifactAnalyzer:
    """Forensic analyzer for raw and formatted RAM dumps and high-speed string extraction.

    Implements streaming multi-hash computation, format detection (raw, Microsoft crash dump,
    LiME, ELF core), and streaming regex-based string extraction (ASCII and UTF-16LE)
    with chunk overlap resolution to support multi-gigabyte acquisitions in memory-constrained environments.
    """

    # Magic signatures
    _MAGIC_CRASH_DUMP_32 = b"PAGEDUMP"  # or PAGE
    _MAGIC_CRASH_DUMP_64 = b"PAGEDU64"
    _MAGIC_PAGE_PREFIX = b"PAGE"
    _MAGIC_LIME = b"EMiL\x01\x00\x00\x00"
    _MAGIC_ELF = b"\x7fELF"

    def __init__(self, default_chunk_size: int = 1024 * 1024) -> None:
        """Initialize analyzer with default chunk size (default 1MB)."""
        self.default_chunk_size = default_chunk_size

    def identify_format(
        self, header_bytes: bytes, file_size: int = 0, file_path: str = ""
    ) -> MemoryDumpMetadata:
        """Inspect leading header bytes and path to determine memory image format and metadata.

        Args:
            header_bytes: First 4096 bytes of the memory dump.
            file_size: Total file size in bytes.
            file_path: Optional filename/path for extension hints.

        Returns:
            MemoryDumpMetadata model.
        """
        if not header_bytes:
            return MemoryDumpMetadata(
                format=MemoryDumpFormat.UNKNOWN,
                size_bytes=file_size,
                magic_bytes_hex="",
                architecture="unknown",
                header_details={},
                is_valid=False,
            )

        magic_hex = header_bytes[:16].hex()
        hdr_len = len(header_bytes)

        # 1. Microsoft 64-bit Crash Dump
        if header_bytes.startswith(self._MAGIC_CRASH_DUMP_64):
            details: dict[str, Any] = {"signature": "PAGEDU64"}
            if hdr_len >= 0x30:
                try:
                    # Parse crash dump header fields (64-bit)
                    # MajorVersion, MinorVersion, DirectoryTableBase, PfnDataBase
                    major, minor = struct.unpack_from("<II", header_bytes, 0x08)
                    dtb = struct.unpack_from("<Q", header_bytes, 0x10)[0]
                    details["major_version"] = major
                    details["minor_version"] = minor
                    details["directory_table_base"] = hex(dtb)
                except Exception:
                    pass
            return MemoryDumpMetadata(
                format=MemoryDumpFormat.MICROSOFT_CRASH_DUMP_64,
                size_bytes=file_size,
                magic_bytes_hex=magic_hex,
                architecture="x64",
                header_details=details,
                is_valid=True,
            )

        # 2. Microsoft 32-bit Crash Dump
        if header_bytes.startswith(self._MAGIC_CRASH_DUMP_32) or (
            header_bytes.startswith(self._MAGIC_PAGE_PREFIX)
            and not header_bytes.startswith(self._MAGIC_CRASH_DUMP_64)
        ):
            details = {"signature": "PAGE/PAGEDUMP"}
            if hdr_len >= 0x20:
                try:
                    major, minor = struct.unpack_from("<II", header_bytes, 0x08)
                    dtb = struct.unpack_from("<I", header_bytes, 0x10)[0]
                    details["major_version"] = major
                    details["minor_version"] = minor
                    details["directory_table_base"] = hex(dtb)
                except Exception:
                    pass
            return MemoryDumpMetadata(
                format=MemoryDumpFormat.MICROSOFT_CRASH_DUMP_32,
                size_bytes=file_size,
                magic_bytes_hex=magic_hex,
                architecture="x86",
                header_details=details,
                is_valid=True,
            )

        # 3. LiME (Linux Memory Extractor) Dump
        if header_bytes.startswith(self._MAGIC_LIME) or header_bytes[:4] == b"EMiL":
            details = {"signature": "LiME"}
            if hdr_len >= 32:
                try:
                    magic, version, s_addr, e_addr = struct.unpack_from("<IIQQ", header_bytes, 0)
                    details["magic"] = hex(magic)
                    details["version"] = version
                    details["start_address"] = hex(s_addr)
                    details["end_address"] = hex(e_addr)
                except Exception:
                    pass
            return MemoryDumpMetadata(
                format=MemoryDumpFormat.LIME_DUMP,
                size_bytes=file_size,
                magic_bytes_hex=magic_hex,
                architecture="linux_x86_or_x64",
                header_details=details,
                is_valid=True,
            )

        # 4. ELF Core Dump
        if header_bytes.startswith(self._MAGIC_ELF):
            details = {"signature": "ELF"}
            arch = "unknown"
            if hdr_len >= 18:
                try:
                    ei_class = header_bytes[4]  # 1 = 32-bit, 2 = 64-bit
                    e_type = struct.unpack_from("<H", header_bytes, 16)[0]
                    e_machine = struct.unpack_from("<H", header_bytes, 18)[0]
                    details["ei_class"] = "64-bit" if ei_class == 2 else "32-bit"
                    details["e_type"] = e_type
                    details["is_core_dump"] = e_type == 4  # ET_CORE = 4
                    arch = "x64" if ei_class == 2 else "x86"
                    if e_machine == 0x3E:
                        arch = "x86_64"
                    elif e_machine == 0x03:
                        arch = "i386"
                    elif e_machine == 0xB7:
                        arch = "aarch64"
                except Exception:
                    pass
            return MemoryDumpMetadata(
                format=MemoryDumpFormat.ELF_CORE_DUMP,
                size_bytes=file_size,
                magic_bytes_hex=magic_hex,
                architecture=arch,
                header_details=details,
                is_valid=True,
            )

        # 5. VMware VMEM check
        path_lower = file_path.lower()
        if path_lower.endswith(".vmem"):
            return MemoryDumpMetadata(
                format=MemoryDumpFormat.VMWARE_VMEM,
                size_bytes=file_size,
                magic_bytes_hex=magic_hex,
                architecture="unknown",
                header_details={"format_hint": "VMware Virtual Machine Memory"},
                is_valid=True,
            )

        # 6. Raw Linear RAM Image
        return MemoryDumpMetadata(
            format=MemoryDumpFormat.RAW_LINEAR,
            size_bytes=file_size,
            magic_bytes_hex=magic_hex,
            architecture="unknown",
            header_details={"description": "Raw linear memory acquisition image"},
            is_valid=True,
        )

    def extract_strings_stream(
        self,
        stream_or_path: str | Path | bytes | BinaryIO,
        min_length: int = 4,
        chunk_size: int | None = None,
    ) -> Iterator[ExtractedStringItem]:
        """Stream extracted ASCII and UTF-16LE strings with exact byte offsets.

        Uses memory-efficient sliding buffer chunking to process multi-gigabyte memory
        images while resolving strings that span across chunk boundaries.

        Args:
            stream_or_path: File path, bytes, or BinaryIO stream.
            min_length: Minimum character length of printable strings (default 4).
            chunk_size: Processing chunk buffer size in bytes (default self.default_chunk_size).

        Yields:
            ExtractedStringItem instances.
        """
        c_size = chunk_size or self.default_chunk_size
        ascii_pattern = re.compile(rb"[\x20-\x7E]{" + str(min_length).encode("ascii") + rb",}")
        utf16_pattern = re.compile(
            rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode("ascii") + rb",}"
        )

        stream, should_close = self._get_binary_stream(stream_or_path)

        try:
            buffer = bytearray()
            stream_offset = 0  # Absolute offset of the start of `buffer` in the stream
            overlap_reserve = 4096  # Overlap buffer size to avoid boundary string slicing

            while True:
                chunk = stream.read(c_size)
                is_eof = len(chunk) == 0

                if chunk:
                    buffer.extend(chunk)

                if not buffer:
                    break

                # If EOF, we inspect the entire remaining buffer
                scan_limit = len(buffer) if is_eof else max(0, len(buffer) - overlap_reserve)

                # Find all ASCII strings
                ascii_matches: list[tuple[int, int, StringEncoding, str]] = []
                for match in ascii_pattern.finditer(buffer):
                    start, end = match.start(), match.end()
                    if start < scan_limit or is_eof:
                        text = match.group(0).decode("ascii", errors="replace")
                        ascii_matches.append((start, end, StringEncoding.ASCII, text))

                # Find all UTF-16LE strings
                utf16_matches: list[tuple[int, int, StringEncoding, str]] = []
                for match in utf16_pattern.finditer(buffer):
                    start, end = match.start(), match.end()
                    if start < scan_limit or is_eof:
                        raw_bytes = match.group(0)
                        text = raw_bytes.decode("utf-16le", errors="replace")
                        utf16_matches.append((start, end, StringEncoding.UTF16_LE, text))

                # Merge and sort matches by start offset
                all_matches = sorted(ascii_matches + utf16_matches, key=lambda x: x[0])

                # Determine how much of the buffer was safely consumed
                last_consumed_rel_offset = 0
                for start, end, enc, text in all_matches:
                    abs_offset = stream_offset + start
                    yield ExtractedStringItem(
                        offset=abs_offset,
                        encoding=enc,
                        value=text,
                        length=len(text),
                    )
                    last_consumed_rel_offset = max(last_consumed_rel_offset, end)

                if is_eof:
                    break

                # Advance buffer: slide forward by scan_limit
                consumed_bytes = scan_limit
                del buffer[:consumed_bytes]
                stream_offset += consumed_bytes

        finally:
            if should_close:
                stream.close()

    def analyze(
        self,
        stream_or_path: str | Path | bytes | BinaryIO,
        min_length: int = 4,
        max_samples: int = 1000,
        chunk_size: int | None = None,
    ) -> MemoryExtractionReport:
        """Perform comprehensive memory dump ingestion, hashing, format identification, and string extraction.

        Args:
            stream_or_path: File path, bytes, or BinaryIO stream.
            min_length: Minimum character length for string extraction (default 4).
            max_samples: Maximum string items to preserve in the report's `strings_sample` list.
            chunk_size: Streaming chunk size in bytes.

        Returns:
            MemoryExtractionReport with forensic hashes, metadata, statistics, and string sample.
        """
        evidence_path = (
            str(stream_or_path)
            if isinstance(stream_or_path, (str, Path))
            else "<memory_stream_buffer>"
        )

        # 1. Compute cryptographic hashes & extract header
        stream, should_close = self._get_binary_stream(stream_or_path)
        md5_hasher = hashlib.md5()
        sha256_hasher = hashlib.sha256()

        header_bytes = b""
        total_bytes = 0
        c_size = chunk_size or self.default_chunk_size

        try:
            first_chunk = stream.read(c_size)
            if first_chunk:
                header_bytes = first_chunk[:4096]
                total_bytes += len(first_chunk)
                md5_hasher.update(first_chunk)
                sha256_hasher.update(first_chunk)

                while True:
                    chunk = stream.read(c_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    md5_hasher.update(chunk)
                    sha256_hasher.update(chunk)
        finally:
            if should_close:
                stream.close()

        evidence_hashes = {
            "md5": md5_hasher.hexdigest(),
            "sha256": sha256_hasher.hexdigest(),
        }

        # 2. Format Identification
        metadata = self.identify_format(
            header_bytes=header_bytes,
            file_size=total_bytes,
            file_path=evidence_path,
        )

        # 3. String Extraction & Statistics
        total_strings = 0
        ascii_count = 0
        utf16_count = 0
        total_chars = 0
        longest_len = 0
        sample_list: list[ExtractedStringItem] = []

        for item in self.extract_strings_stream(
            stream_or_path, min_length=min_length, chunk_size=c_size
        ):
            total_strings += 1
            if item.encoding == StringEncoding.ASCII:
                ascii_count += 1
            else:
                utf16_count += 1

            total_chars += item.length
            if item.length > longest_len:
                longest_len = item.length

            if len(sample_list) < max_samples:
                sample_list.append(item)

        avg_len = (total_chars / total_strings) if total_strings > 0 else 0.0
        printable_ratio = (total_chars / total_bytes) if total_bytes > 0 else 0.0

        statistics = StringStatistics(
            total_strings=total_strings,
            ascii_count=ascii_count,
            utf16_count=utf16_count,
            avg_string_length=round(avg_len, 2),
            longest_string_length=longest_len,
            printable_ratio=round(printable_ratio, 4),
        )

        return MemoryExtractionReport(
            evidence_path=evidence_path,
            evidence_hashes=evidence_hashes,
            metadata=metadata,
            statistics=statistics,
            strings_sample=sample_list,
            total_extracted_count=total_strings,
        )

    def _get_binary_stream(
        self, stream_or_path: str | Path | bytes | BinaryIO
    ) -> tuple[BinaryIO, bool]:
        """Convert input path, bytes, or stream into a readable binary stream and close flag."""
        if isinstance(stream_or_path, (str, Path)):
            path = Path(stream_or_path)
            if not path.exists():
                raise FileNotFoundError(f"Memory dump file not found: {path}")
            return open(path, "rb"), True
        elif isinstance(stream_or_path, bytes):
            return io.BytesIO(stream_or_path), False
        elif hasattr(stream_or_path, "read"):
            # If already a stream, ensure seek(0) if seekable
            if hasattr(stream_or_path, "seek") and stream_or_path.seekable():
                stream_or_path.seek(0)
            return stream_or_path, False
        else:
            raise ValueError(f"Unsupported memory image input type: {type(stream_or_path)}")
