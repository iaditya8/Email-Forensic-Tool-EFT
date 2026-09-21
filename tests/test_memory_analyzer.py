"""Unit tests for MemoryArtifactAnalyzer and memory forensics models."""

import struct
from pathlib import Path

import pytest

from eft.analysis.memory_analyzer import MemoryArtifactAnalyzer
from eft.models.memory_forensics import (
    MemoryDumpFormat,
    StringEncoding,
)


@pytest.fixture
def memory_analyzer() -> MemoryArtifactAnalyzer:
    """Provide a fresh MemoryArtifactAnalyzer instance."""
    return MemoryArtifactAnalyzer(default_chunk_size=1024)


def test_identify_format_empty(memory_analyzer: MemoryArtifactAnalyzer) -> None:
    """Verify that empty header returns invalid metadata."""
    meta = memory_analyzer.identify_format(b"", file_size=0)
    assert not meta.is_valid
    assert meta.format == MemoryDumpFormat.UNKNOWN
    assert meta.magic_bytes_hex == ""


def test_identify_format_microsoft_crash_dump_64(memory_analyzer: MemoryArtifactAnalyzer) -> None:
    """Verify detection of 64-bit Microsoft Crash Dumps (PAGEDU64)."""
    # Header: PAGEDU64 + major(15), minor(19041), DTB(0x1AA000)
    header = (
        b"PAGEDU64" + struct.pack("<II", 15, 19041) + struct.pack("<Q", 0x1AA000) + b"\x00" * 64
    )
    meta = memory_analyzer.identify_format(header, file_size=len(header), file_path="memory.dmp")
    assert meta.is_valid
    assert meta.format == MemoryDumpFormat.MICROSOFT_CRASH_DUMP_64
    assert meta.architecture == "x64"
    assert meta.header_details.get("major_version") == 15
    assert meta.header_details.get("minor_version") == 19041
    assert "0x1aa000" in str(meta.header_details.get("directory_table_base"))


def test_identify_format_microsoft_crash_dump_32(memory_analyzer: MemoryArtifactAnalyzer) -> None:
    """Verify detection of 32-bit Microsoft Crash Dumps (PAGEDUMP)."""
    header = b"PAGEDUMP" + struct.pack("<II", 15, 7601) + struct.pack("<I", 0x39000) + b"\x00" * 32
    meta = memory_analyzer.identify_format(header, file_size=len(header), file_path="crash32.dmp")
    assert meta.is_valid
    assert meta.format == MemoryDumpFormat.MICROSOFT_CRASH_DUMP_32
    assert meta.architecture == "x86"
    assert meta.header_details.get("major_version") == 15
    assert meta.header_details.get("minor_version") == 7601


def test_identify_format_lime(memory_analyzer: MemoryArtifactAnalyzer) -> None:
    """Verify detection of Linux Memory Extractor (LiME) image format."""
    # LiME header: magic (0x4c694d45), version(1), start(0x0000), end(0xFFFFFFFF)
    header = struct.pack("<IIQQ", 0x4C694D45, 1, 0x00000000, 0xFFFFFFFF) + b"\x00" * 32
    meta = memory_analyzer.identify_format(header, file_size=len(header), file_path="ram.lime")
    assert meta.is_valid
    assert meta.format == MemoryDumpFormat.LIME_DUMP
    assert meta.architecture == "linux_x86_or_x64"
    assert meta.header_details.get("version") == 1


def test_identify_format_elf_core(memory_analyzer: MemoryArtifactAnalyzer) -> None:
    """Verify detection of ELF Core Dumps."""
    # ELF: \x7fELF, class=2 (64-bit), data=1 (LE), ver=1, abi=0, pad(8), e_type=4 (ET_CORE), e_machine=0x3E (x86_64)
    header = (
        b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8 + struct.pack("<HH", 4, 0x3E) + b"\x00" * 32
    )
    meta = memory_analyzer.identify_format(header, file_size=len(header), file_path="core.dump")
    assert meta.is_valid
    assert meta.format == MemoryDumpFormat.ELF_CORE_DUMP
    assert meta.architecture == "x86_64"
    assert meta.header_details.get("is_core_dump") is True


def test_identify_format_vmem(memory_analyzer: MemoryArtifactAnalyzer) -> None:
    """Verify VMware VMEM detection from file extension."""
    data = b"\x00" * 1024
    meta = memory_analyzer.identify_format(
        data, file_size=1024, file_path="Windows10-Snapshot.vmem"
    )
    assert meta.is_valid
    assert meta.format == MemoryDumpFormat.VMWARE_VMEM


def test_identify_format_raw_linear(memory_analyzer: MemoryArtifactAnalyzer) -> None:
    """Verify Raw Linear memory image identification."""
    data = b"\x90\x90\x90\x90" * 256
    meta = memory_analyzer.identify_format(data, file_size=1024, file_path="physical_memory.raw")
    assert meta.is_valid
    assert meta.format == MemoryDumpFormat.RAW_LINEAR


def test_extract_strings_ascii_and_utf16(memory_analyzer: MemoryArtifactAnalyzer) -> None:
    """Verify accurate extraction and byte offset tracking for ASCII and UTF-16LE strings."""
    # Build a byte stream with padding and embedded strings
    ascii_str = b"cmd.exe /c powershell -enc JABhID0A"
    utf16_str = "C:\\Windows\\System32\\svchost.exe".encode("utf-16le")

    buffer = bytearray(200)
    # Insert ASCII string at offset 20
    buffer[20 : 20 + len(ascii_str)] = ascii_str
    # Insert UTF-16LE string at offset 100
    buffer[100 : 100 + len(utf16_str)] = utf16_str

    items = list(memory_analyzer.extract_strings_stream(bytes(buffer), min_length=4))

    assert len(items) == 2
    # ASCII string check
    assert items[0].offset == 20
    assert items[0].encoding == StringEncoding.ASCII
    assert items[0].value == "cmd.exe /c powershell -enc JABhID0A"
    assert items[0].length == len(items[0].value)

    # UTF-16LE string check
    assert items[1].offset == 100
    assert items[1].encoding == StringEncoding.UTF16_LE
    assert items[1].value == "C:\\Windows\\System32\\svchost.exe"
    assert items[1].length == len("C:\\Windows\\System32\\svchost.exe")


def test_chunk_boundary_overlap(memory_analyzer: MemoryArtifactAnalyzer) -> None:
    """Verify that strings spanning across streaming chunk boundaries are extracted completely without truncation."""
    # Chunk size is small (e.g. 64 bytes)
    chunk_size = 64
    long_string = "SUPER_SECRET_AUTHENTICATION_TOKEN_EXFILTRATION_PAYLOAD_12345"

    # Place the string such that it spans chunk boundary between offset 50 and 110
    raw_data = bytearray(256)
    raw_data[50 : 50 + len(long_string)] = long_string.encode("ascii")

    items = list(
        memory_analyzer.extract_strings_stream(bytes(raw_data), min_length=4, chunk_size=chunk_size)
    )

    found = [it for it in items if long_string in it.value]
    assert len(found) == 1
    assert found[0].offset == 50
    assert found[0].value == long_string


def test_min_length_filter(memory_analyzer: MemoryArtifactAnalyzer) -> None:
    """Verify that strings below min_length threshold are omitted."""
    data = b"\x00\x00abc\x00\x00longstring\x00\x00"
    items = list(memory_analyzer.extract_strings_stream(data, min_length=6))
    assert len(items) == 1
    assert items[0].value == "longstring"


def test_analyze_full_report(tmp_path: Path, memory_analyzer: MemoryArtifactAnalyzer) -> None:
    """Verify comprehensive analyze() execution on disk image file."""
    image_file = tmp_path / "test_memory.raw"
    payload = (
        b"\x00" * 64
        + b"MALWARE_BEACON_C2_HOST: http://evil-command-control.com/beacon"
        + b"\x00" * 32
        + "Authorization: Bearer secret_jwt_token_here".encode("utf-16le")
        + b"\x00" * 128
    )
    image_file.write_bytes(payload)

    report = memory_analyzer.analyze(image_file, min_length=4, max_samples=10)

    assert report.evidence_path == str(image_file)
    assert len(report.evidence_hashes["md5"]) == 32
    assert len(report.evidence_hashes["sha256"]) == 64
    assert report.metadata.format == MemoryDumpFormat.RAW_LINEAR
    assert report.statistics.total_strings >= 2
    assert report.statistics.ascii_count >= 1
    assert report.statistics.utf16_count >= 1
    assert len(report.strings_sample) >= 2
    assert report.total_extracted_count == report.statistics.total_strings


def test_file_not_found_raises(memory_analyzer: MemoryArtifactAnalyzer) -> None:
    """Verify FileNotFoundError is raised for non-existent evidence paths."""
    with pytest.raises(FileNotFoundError):
        memory_analyzer.analyze("C:\\non_existent_memory_dump_path_12345.raw")
