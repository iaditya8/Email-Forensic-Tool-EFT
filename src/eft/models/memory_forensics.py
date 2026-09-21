"""Pydantic data models for memory and volatile process forensic extraction."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MemoryDumpFormat(str, Enum):
    """Recognized memory dump acquisition file formats."""

    RAW_LINEAR = "RAW_LINEAR"
    MICROSOFT_CRASH_DUMP_32 = "MICROSOFT_CRASH_DUMP_32"
    MICROSOFT_CRASH_DUMP_64 = "MICROSOFT_CRASH_DUMP_64"
    ELF_CORE_DUMP = "ELF_CORE_DUMP"
    LIME_DUMP = "LIME_DUMP"
    VMWARE_VMEM = "VMWARE_VMEM"
    UNKNOWN = "UNKNOWN"


class StringEncoding(str, Enum):
    """Character encoding type of extracted memory string."""

    ASCII = "ASCII"
    UTF16_LE = "UTF-16LE"


class ExtractedStringItem(BaseModel):
    """Canonical model for a single extracted string artifact."""

    model_config = ConfigDict(frozen=True)

    offset: int = Field(..., description="Absolute byte offset within the memory image")
    encoding: StringEncoding = Field(..., description="Character encoding format")
    value: str = Field(..., description="Extracted text string value")
    length: int = Field(..., description="Length of the extracted string in characters")


class MemoryDumpMetadata(BaseModel):
    """Metadata extracted from memory dump file header."""

    model_config = ConfigDict(frozen=True)

    format: MemoryDumpFormat = Field(
        default=MemoryDumpFormat.UNKNOWN, description="Identified memory image format"
    )
    size_bytes: int = Field(default=0, description="Total size of the memory image in bytes")
    magic_bytes_hex: str = Field(
        default="", description="Hexadecimal representation of leading magic bytes"
    )
    architecture: str = Field(
        default="unknown", description="Architecture clue (x86, x64, arm, or unknown)"
    )
    header_details: dict[str, Any] = Field(
        default_factory=dict, description="Parsed header fields specific to image format"
    )
    is_valid: bool = Field(
        default=True, description="Whether the memory dump file is accessible and non-empty"
    )


class StringStatistics(BaseModel):
    """Statistical metrics for extracted string artifacts."""

    model_config = ConfigDict(frozen=True)

    total_strings: int = Field(default=0, description="Total number of strings extracted")
    ascii_count: int = Field(default=0, description="Count of ASCII strings extracted")
    utf16_count: int = Field(default=0, description="Count of UTF-16LE strings extracted")
    avg_string_length: float = Field(
        default=0.0, description="Average character length of extracted strings"
    )
    longest_string_length: int = Field(
        default=0, description="Length of the longest extracted string"
    )
    printable_ratio: float = Field(
        default=0.0, description="Estimated ratio of printable string content across analyzed data"
    )


class MemoryExtractionReport(BaseModel):
    """Master report containing memory dump ingestion and string extraction results."""

    model_config = ConfigDict(frozen=True)

    evidence_path: str = Field(..., description="Path or identifier of the analyzed memory image")
    evidence_hashes: dict[str, str] = Field(
        default_factory=dict, description="Cryptographic acquisition hashes (md5, sha256)"
    )
    metadata: MemoryDumpMetadata = Field(
        default_factory=MemoryDumpMetadata, description="Memory image format and header metadata"
    )
    statistics: StringStatistics = Field(
        default_factory=StringStatistics, description="Aggregate string extraction metrics"
    )
    strings_sample: list[ExtractedStringItem] = Field(
        default_factory=list,
        description="Representative sample of extracted strings for triage inspection",
    )
    total_extracted_count: int = Field(
        default=0, description="Total number of extracted strings meeting min length criteria"
    )
    analysis_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the memory extraction analysis",
    )
