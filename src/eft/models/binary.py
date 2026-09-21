"""Forensic data models for binary file artifact identification and integrity analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from eft.models.threat import RiskSeverity


class FileFormatCategory(str, Enum):
    """Categorization of binary and document formats."""

    EXECUTABLE = "Executable / Binary Payload"
    DOCUMENT = "Document / Office Document"
    ARCHIVE = "Archive / Compressed Container"
    IMAGE = "Raster / Vector Image"
    AUDIO_VIDEO = "Audio / Video Media"
    SCRIPT = "Script / Interpreted Code"
    DATABASE = "Database / Storage Format"
    FONT = "Font / Typography"
    SECURITY_CERT = "Security Certificate / Key"
    EMAIL_DATA = "Email Artifact / Message Store"
    UNKNOWN = "Unknown / Raw Binary Stream"


class MagicByteSignature(BaseModel):
    """Signature definition for binary magic byte detection."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    mime_type: str
    category: FileFormatCategory
    magic_hex: str
    offset: int = 0
    canonical_extensions: List[str] = Field(default_factory=list)
    secondary_magic_hex: Optional[str] = None
    secondary_offset: Optional[int] = None
    description: str = ""


class FileTypeIdentification(BaseModel):
    """Result of deep magic byte inspection and extension validation."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    is_identified: bool = False
    detected_format: str = "Unknown Format"
    detected_mime: str = "application/octet-stream"
    category: FileFormatCategory = FileFormatCategory.UNKNOWN
    declared_extension: str = ""
    canonical_extensions: List[str] = Field(default_factory=list)

    # Deception & Anomaly Indicators
    is_extension_mismatch: bool = False
    is_double_extension: bool = False
    detected_inner_extension: Optional[str] = None
    has_null_byte_injection: bool = False
    has_right_to_left_override: bool = False
    rlo_clean_name: Optional[str] = None

    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    forensic_alerts: List[str] = Field(default_factory=list)


class FileArtifactReport(BaseModel):
    """Master forensic inspection report for binary files and standalone artifacts."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    file_path: Optional[str] = None
    filename: str
    size_bytes: int
    hashes: Dict[str, str] = Field(default_factory=dict)  # md5, sha1, sha256, sha512

    identification: FileTypeIdentification

    # Threat Scoring & Attribution
    is_suspicious: bool = False
    threat_severity: RiskSeverity = RiskSeverity.CLEAN
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    summary: str = ""
    remediation_advice: List[str] = Field(default_factory=list)

    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to a JSON-compatible Python dictionary."""
        return self.model_dump(mode="json")
