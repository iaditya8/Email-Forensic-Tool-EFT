"""Canonical data models for normalized forensic email representations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field


class SourceFileInfo(BaseModel):
    """Cryptographic and filesystem metadata for the source evidence file."""

    model_config = ConfigDict(frozen=True)

    file_path: str
    file_name: str
    file_format: str  # 'eml', 'msg', 'mbox'
    file_size_bytes: int
    hashes: Dict[str, str] = Field(
        default_factory=dict,
        description="Pre-analysis cryptographic hashes (md5, sha1, sha256)",
    )


class AttachmentMetadata(BaseModel):
    """Metadata and cryptographic fingerprints for an extracted attachment or inline asset."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    filename: str
    content_type: str = "application/octet-stream"
    size_bytes: int = 0
    content_id: Optional[str] = None
    content_disposition: Optional[str] = None
    is_inline: bool = False
    hashes: Dict[str, str] = Field(
        default_factory=dict,
        description="Cryptographic digests (md5, sha1, sha256) of attachment binary stream",
    )
    raw_data: Optional[bytes] = Field(
        default=None,
        repr=False,
        description="Raw byte stream of the attachment payload",
    )


class MIMEPartNode(BaseModel):
    """Represents a structural node in the MIME hierarchy tree."""

    part_index: int
    content_type: str
    charset: Optional[str] = None
    content_transfer_encoding: Optional[str] = None
    content_disposition: Optional[str] = None
    content_id: Optional[str] = None
    is_multipart: bool = False
    size_bytes: int = 0
    children: List[MIMEPartNode] = Field(default_factory=list)


class CanonicalEmail(BaseModel):
    """Normalized, court-defensible representation of an ingested email."""

    message_id: Optional[str] = None
    date: Optional[str] = None
    subject: Optional[str] = None
    from_address: Optional[str] = None
    to_addresses: List[str] = Field(default_factory=list)
    cc_addresses: List[str] = Field(default_factory=list)
    bcc_addresses: List[str] = Field(default_factory=list)
    reply_to: Optional[str] = None
    return_path: Optional[str] = None

    # Preserved raw & structured headers
    headers: Dict[str, Union[str, List[str]]] = Field(
        default_factory=dict,
        description="Normalized header map (lowercase keys, multi-headers grouped as lists)",
    )
    ordered_headers: List[Tuple[str, str]] = Field(
        default_factory=list,
        description="Strictly ordered list of (header_name, header_value) preserving physical transit order",
    )

    # Message bodies
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    body_rtf: Optional[str] = None

    # Extracted structures
    attachments: List[AttachmentMetadata] = Field(default_factory=list)
    mime_parts: List[MIMEPartNode] = Field(default_factory=list)

    # Forensic lineage & provenance
    source_file: Optional[SourceFileInfo] = None
    ingestion_timestamp_utc: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    parsing_diagnostics: List[str] = Field(
        default_factory=list,
        description="Diagnostic logs, non-fatal anomalies, and warnings recorded during ingestion",
    )


class IngestionResult(BaseModel):
    """Result envelope for an email evidence ingestion operation."""

    source_file: SourceFileInfo
    messages: List[CanonicalEmail] = Field(default_factory=list)
    total_messages: int = 0
    success: bool = True
    errors: List[str] = Field(default_factory=list)
    post_analysis_hash: str
    tamper_verified: bool = True
