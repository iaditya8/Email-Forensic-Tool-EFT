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


class FileTypeInspection(BaseModel):
    """Deep file type inspection comparing declared file metadata against true magic bytes."""

    declared_extension: str = ""
    detected_extension: Optional[str] = None
    declared_mime_type: str = "application/octet-stream"
    detected_mime_type: Optional[str] = None
    is_extension_mismatch: bool = False
    is_mime_mismatch: bool = False
    match_description: Optional[str] = None
    risk_level: str = "BENIGN"  # BENIGN, LOW, MEDIUM, HIGH, CRITICAL
    risk_reasons: List[str] = Field(default_factory=list)


class ExtractedAttachment(BaseModel):
    """Fully extracted, isolated, and cryptographically fingerprinted forensic attachment artifact."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    attachment_index: int = 0
    filename: str
    safe_filename: str
    saved_path: Optional[str] = None
    size_bytes: int = 0
    content_type: str = "application/octet-stream"
    content_id: Optional[str] = None
    content_disposition: Optional[str] = None
    is_inline: bool = False
    hashes: Dict[str, str] = Field(
        default_factory=dict,
        description="Cryptographic multi-hashes (md5, sha1, sha256) of extracted payload",
    )
    file_type_inspection: FileTypeInspection = Field(
        default_factory=FileTypeInspection,
        description="Magic byte inspection and spoofing risk analysis",
    )
    extracted_timestamp_utc: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when forensic extraction occurred",
    )


class MIMEPartNode(BaseModel):
    """Represents a structural node in the MIME hierarchy tree."""

    part_index: int
    part_path: str = "1"  # e.g., "1", "1.1", "1.2.1"
    depth: int = 0
    parent_path: Optional[str] = None
    content_type: str
    charset: Optional[str] = None
    content_transfer_encoding: Optional[str] = None
    content_disposition: Optional[str] = None
    content_id: Optional[str] = None
    boundary: Optional[str] = None
    is_multipart: bool = False
    is_attachment: bool = False
    filename: Optional[str] = None
    size_bytes: int = 0
    raw_headers: List[Tuple[str, str]] = Field(default_factory=list)
    children: List[MIMEPartNode] = Field(default_factory=list)


class HeaderDecomposition(BaseModel):
    """Decomposed, categorized view of all standard, routing, authentication, and custom headers."""

    received_headers: List[str] = Field(
        default_factory=list,
        description="Ordered list of 'Received' transit headers in top-down appearance order",
    )
    auth_results_headers: List[str] = Field(
        default_factory=list,
        description="List of Authentication-Results and Received-SPF header values",
    )
    dkim_signatures: List[str] = Field(
        default_factory=list,
        description="List of DKIM-Signature header values",
    )
    arc_headers: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Dictionary of ARC-* headers (ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results)",
    )
    custom_x_headers: Dict[str, Union[str, List[str]]] = Field(
        default_factory=dict,
        description="Dictionary of all custom non-standard X-* vendor and security headers",
    )
    standard_headers: Dict[str, Union[str, List[str]]] = Field(
        default_factory=dict,
        description="Dictionary of standard RFC 5322 core envelope headers",
    )


class IsolatedBody(BaseModel):
    """Isolated and cryptographically fingerprinted body representation."""

    content: str
    content_type: str  # 'text/plain', 'text/html', 'text/rtf'
    charset: Optional[str] = None
    size_bytes: int = 0
    sha256: str = ""


class IsolatedBodyArtifacts(BaseModel):
    """Container for isolated body artifacts partitioned by MIME type."""

    plain_bodies: List[IsolatedBody] = Field(default_factory=list)
    html_bodies: List[IsolatedBody] = Field(default_factory=list)
    rtf_bodies: List[IsolatedBody] = Field(default_factory=list)


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
    header_decomposition: Optional[HeaderDecomposition] = Field(
        default=None,
        description="Categorized header structures (Received, Auth, DKIM, ARC, X-*)",
    )

    # Message bodies
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    body_rtf: Optional[str] = None
    body_artifacts: Optional[IsolatedBodyArtifacts] = Field(
        default=None,
        description="Isolated body artifacts partitioned into structured streams with hashes",
    )

    # Extracted structures
    attachments: List[AttachmentMetadata] = Field(default_factory=list)
    extracted_attachments: List[ExtractedAttachment] = Field(
        default_factory=list,
        description="Forensically extracted, sanitized, and fingerprinted attachments",
    )
    mime_parts: List[MIMEPartNode] = Field(default_factory=list)

    # Forensic lineage & provenance
    source_file: Optional[SourceFileInfo] = None
    ingestion_timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
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
