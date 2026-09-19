"""Canonical data models for evidence chain of custody and cryptographic ledger."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class CustodyAction(str, Enum):
    """Standardized action types for forensic evidence lifecycle events."""

    ACQUISITION = "ACQUISITION"
    INGESTION = "INGESTION"
    INTEGRITY_CHECK = "INTEGRITY_CHECK"
    PARSING = "PARSING"
    ATTACHMENT_EXTRACTION = "ATTACHMENT_EXTRACTION"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    EVIDENCE_TRANSFER = "EVIDENCE_TRANSFER"
    REPORT_GENERATION = "REPORT_GENERATION"
    ARCHIVAL = "ARCHIVAL"
    TAMPER_DETECTED = "TAMPER_DETECTED"
    NOTE_ADDED = "NOTE_ADDED"


class EvidenceManifest(BaseModel):
    """Cryptographic evidence manifest establishing original state and immutable hashes."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    manifest_id: str = Field(
        default_factory=lambda: f"MAN-{uuid.uuid4().hex[:12].upper()}",
        description="Unique identifier for the evidence manifest",
    )
    case_id: str = Field(
        ..., description="DFIR Case or Incident identifier (e.g., 'CASE-2026-0042')"
    )
    evidence_id: str = Field(..., description="Unique Evidence Item ID (e.g., 'EVID-001')")
    examiner_name: str = Field(..., description="Full name or badge ID of the forensic examiner")
    examiner_agency: Optional[str] = Field(
        default=None,
        description="Law enforcement agency, DFIR firm, or organization conducting investigation",
    )
    source_file_path: str = Field(
        ..., description="Absolute or relative path to the acquired evidence file"
    )
    source_file_name: str = Field(..., description="Original filename of the evidence")
    source_file_size_bytes: int = Field(
        ..., ge=0, description="Exact byte size of the evidence file"
    )
    file_format: str = Field(
        default="eml", description="Detected or declared evidence format (eml, msg, mbox)"
    )
    acquisition_timestamp_utc: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when evidence was acquired/registered into custody",
    )
    pre_analysis_hashes: Dict[str, str] = Field(
        default_factory=dict,
        description="Multi-algorithm cryptographic hashes (md5, sha1, sha256, sha512) computed upon acquisition",
    )
    post_analysis_hashes: Optional[Dict[str, str]] = Field(
        default=None,
        description="Multi-algorithm cryptographic hashes re-computed post-examination",
    )
    integrity_verified: bool = Field(
        default=True,
        description="Indicates whether post-analysis hashes perfectly match acquisition pre-analysis hashes",
    )
    verification_timestamp_utc: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp of the most recent integrity verification",
    )
    notes: Optional[str] = Field(
        default=None,
        description="Examiner investigative notes or acquisition context",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary supplementary forensic metadata (e.g. host info, tool version)",
    )
    manifest_version: str = Field(
        default="1.0.0",
        description="Schema specification version of the manifest",
    )


class CustodyEvent(BaseModel):
    """Immutable entry in the chain of custody recording an action performed on evidence."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: str = Field(
        default_factory=lambda: f"EVT-{uuid.uuid4().hex[:10].upper()}",
        description="Unique identifier for this custody event",
    )
    timestamp_utc: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Exact UTC timestamp when the action occurred",
    )
    action: str = Field(
        ...,
        description="Type of action performed (e.g., ACQUISITION, INGESTION, INTEGRITY_CHECK)",
    )
    performed_by: str = Field(
        ..., description="Name, badge number, or system identity performing the action"
    )
    agency: Optional[str] = Field(
        default=None,
        description="Agency or organization of the actor",
    )
    description: str = Field(
        ..., description="Detailed description of the forensic operation or finding"
    )
    evidence_hash: Optional[str] = Field(
        default=None,
        description="Cryptographic SHA-256 hash of the evidence at the time of the event",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured key-value context regarding the event (e.g., tool params, counts)",
    )


class EvidenceLedger(BaseModel):
    """Complete, defensible Chain of Custody ledger linking an evidence manifest with all lifecycle events."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    ledger_id: str = Field(
        default_factory=lambda: f"LEDGER-{uuid.uuid4().hex[:12].upper()}",
        description="Unique identifier for this chain of custody ledger",
    )
    case_id: str = Field(..., description="DFIR Case identifier")
    evidence_id: str = Field(..., description="Evidence item identifier")
    manifest: EvidenceManifest = Field(..., description="Original evidence acquisition manifest")
    events: List[CustodyEvent] = Field(
        default_factory=list,
        description="Chronologically ordered sequence of custody events",
    )
    created_at_utc: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC creation timestamp of the ledger",
    )
    updated_at_utc: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the last recorded custody event",
    )
    is_tampered: bool = Field(
        default=False,
        description="Flag indicating if any integrity verification check has failed",
    )
    tamper_details: Optional[str] = Field(
        default=None,
        description="Description of detected tamper or hash mismatch if any",
    )
