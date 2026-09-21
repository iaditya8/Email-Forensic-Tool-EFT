"""Canonical data models for cross-module Master Case forensic investigation reports."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from eft.models.custody import EvidenceManifest


class EvidenceItemType(str, Enum):
    """Supported forensic domain evidence classifications."""

    EMAIL = "EMAIL"
    FILE_BINARY = "FILE_BINARY"
    NETWORK_PCAP = "NETWORK_PCAP"
    WINDOWS_EVTX = "WINDOWS_EVTX"
    CLOUD_AUDIT = "CLOUD_AUDIT"
    VOLATILE_MEMORY = "VOLATILE_MEMORY"
    OSINT_DOMAIN = "OSINT_DOMAIN"
    OSINT_IP = "OSINT_IP"


class MasterCaseIoC(BaseModel):
    """Unified Indicator of Compromise (IoC) extracted from any forensic evidence item."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    ioc_id: str = Field(
        default_factory=lambda: f"IOC-{uuid.uuid4().hex[:10].upper()}",
        description="Unique identifier for the extracted IoC",
    )
    ioc_type: str = Field(
        ...,
        description="Type of IoC (e.g., 'ip-address', 'domain', 'url', 'file-hash-sha256', 'email-address', 'crypto-wallet', 'mitre-technique')",
    )
    ioc_value: str = Field(..., description="Raw or normalized value of the IoC")
    source_item_id: str = Field(
        ..., description="Identifier of the evidence item from which this IoC was extracted"
    )
    source_item_type: EvidenceItemType = Field(
        ..., description="Domain type of the originating evidence item"
    )
    severity: str = Field(
        default="INFO",
        description="Severity level ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
    )
    threat_category: str = Field(
        default="ARTIFACT",
        description="Threat taxonomy category ('C2_INFRASTRUCTURE', 'MALICIOUS_PAYLOAD', 'PHISHING', 'CREDENTIAL_THEFT', 'IDENTITY', 'EVASION')",
    )
    description: str = Field(
        default="",
        description="Contextual description explaining why this IoC is significant",
    )


class MasterTimelineEvent(BaseModel):
    """Unified chronological timeline event across all forensic evidence sources."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: str = Field(
        default_factory=lambda: f"EVT-{uuid.uuid4().hex[:10].upper()}",
        description="Unique identifier for the timeline event",
    )
    timestamp_utc: datetime = Field(
        ...,
        description="Exact UTC timestamp of the observed forensic event",
    )
    source_item_id: str = Field(..., description="Identifier of the originating evidence item")
    source_type: EvidenceItemType = Field(..., description="Domain type of the evidence item")
    event_category: str = Field(
        default="ACTIVITY",
        description="Event classification category ('EMAIL_DELIVERY', 'FILE_CREATION', 'PROCESS_SPAWN', 'NETWORK_FLOW', 'DNS_QUERY', 'FAILED_LOGON', 'MEMORY_INJECTION', 'PRIVILEGE_ESCALATION')",
    )
    title: str = Field(..., description="Short concise title of the timeline event")
    description: str = Field(default="", description="Detailed narrative of the event")
    actor_or_source: str = Field(
        default="-",
        description="Originating actor, source IP, process name, or sender",
    )
    target_or_dest: str = Field(
        default="-",
        description="Target entity, recipient, destination IP, or impacted resource",
    )
    severity: str = Field(
        default="INFO",
        description="Forensic severity ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
    )


class CaseEvidenceItem(BaseModel):
    """Detailed metadata and analysis results for a single forensic evidence item within a case."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    item_id: str = Field(
        default_factory=lambda: f"EVID-{uuid.uuid4().hex[:8].upper()}",
        description="Unique evidence item identifier within the case",
    )
    item_type: EvidenceItemType = Field(..., description="Classified forensic domain type")
    source_path: str = Field(..., description="Path or location of the evidence file")
    source_name: str = Field(..., description="Filename or label of the evidence item")
    size_bytes: int = Field(default=0, ge=0, description="Size in bytes of the evidence file")
    manifest: EvidenceManifest = Field(
        ..., description="Cryptographic acquisition and custody manifest"
    )
    risk_score: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Domain-specific risk score (0-100)"
    )
    risk_level: str = Field(
        default="BENIGN",
        description="Risk level ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BENIGN')",
    )
    summary: str = Field(
        default="", description="High-level narrative summary of findings for this item"
    )
    extracted_iocs: List[MasterCaseIoC] = Field(
        default_factory=list,
        description="List of extracted IoCs from this evidence item",
    )
    timeline_events: List[MasterTimelineEvent] = Field(
        default_factory=list,
        description="Chronological events sourced from this item",
    )
    mitre_techniques: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs identified in this item (e.g. 'T1566.001')",
    )
    raw_analysis_report: Dict[str, Any] = Field(
        default_factory=dict,
        description="Domain-specific structured analysis report dictionary",
    )


class CrossEvidenceCorrelation(BaseModel):
    """Correlation link between two or more evidence items sharing IoCs, timestamps, or attack chains."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    correlation_id: str = Field(
        default_factory=lambda: f"CORR-{uuid.uuid4().hex[:8].upper()}",
        description="Unique correlation identifier",
    )
    correlation_type: str = Field(
        ...,
        description="Type of correlation ('SHARED_IOC', 'ATTACK_CHAIN_SEQUENCE', 'IDENTITY_LINK', 'C2_EGRESS', 'CREDENTIAL_REUSE')",
    )
    title: str = Field(..., description="Title of the cross-evidence finding")
    description: str = Field(..., description="Narrative explaining the cross-evidence link")
    matched_ioc_type: Optional[str] = Field(default=None, description="Type of shared IoC if any")
    matched_ioc_value: Optional[str] = Field(default=None, description="Shared IoC value if any")
    involved_item_ids: List[str] = Field(
        default_factory=list,
        description="List of evidence item IDs linked by this correlation",
    )
    severity: str = Field(
        default="HIGH",
        description="Correlation threat severity ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
    )
    mitre_technique: Optional[str] = Field(
        default=None, description="Associated MITRE ATT&CK technique ID"
    )


class MasterCaseReport(BaseModel):
    """Comprehensive Master Case Investigation Report aggregating all evidence domains."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    case_id: str = Field(..., description="DFIR Case Identifier (e.g., 'CASE-2026-0042')")
    case_title: str = Field(
        default="Master Digital Forensics Investigation Report",
        description="Descriptive title of the case",
    )
    examiner_name: str = Field(..., description="Lead Forensic Examiner Name")
    examiner_agency: Optional[str] = Field(
        default=None, description="Investigating Agency or Organization"
    )
    created_at_utc: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC creation timestamp of the master case report",
    )
    evidence_items: List[CaseEvidenceItem] = Field(
        default_factory=list,
        description="Inventory of all analyzed evidence items",
    )
    overall_composite_risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Weighted composite risk score across all evidence items (0-100)",
    )
    overall_risk_level: str = Field(
        default="BENIGN",
        description="Overall case risk tier ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BENIGN')",
    )
    executive_summary: str = Field(
        default="",
        description="High-level executive summary summarizing the attack narrative and findings",
    )
    cross_module_correlations: List[CrossEvidenceCorrelation] = Field(
        default_factory=list,
        description="Cross-evidence correlations establishing the end-to-end attack chain",
    )
    master_timeline: List[MasterTimelineEvent] = Field(
        default_factory=list,
        description="Unified chronological timeline ordered from earliest to latest UTC event",
    )
    master_ioc_ledger: List[MasterCaseIoC] = Field(
        default_factory=list,
        description="Deduplicated master inventory of all Indicators of Compromise",
    )
    mitre_matrix: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Observed MITRE ATT&CK tactics mapped to lists of technique IDs",
    )
    immutability_audit: Dict[str, Any] = Field(
        default_factory=dict,
        description="Cryptographic integrity ledger proving 100% zero-byte mutation across all evidence files",
    )
