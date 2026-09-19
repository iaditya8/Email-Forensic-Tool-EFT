"""Data models for Email Forensic Tool (EFT)."""

from eft.models.canonical import (
    AttachmentMetadata,
    CanonicalEmail,
    HeaderDecomposition,
    IngestionResult,
    IsolatedBody,
    IsolatedBodyArtifacts,
    MIMEPartNode,
    SourceFileInfo,
)
from eft.models.custody import (
    CustodyAction,
    CustodyEvent,
    EvidenceLedger,
    EvidenceManifest,
)
from eft.models.threat import (
    CompositeRiskReport,
    RiskFactor,
    RiskSeverity,
    RiskVectorType,
    VectorRiskScore,
)
from eft.models.timeline import (
    ForensicTimelineReport,
    TimelineAnomalyType,
    TimelineEvent,
    TimelineEventType,
)

__all__ = [
    "SourceFileInfo",
    "AttachmentMetadata",
    "MIMEPartNode",
    "HeaderDecomposition",
    "IsolatedBody",
    "IsolatedBodyArtifacts",
    "CanonicalEmail",
    "IngestionResult",
    "CustodyAction",
    "EvidenceManifest",
    "CustodyEvent",
    "EvidenceLedger",
    "TimelineEventType",
    "TimelineAnomalyType",
    "TimelineEvent",
    "ForensicTimelineReport",
    "RiskSeverity",
    "RiskVectorType",
    "RiskFactor",
    "VectorRiskScore",
    "CompositeRiskReport",
]
