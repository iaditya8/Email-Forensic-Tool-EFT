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
]
