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

__all__ = [
    "SourceFileInfo",
    "AttachmentMetadata",
    "MIMEPartNode",
    "HeaderDecomposition",
    "IsolatedBody",
    "IsolatedBodyArtifacts",
    "CanonicalEmail",
    "IngestionResult",
]
