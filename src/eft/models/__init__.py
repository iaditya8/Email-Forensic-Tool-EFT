"""Data models for Email Forensic Tool (EFT)."""

from eft.models.canonical import (
    AttachmentMetadata,
    CanonicalEmail,
    IngestionResult,
    MIMEPartNode,
    SourceFileInfo,
)

__all__ = [
    "SourceFileInfo",
    "AttachmentMetadata",
    "MIMEPartNode",
    "CanonicalEmail",
    "IngestionResult",
]
