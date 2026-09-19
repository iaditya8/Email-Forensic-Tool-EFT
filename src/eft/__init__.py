"""Email Forensic Tool (EFT) - Enterprise DFIR & Authentication Analysis Suite."""

from eft.core.exceptions import (
    CorruptFileError,
    EFTException,
    EvidenceTamperedException,
    ForensicIngestionError,
    UnsupportedFormatError,
)
from eft.core.integrity import compute_bytes_hashes, compute_file_hashes
from eft.ingestion.base import BaseEmailParser
from eft.ingestion.eml_parser import EMLParser
from eft.ingestion.engine import EmailIngester
from eft.ingestion.mbox_parser import MBOXParser
from eft.ingestion.msg_parser import MSGParser
from eft.models.canonical import (
    AttachmentMetadata,
    CanonicalEmail,
    IngestionResult,
    MIMEPartNode,
    SourceFileInfo,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "EmailIngester",
    "BaseEmailParser",
    "EMLParser",
    "MSGParser",
    "MBOXParser",
    "CanonicalEmail",
    "SourceFileInfo",
    "AttachmentMetadata",
    "MIMEPartNode",
    "IngestionResult",
    "EFTException",
    "EvidenceTamperedException",
    "CorruptFileError",
    "UnsupportedFormatError",
    "ForensicIngestionError",
    "compute_file_hashes",
    "compute_bytes_hashes",
]
