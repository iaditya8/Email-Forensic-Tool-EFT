from eft.analysis.auth_verifier import AuthenticationVerifier
from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.analysis.relay_analyzer import RelayAnalyzer
from eft.core.exceptions import (
    CorruptFileError,
    EFTException,
    EvidenceTamperedException,
    ForensicIngestionError,
    UnsupportedFormatError,
)
from eft.core.integrity import compute_bytes_hashes, compute_file_hashes
from eft.ingestion.attachment_extractor import AttachmentExtractor
from eft.ingestion.base import BaseEmailParser
from eft.ingestion.eml_parser import EMLParser
from eft.ingestion.engine import EmailIngester
from eft.ingestion.header_decomposer import HeaderDecomposer
from eft.ingestion.mbox_parser import MBOXParser
from eft.ingestion.mime_decomposer import MIMETreeDecomposer
from eft.ingestion.msg_parser import MSGParser
from eft.models.canonical import (
    ARCChain,
    AttachmentMetadata,
    CanonicalEmail,
    DKIMSignatureArtifact,
    DMARCResult,
    EmailAuthenticationReport,
    ExtractedAttachment,
    FileTypeInspection,
    HeaderDecomposition,
    IngestionResult,
    IPNetworkIntelligence,
    IsolatedBody,
    IsolatedBodyArtifacts,
    MIMEPartNode,
    RelayHop,
    SourceFileInfo,
    SPFResult,
    TransitRoute,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "EmailIngester",
    "BaseEmailParser",
    "EMLParser",
    "MSGParser",
    "MBOXParser",
    "HeaderDecomposer",
    "MIMETreeDecomposer",
    "AttachmentExtractor",
    "RelayAnalyzer",
    "NetworkIntelligenceService",
    "AuthenticationVerifier",
    "CanonicalEmail",
    "SourceFileInfo",
    "AttachmentMetadata",
    "ExtractedAttachment",
    "FileTypeInspection",
    "IPNetworkIntelligence",
    "SPFResult",
    "DKIMSignatureArtifact",
    "DMARCResult",
    "ARCChain",
    "EmailAuthenticationReport",
    "MIMEPartNode",
    "HeaderDecomposition",
    "RelayHop",
    "TransitRoute",
    "IsolatedBody",
    "IsolatedBodyArtifacts",
    "IngestionResult",
    "EFTException",
    "EvidenceTamperedException",
    "CorruptFileError",
    "UnsupportedFormatError",
    "ForensicIngestionError",
    "compute_file_hashes",
    "compute_bytes_hashes",
]
