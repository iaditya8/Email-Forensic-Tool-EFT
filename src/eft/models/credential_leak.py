"""Forensic data models for Cleartext Credential & High-Risk Protocol Extraction."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class CleartextProtocol(str, Enum):
    """Protocol over which unencrypted authentication or sensitive data was transmitted."""

    HTTP_BASIC_AUTH = "HTTP_BASIC_AUTH"
    HTTP_BEARER_AUTH = "HTTP_BEARER_AUTH"
    HTTP_POST_BODY = "HTTP_POST_BODY"
    HTTP_COOKIE_SESSION = "HTTP_COOKIE_SESSION"
    FTP = "FTP"
    TELNET = "TELNET"
    SMTP = "SMTP"
    POP3 = "POP3"
    IMAP = "IMAP"
    SNMP = "SNMP"
    LDAP = "LDAP"
    OTHER = "OTHER"


class SecretType(str, Enum):
    """Classification of leaked sensitive credential or secret."""

    PASSWORD = "PASSWORD"
    API_KEY = "API_KEY"
    BEARER_TOKEN = "BEARER_TOKEN"
    BASIC_AUTH = "BASIC_AUTH"
    SESSION_COOKIE = "SESSION_COOKIE"
    PRIVATE_KEY = "PRIVATE_KEY"
    SNMP_COMMUNITY_STRING = "SNMP_COMMUNITY_STRING"
    GENERIC_TOKEN = "GENERIC_TOKEN"


class DefangedSecret(BaseModel):
    """Masked secret presentation model with ISO/IEC 27037 evidence hash."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    secret_type: SecretType
    masked_value: str  # e.g., "sk-proj-****9a2f", "pa****123"
    length: int
    entropy: float = 0.0
    sha256_hash: str  # Cryptographic fingerprint for legal verification


class ExtractedCredentialRecord(BaseModel):
    """Forensic record of a cleartext credential or authentication token discovered on wire."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime
    protocol: CleartextProtocol
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    username: Optional[str] = None
    secret: DefangedSecret
    endpoint_url: Optional[str] = None
    context_snippet: Optional[str] = None
    severity: str = "HIGH"  # HIGH or CRITICAL


class UnencryptedFileTransferRecord(BaseModel):
    """Record of an unencrypted file upload or download captured over cleartext network."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime
    protocol: str  # HTTP, FTP
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    filename: str
    size_bytes: int = 0
    content_type: Optional[str] = None
    sha256_hash: Optional[str] = None
    is_sensitive_file: bool = False
    warning_reason: Optional[str] = None


class HighRiskProtocolExposure(BaseModel):
    """Detection of unencrypted, legacy, or high-risk protocols exposed on the network."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    protocol_name: str
    port: int
    server_ip: str
    client_ips: List[str] = Field(default_factory=list)
    packet_count: int = 0
    risk_description: str
    recommended_replacement: str


class CredentialLeakageReport(BaseModel):
    """Master forensic report for cleartext credentials and high-risk protocol inspection."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    file_path: Optional[str] = None
    filename: Optional[str] = None
    hashes: Dict[str, str] = Field(default_factory=dict)

    total_packets_scanned: int = 0
    total_credentials_leaked: int = 0
    total_unencrypted_files: int = 0
    total_protocol_exposures: int = 0

    # Categorized Detections
    credentials: List[ExtractedCredentialRecord] = Field(default_factory=list)
    unencrypted_files: List[UnencryptedFileTransferRecord] = Field(default_factory=list)
    protocol_exposures: List[HighRiskProtocolExposure] = Field(default_factory=list)

    # Forensic Assessment
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    verdict: str = "BENIGN"  # BENIGN, SUSPICIOUS, MALICIOUS
    extracted_iocs: List[str] = Field(default_factory=list)
    executive_summary: str = ""
    remediation_guidance: List[str] = Field(default_factory=list)

    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to a JSON-compatible Python dictionary."""
        return self.model_dump(mode="json")
