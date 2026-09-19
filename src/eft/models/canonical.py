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


class IPNetworkIntelligence(BaseModel):
    """Forensic network intelligence, ASN, GeoIP, and infrastructure classification for an IP."""

    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    as_org: Optional[str] = None
    isp: Optional[str] = None
    is_cloud_provider: bool = False
    cloud_provider_name: Optional[str] = None
    is_tor_exit_node: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_private: bool = False
    reverse_dns: Optional[str] = None
    threat_tags: List[str] = Field(
        default_factory=list,
        description="Forensic intelligence flags (e.g., 'TOR_EXIT_NODE', 'COMMERCIAL_VPN', 'HYPERSCALER_AWS')",
    )


class RelayHop(BaseModel):
    """Forensic representation of a single Mail Transfer Agent (MTA) transmission hop."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    hop_number: int = 1  # 1-indexed chronological hop number
    raw_header: str = ""
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    by_ip: Optional[str] = None
    protocol: Optional[str] = None
    auth_user: Optional[str] = None
    tls_cipher: Optional[str] = None
    message_id_stamp: Optional[str] = None
    timestamp_raw: Optional[str] = None
    timestamp_utc: Optional[datetime] = None
    delay_seconds: float = 0.0  # Transit time in seconds elapsed since previous hop
    is_private_ip: bool = False
    is_originating_hop: bool = False
    network_intelligence: Optional[IPNetworkIntelligence] = Field(
        default=None,
        description="GeoIP, ASN, ISP, and hosting/threat classification for the sending IP",
    )
    anomalies: List[str] = Field(
        default_factory=list,
        description="Forensic anomalies detected at this hop (negative delay, private IP in external hop, etc.)",
    )


class TransitRoute(BaseModel):
    """Reconstructed chronological transit route and delay timeline across all MTAs."""

    total_hops: int = 0
    total_transit_seconds: float = 0.0
    originating_ip: Optional[str] = None
    originating_host: Optional[str] = None
    originating_ip_intelligence: Optional[IPNetworkIntelligence] = Field(
        default=None,
        description="GeoIP, ASN, ISP, and hosting/threat classification for the originating IP",
    )
    hops: List[RelayHop] = Field(
        default_factory=list,
        description="Chronologically ordered list of hops (Hop 1 = sender/origin -> Hop N = recipient MTA)",
    )
    anomalies_detected: List[str] = Field(
        default_factory=list,
        description="Global transit anomalies (e.g. clock skew, impossible routing jumps)",
    )


class SPFResult(BaseModel):
    """Forensic evaluation of Sender Policy Framework (SPF) validation and envelope alignment."""

    status: str = "none"  # pass, fail, softfail, neutral, none, temperror, permerror
    sender_ip: Optional[str] = None
    mail_from_domain: Optional[str] = None
    helo_domain: Optional[str] = None
    is_aligned: bool = False
    alignment_mode: str = "relaxed"  # relaxed, strict
    details: Optional[str] = None


class DKIMSignatureArtifact(BaseModel):
    """Decomposed DKIM signature parameters, cryptographic header tags, and verification status."""

    domain: str = ""  # d= tag
    selector: str = ""  # s= tag
    algorithm: str = "rsa-sha256"  # a= tag
    canonicalization: Optional[str] = None  # c= tag (e.g. relaxed/relaxed)
    body_hash: Optional[str] = None  # bh= tag
    signature_data: Optional[str] = None  # b= tag
    signed_headers: List[str] = Field(default_factory=list)  # h= tag
    status: str = "none"  # pass, fail, none, neutral, temperror, permerror
    is_aligned: bool = False
    alignment_mode: str = "relaxed"  # relaxed, strict
    timestamp_signed: Optional[datetime] = None  # t= tag
    expiration: Optional[datetime] = None  # x= tag
    details: Optional[str] = None


class DMARCResult(BaseModel):
    """Forensic evaluation of DMARC policy, identifier alignment, and enforcement disposition."""

    status: str = "none"  # pass, fail, none, temperror, permerror
    policy: str = "none"  # none, quarantine, reject, none_found
    subdomain_policy: Optional[str] = None
    spf_alignment: bool = False
    dkim_alignment: bool = False
    header_from_domain: str = ""
    percentage: int = 100
    disposition: str = "none"  # none, quarantine, reject
    details: Optional[str] = None


class ARCChain(BaseModel):
    """Authenticated Received Chain (ARC) validation state across forwarders and intermediaries."""

    arc_seal_status: str = "none"  # pass, fail, none
    arc_message_signature_status: str = "none"  # pass, fail, none
    arc_auth_results_status: str = "none"  # pass, fail, none
    instance_count: int = 0
    is_valid: bool = False
    details: Optional[str] = None


class EmailAuthenticationReport(BaseModel):
    """Comprehensive multi-protocol email authentication analysis report."""

    overall_verdict: str = "INSUFFICIENT_DATA"  # PASS, FAIL, SUSPICIOUS, NEUTRAL, INSUFFICIENT_DATA
    verdict_summary: str = ""
    spf: Optional[SPFResult] = None
    dkim_signatures: List[DKIMSignatureArtifact] = Field(default_factory=list)
    dmarc: Optional[DMARCResult] = None
    arc: Optional[ARCChain] = None
    auth_results_raw: List[str] = Field(default_factory=list)
    authentication_flags: List[str] = Field(
        default_factory=list,
        description="Forensic authentication alert flags (e.g. 'SPOOFING_CRITICAL_DMARC_FAILED', 'SPF_ALIGNMENT_MISMATCH')",
    )


class ExtractedURL(BaseModel):
    """Forensic record of a URL extracted from email headers, HTML DOM, or body content."""

    url: str
    defanged_url: str
    anchor_text: Optional[str] = None
    source_location: str = (
        "body_text"  # html_href, html_src, html_action, html_body_text, plain_body_text, header
    )
    domain: str = ""
    scheme: str = "http"
    is_anchor_mismatch: bool = False
    anchor_domain: Optional[str] = None
    is_idn_homograph: bool = False
    punycode_domain: Optional[str] = None
    unicode_domain: Optional[str] = None
    homoglyph_details: List[str] = Field(default_factory=list)
    is_ip_host: bool = False
    is_shortener: bool = False
    is_suspicious_tld: bool = False
    risk_flags: List[str] = Field(
        default_factory=list,
        description="Triggered threat indicators (e.g. 'ANCHOR_URL_MISMATCH', 'IDN_HOMOGRAPH_ATTACK')",
    )
    risk_score: float = 0.0  # 0.0 to 100.0


class URLExtractionReport(BaseModel):
    """Comprehensive URL and hyperlink forensic threat report."""

    total_urls_found: int = 0
    unique_domains: List[str] = Field(default_factory=list)
    urls: List[ExtractedURL] = Field(default_factory=list)
    anchor_mismatches_count: int = 0
    homographs_count: int = 0
    ip_urls_count: int = 0
    shorteners_count: int = 0
    overall_url_risk: str = "CLEAN"  # CLEAN, SUSPICIOUS, MALICIOUS
    risk_flags: List[str] = Field(default_factory=list)


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
    transit_route: Optional[TransitRoute] = Field(
        default=None,
        description="Reconstructed chronological MTA transit hops, delays, and originating IP",
    )
    authentication_report: Optional[EmailAuthenticationReport] = Field(
        default=None,
        description="Comprehensive forensic evaluation of SPF, DKIM, DMARC, and ARC authentication",
    )
    url_report: Optional[URLExtractionReport] = Field(
        default=None,
        description="Forensic URL extraction, defanging, anchor mismatch, and homograph detection report",
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
