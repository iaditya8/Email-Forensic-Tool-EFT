"""Forensic data models for network packet capture (PCAP/PCAPNG) analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class TransportProtocol(str, Enum):
    """Transport and Network layer protocol classification."""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ICMPV6 = "ICMPv6"
    ARP = "ARP"
    IGMP = "IGMP"
    GRE = "GRE"
    ESP = "ESP"
    OTHER = "OTHER"


class AppProtocol(str, Enum):
    """Application layer protocol classification."""

    DNS = "DNS"
    HTTP = "HTTP"
    TLS = "TLS / HTTPS"
    DHCP = "DHCP"
    NTP = "NTP"
    SSH = "SSH"
    FTP = "FTP"
    SMTP = "SMTP"
    UNKNOWN = "UNKNOWN"


class DNSResourceRecord(BaseModel):
    """DNS Question, Answer, Authority, or Additional Resource Record."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    record_type: str  # A, AAAA, CNAME, MX, TXT, PTR, NS, SOA, SRV, ANY
    record_class: str = "IN"
    ttl: int = 0
    rdata: str = ""


class DNSPacketInfo(BaseModel):
    """Parsed DNS transaction packet metadata."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    transaction_id: int
    is_response: bool
    opcode: int = 0
    rcode: int = 0
    rcode_name: str = "NOERROR"
    questions: List[DNSResourceRecord] = Field(default_factory=list)
    answers: List[DNSResourceRecord] = Field(default_factory=list)
    authorities: List[DNSResourceRecord] = Field(default_factory=list)
    additionals: List[DNSResourceRecord] = Field(default_factory=list)


class HTTPRequestInfo(BaseModel):
    """Dissected HTTP request frame."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    method: str
    uri: str
    version: str = "HTTP/1.1"
    host: Optional[str] = None
    user_agent: Optional[str] = None
    referer: Optional[str] = None
    content_type: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    body_snippet: Optional[str] = None
    body_length: int = 0


class HTTPResponseInfo(BaseModel):
    """Dissected HTTP response frame."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    version: str = "HTTP/1.1"
    status_code: int = 200
    reason_phrase: str = "OK"
    server: Optional[str] = None
    content_type: Optional[str] = None
    location: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    body_snippet: Optional[str] = None
    body_length: int = 0


class TLSHandshakeInfo(BaseModel):
    """Dissected TLS Client Hello / Server Hello Handshake metadata."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    content_type: int = 22
    tls_version: str = "TLS 1.2"
    handshake_type: str = "Client Hello"
    server_name: Optional[str] = None  # Server Name Indication (SNI)
    cipher_suites: List[str] = Field(default_factory=list)
    selected_cipher: Optional[str] = None
    supported_versions: List[str] = Field(default_factory=list)
    ja3_string: Optional[str] = None
    ja3_hash: Optional[str] = None


class PacketRecord(BaseModel):
    """Detailed forensic record of an individual captured network packet."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    packet_num: int
    timestamp: datetime
    wire_len: int
    cap_len: int
    link_type: str = "Ethernet"

    # Layer 2 (Data Link)
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None

    # Layer 3 (Network)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_version: Optional[int] = None  # 4 or 6
    ttl: Optional[int] = None

    # Layer 4 (Transport)
    transport_protocol: TransportProtocol = TransportProtocol.OTHER
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: List[str] = Field(default_factory=list)
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    payload_len: int = 0

    # Layer 7 (Application)
    app_protocol: AppProtocol = AppProtocol.UNKNOWN
    dns_info: Optional[DNSPacketInfo] = None
    http_request: Optional[HTTPRequestInfo] = None
    http_response: Optional[HTTPResponseInfo] = None
    tls_info: Optional[TLSHandshakeInfo] = None


class NetworkFlow(BaseModel):
    """Aggregated bidirectional IP conversation flow."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    flow_id: str
    protocol: TransportProtocol = TransportProtocol.TCP
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int

    # Forensic Network Intelligence Enrichment
    client_geo: Optional[str] = None
    server_geo: Optional[str] = None
    client_asn: Optional[str] = None
    server_asn: Optional[str] = None
    client_cloud_tag: Optional[str] = None
    server_cloud_tag: Optional[str] = None
    is_vpn_tor: bool = False

    # Flow Metrics
    total_packets: int = 0
    forward_packets: int = 0
    reverse_packets: int = 0
    total_bytes: int = 0
    forward_bytes: int = 0
    reverse_bytes: int = 0

    start_time: datetime
    end_time: datetime
    duration_seconds: float = 0.0
    handshake_rtt_seconds: Optional[float] = None

    # Application Layer Attributes
    app_protocol: AppProtocol = AppProtocol.UNKNOWN
    sni: Optional[str] = None
    http_host: Optional[str] = None
    dns_domain: Optional[str] = None
    tcp_state: str = "UNKNOWN"


class PCAPAnalysisReport(BaseModel):
    """Master forensic report for an ingested PCAP or PCAPNG capture file."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    file_path: Optional[str] = None
    filename: str
    size_bytes: int
    hashes: Dict[str, str] = Field(default_factory=dict)  # md5, sha1, sha256, sha512
    file_format: str = "PCAP"  # PCAP or PCAPNG

    total_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    link_type: str = "Ethernet"

    packets_by_protocol: Dict[str, int] = Field(default_factory=dict)
    top_talkers_ips: List[Dict[str, Any]] = Field(default_factory=list)
    top_talkers_ports: List[Dict[str, Any]] = Field(default_factory=list)

    flows: List[NetworkFlow] = Field(default_factory=list)

    # L7 Summaries
    dns_queries_count: int = 0
    http_requests_count: int = 0
    tls_handshakes_count: int = 0
    unique_snis: List[str] = Field(default_factory=list)
    unique_dns_domains: List[str] = Field(default_factory=list)
    geoip_summary: Dict[str, int] = Field(default_factory=dict)

    # Forensic Threat Assessment
    forensic_alerts: List[str] = Field(default_factory=list)
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    verdict: str = "BENIGN"

    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to a JSON-compatible Python dictionary."""
        return self.model_dump(mode="json")
