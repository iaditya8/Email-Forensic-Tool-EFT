"""Forensic data models for DNS Exfiltration, Tunneling, Fast-Flux, and DGA analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class DNSTunnelingMethod(str, Enum):
    """Encoding or encapsulation mechanism used in DNS covert channels."""

    BASE32 = "BASE32"
    BASE64 = "BASE64"
    BASE64URL = "BASE64URL"
    HEXADECIMAL = "HEXADECIMAL"
    BINARY_RAW = "BINARY_RAW"
    UNKNOWN = "UNKNOWN"


class DNSAnomalyType(str, Enum):
    """Categorized DNS threat anomaly types."""

    HIGH_ENTROPY_SUBDOMAIN = "HIGH_ENTROPY_SUBDOMAIN"
    EXCESSIVE_QUERY_VOLUME = "EXCESSIVE_QUERY_VOLUME"
    LONG_QUERY_LENGTH = "LONG_QUERY_LENGTH"
    LARGE_TXT_PAYLOAD = "LARGE_TXT_PAYLOAD"
    FAST_FLUX_RESOLUTIONS = "FAST_FLUX_RESOLUTIONS"
    DOUBLE_FAST_FLUX = "DOUBLE_FAST_FLUX"
    LOW_TTL_ANOMALY = "LOW_TTL_ANOMALY"
    HIGH_NXDOMAIN_RATIO = "HIGH_NXDOMAIN_RATIO"
    DGA_DOMAIN = "DGA_DOMAIN"
    PERIODIC_BEACONING = "PERIODIC_BEACONING"


class FluxType(str, Enum):
    """Fast-Flux architecture classification."""

    NONE = "NONE"
    SINGLE_FLUX = "SINGLE_FLUX"  # Rapidly changing A/AAAA records
    DOUBLE_FLUX = "DOUBLE_FLUX"  # Rapidly changing both A/AAAA and NS records


class SubdomainEntropyAnalysis(BaseModel):
    """Shannon entropy and character distribution analysis for a domain label."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    fqdn: str
    apex_domain: str
    subdomain: str
    subdomain_length: int
    entropy: float  # Shannon entropy in bits/symbol
    detected_encoding: DNSTunnelingMethod = DNSTunnelingMethod.UNKNOWN
    is_suspicious: bool = False
    reasons: List[str] = Field(default_factory=list)


class DNSTunnelingAlert(BaseModel):
    """Alert raised when DNS covert channel or bulk data exfiltration is detected."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    apex_domain: str
    total_queries: int
    unique_subdomains_count: int
    high_entropy_queries_count: int
    max_query_length: int
    avg_query_length: float
    estimated_exfiltrated_bytes: int
    detected_encodings: List[DNSTunnelingMethod] = Field(default_factory=list)
    query_types_used: List[str] = Field(default_factory=list)  # TXT, NULL, CNAME, A
    threat_indicators: List[str] = Field(default_factory=list)
    severity: str = "HIGH"  # LOW, MEDIUM, HIGH, CRITICAL


class FastFluxAlert(BaseModel):
    """Alert raised when Fast-Flux or Double Fast-Flux botnet infrastructure is detected."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    domain: str
    flux_type: FluxType = FluxType.SINGLE_FLUX
    unique_a_ips_count: int
    unique_ns_count: int = 0
    unique_asns_count: int = 0
    unique_countries_count: int = 0
    avg_ttl: float
    min_ttl: int
    resolved_ips: List[str] = Field(default_factory=list)
    nameservers: List[str] = Field(default_factory=list)
    threat_indicators: List[str] = Field(default_factory=list)
    severity: str = "HIGH"


class DGADomainAlert(BaseModel):
    """Alert raised when an algorithmically generated domain (DGA) is detected."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    domain: str
    apex_domain: str
    entropy: float
    vowel_consonant_ratio: float
    length: int
    predicted_dga_family: str = "High-Entropy Random"
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)


class DNSBeaconingAnalysis(BaseModel):
    """Time-series periodicity and beaconing analysis for DNS C2 communication."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    apex_domain: str
    query_count: int
    mean_interval_seconds: float
    median_interval_seconds: float
    interval_std_dev: float  # Jitter measurement
    regularity_score: float = Field(default=0.0, ge=0.0, le=1.0)  # 1.0 = perfect clockwork beacon
    is_periodic_beacon: bool = False
    severity: str = "MEDIUM"


class LargeTXTPayloadRecord(BaseModel):
    """Record of an unusually large TXT, NULL, or CNAME DNS payload."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    domain: str
    record_type: str
    payload_length_bytes: int
    payload_snippet: str
    entropy: float
    detected_encoding: DNSTunnelingMethod = DNSTunnelingMethod.UNKNOWN
    is_suspicious: bool = False


class DNSThreatReport(BaseModel):
    """Master forensic report for DNS covert channel, exfiltration, and infrastructure analysis."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    file_path: Optional[str] = None
    filename: Optional[str] = None
    hashes: Dict[str, str] = Field(default_factory=dict)

    total_dns_packets: int = 0
    total_queries: int = 0
    total_responses: int = 0
    total_nxdomains: int = 0
    nxdomain_rate: float = 0.0

    unique_apex_domains_count: int = 0
    unique_fqdns_count: int = 0
    query_type_distribution: Dict[str, int] = Field(default_factory=dict)
    response_code_distribution: Dict[str, int] = Field(default_factory=dict)

    # Forensic Detections
    high_entropy_subdomains: List[SubdomainEntropyAnalysis] = Field(default_factory=list)
    tunneling_alerts: List[DNSTunnelingAlert] = Field(default_factory=list)
    fast_flux_alerts: List[FastFluxAlert] = Field(default_factory=list)
    dga_alerts: List[DGADomainAlert] = Field(default_factory=list)
    beaconing_analyses: List[DNSBeaconingAnalysis] = Field(default_factory=list)
    large_txt_payloads: List[LargeTXTPayloadRecord] = Field(default_factory=list)

    # Scoring & Attribution
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    verdict: str = "BENIGN"  # BENIGN, SUSPICIOUS, MALICIOUS
    extracted_iocs: List[str] = Field(default_factory=list)
    executive_summary: str = ""
    remediation_guidance: List[str] = Field(default_factory=list)

    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to a JSON-compatible Python dictionary."""
        return self.model_dump(mode="json")
