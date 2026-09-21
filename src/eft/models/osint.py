"""Forensic data models for Domain and Email Address OSINT Intelligence."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from eft.models.threat import RiskFactor, RiskSeverity


class DomainCategory(str, Enum):
    """Categorization of domain ownership and security profile."""

    CORPORATE = "Corporate / Enterprise Domain"
    FREEMAIL = "Public Webmail (Freemail)"
    DISPOSABLE = "Disposable / Temporary Email Service"
    LOOKALIKE = "High-Risk Lookalike / Typosquat"
    GOVERNMENT_EDU = "Government / Educational Domain"
    UNRESOLVED = "Unresolved / Parked / Inactive Domain"


class SPFStrictness(str, Enum):
    """SPF policy enforcement strictness rating."""

    STRICT = "STRICT"  # -all (Hardfail)
    SOFTFAIL = "SOFTFAIL"  # ~all (Softfail)
    NEUTRAL = "NEUTRAL"  # ?all
    PERMISSIVE = "PERMISSIVE"  # +all (Dangerous)
    MISSING = "MISSING"  # No SPF record found
    INVALID = "INVALID"  # Multiple or malformed SPF records


class DMARCEnforcement(str, Enum):
    """DMARC policy enforcement level."""

    REJECT = "REJECT"  # p=reject (Maximum enforcement)
    QUARANTINE = "QUARANTINE"  # p=quarantine
    NONE = "NONE"  # p=none (Monitoring only)
    MISSING = "MISSING"  # No DMARC record found
    INVALID = "INVALID"  # Malformed DMARC record


class MXRecordInfo(BaseModel):
    """MX server routing record metadata."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    host: str
    preference: int = 10
    ip_addresses: List[str] = Field(default_factory=list)
    matches_trusted_vendor: bool = False
    trusted_vendor_name: Optional[str] = None


class SPFPosture(BaseModel):
    """SPF record posture and security parameters."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    raw_record: Optional[str] = None
    qualifier: str = "missing"  # -all, ~all, ?all, +all, missing
    strictness: SPFStrictness = SPFStrictness.MISSING
    mechanisms: List[str] = Field(default_factory=list)
    lookup_count: int = 0
    warnings: List[str] = Field(default_factory=list)
    is_valid: bool = False


class DMARCPosture(BaseModel):
    """DMARC policy posture and reporting configuration."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    raw_record: Optional[str] = None
    policy: str = "missing"  # reject, quarantine, none, missing
    subdomain_policy: Optional[str] = None
    percentage: int = 100
    rua_uris: List[str] = Field(default_factory=list)
    ruf_uris: List[str] = Field(default_factory=list)
    adkim: str = "r"  # r (relaxed), s (strict)
    aspf: str = "r"  # r (relaxed), s (strict)
    enforcement: DMARCEnforcement = DMARCEnforcement.MISSING
    warnings: List[str] = Field(default_factory=list)
    is_valid: bool = False


class DKIMDiscovery(BaseModel):
    """Discovered DKIM selector and public key information."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    selector: str
    record_name: str
    raw_record: str
    key_type: str = "rsa"
    public_key_preview: str = ""
    is_valid: bool = True


class BIMIPosture(BaseModel):
    """Brand Indicators for Message Identification (BIMI) evaluation."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    raw_record: Optional[str] = None
    logo_url: Optional[str] = None
    authority_url: Optional[str] = None
    has_vmc: bool = False
    is_valid: bool = False


class DNSAuthPosture(BaseModel):
    """Aggregated DNS authentication and routing profile."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    domain: str
    has_mx: bool = False
    mx_records: List[MXRecordInfo] = Field(default_factory=list)
    a_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    spf: SPFPosture = Field(default_factory=SPFPosture)
    dmarc: DMARCPosture = Field(default_factory=DMARCPosture)
    discovered_dkim: List[DKIMDiscovery] = Field(default_factory=list)
    bimi: BIMIPosture = Field(default_factory=BIMIPosture)
    dns_query_time_ms: float = 0.0
    dns_error: Optional[str] = None


class BrandMatchResult(BaseModel):
    """Homoglyph, typosquat, and VIP lookalike brand matching evaluation."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    matched_brand_domain: str
    levenshtein_distance: int
    similarity_score: float = Field(ge=0.0, le=1.0)
    homoglyphs_detected: List[str] = Field(default_factory=list)
    has_homoglyphs: bool = False
    is_cousin_domain: bool = False
    risk_indicator: str = "CLEAN"  # CLEAN, SUSPICIOUS, HIGH_RISK, CRITICAL


class DomainOSINTReport(BaseModel):
    """Master OSINT reconnaissance and threat report for domain or email address."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    input_target: str
    analyzed_domain: str
    registered_domain: str
    tld: str
    username: Optional[str] = None
    is_email_address: bool = False
    is_punycode: bool = False
    unicode_domain: str
    category: DomainCategory = DomainCategory.CORPORATE

    # Detailed Subsystems
    dns_posture: DNSAuthPosture
    brand_risk: Optional[BrandMatchResult] = None
    disposable_service: Optional[str] = None
    freemail_provider: Optional[str] = None

    # Composite Threat Scoring
    reputation_score: float = Field(ge=0.0, le=100.0)  # 0 (Safe) to 100 (Critical)
    risk_level: RiskSeverity = RiskSeverity.CLEAN
    risk_factors: List[RiskFactor] = Field(default_factory=list)
    summary: str = ""
    remediation_advice: List[str] = Field(default_factory=list)

    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to a Python dictionary."""
        return self.model_dump(mode="json")
