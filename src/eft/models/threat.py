"""Forensic models for Composite Risk Scoring and Threat Attribution."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class RiskSeverity(str, Enum):
    """Forensic threat risk severity tiers."""

    CLEAN = "CLEAN"
    SUSPICIOUS_LOW = "SUSPICIOUS_LOW"
    SUSPICIOUS_MEDIUM = "SUSPICIOUS_MEDIUM"
    MALICIOUS_HIGH = "MALICIOUS_HIGH"
    CRITICAL = "CRITICAL"


class RiskVectorType(str, Enum):
    """Categorized forensic threat evaluation vectors."""

    AUTHENTICATION = "Authentication & Spoofing"
    PHISHING_URL = "Phishing & Malicious Links"
    BEC_SOCIAL_ENGINEERING = "BEC & Social Engineering"
    ATTACHMENT_MALWARE = "Attachments & Malware"
    OBFUSCATION_TRANSIT = "Content Obfuscation & Transit Anomalies"


class RiskFactor(BaseModel):
    """Individual forensic risk factor contributing to the composite threat score."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    vector: RiskVectorType
    name: str
    score_contribution: float = Field(ge=0.0, le=100.0)
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    evidence_reference: Optional[str] = None


class VectorRiskScore(BaseModel):
    """Risk score breakdown for a specific forensic threat vector."""

    vector: RiskVectorType
    score: float = Field(ge=0.0, le=100.0)
    max_score: float = Field(default=25.0)
    factors: List[RiskFactor] = Field(default_factory=list)


class CompositeRiskReport(BaseModel):
    """Comprehensive composite risk assessment aggregating all forensic threat signals."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    overall_score: float = Field(ge=0.0, le=100.0)
    risk_level: RiskSeverity = RiskSeverity.CLEAN
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)
    vector_breakdown: Dict[str, VectorRiskScore] = Field(default_factory=dict)
    all_factors: List[RiskFactor] = Field(default_factory=list)
    recommended_action: str = "Allow - No suspicious indicators detected."
    summary: str = "Email passed forensic security checks without notable threat signals."
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
