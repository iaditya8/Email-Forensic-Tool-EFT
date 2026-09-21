"""Forensic data models for Cloud Audit Log Ingestion (M365 Unified Audit Logs & Google Workspace)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from eft.models.timeline import TimelineEvent


class CloudProvider(str, Enum):
    """Supported cloud productivity and identity providers."""

    M365 = "M365"
    GOOGLE_WORKSPACE = "GOOGLE_WORKSPACE"
    UNKNOWN = "UNKNOWN"


class CloudThreatClassification(str, Enum):
    """Behavioral threat classification for cloud identity and mailbox operations."""

    BENIGN = "BENIGN"
    MALICIOUS_INBOX_RULE = "MALICIOUS_INBOX_RULE"
    EMAIL_HIDING_RULE = "EMAIL_HIDING_RULE"
    EXTERNAL_FORWARDING = "EXTERNAL_FORWARDING"
    UNAUTHORIZED_MAILBOX_DELEGATION = "UNAUTHORIZED_MAILBOX_DELEGATION"
    ILLICIT_OAUTH_CONSENT = "ILLICIT_OAUTH_CONSENT"
    IMPOSSIBLE_TRAVEL_LOGIN = "IMPOSSIBLE_TRAVEL_LOGIN"
    ANOMALOUS_GEO_LOGIN = "ANOMALOUS_GEO_LOGIN"
    SUSPICIOUS_ADMIN_ACTIVITY = "SUSPICIOUS_ADMIN_ACTIVITY"
    MASS_DOWNLOAD_ACTIVITY = "MASS_DOWNLOAD_ACTIVITY"


class M365InboxRuleRecord(BaseModel):
    """Parsed M365 New-InboxRule, Set-InboxRule, or Enable-InboxRule record."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime
    record_id: Optional[str] = None
    user_id: str
    client_ip: Optional[str] = None
    operation: str  # New-InboxRule, Set-InboxRule
    rule_name: str
    mailbox_owner: Optional[str] = None
    forward_to: List[str] = Field(default_factory=list)
    redirect_to: List[str] = Field(default_factory=list)
    forward_as_attachment_to: List[str] = Field(default_factory=list)
    move_to_folder: Optional[str] = None
    delete_message: bool = False
    mark_as_read: bool = False
    subject_contains_words: List[str] = Field(default_factory=list)
    body_contains_words: List[str] = Field(default_factory=list)
    raw_parameters: Dict[str, Any] = Field(default_factory=dict)


class M365MailboxPermissionRecord(BaseModel):
    """Parsed M365 Add-MailboxPermission, Add-RecipientPermission record."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime
    record_id: Optional[str] = None
    user_id: str  # Operator who performed change
    client_ip: Optional[str] = None
    operation: str  # Add-MailboxPermission, Add-RecipientPermission
    mailbox_owner: str
    delegate_user: str
    access_rights: List[str] = Field(default_factory=list)  # FullAccess, SendAs, SendOnBehalf
    is_external_delegate: bool = False


class CloudOAuthConsentRecord(BaseModel):
    """Parsed OAuth application authorization and consent grant record."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime
    record_id: Optional[str] = None
    provider: CloudProvider = CloudProvider.M365
    user_id: str
    client_ip: Optional[str] = None
    app_name: str
    app_id: Optional[str] = None
    client_id: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)  # e.g. Mail.ReadWrite, Mail.Send
    is_admin_consent: bool = False


class CloudLoginRecord(BaseModel):
    """Parsed M365 UserLoggedIn or Google Workspace Login event."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime
    record_id: Optional[str] = None
    provider: CloudProvider
    user_id: str
    client_ip: str
    location_city: Optional[str] = None
    location_country: Optional[str] = None
    user_agent: Optional[str] = None
    is_success: bool = True
    error_code: Optional[str] = None
    mfa_used: Optional[bool] = None


class GoogleAdminAuditEvent(BaseModel):
    """Parsed Google Workspace Admin audit record."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime
    record_id: Optional[str] = None
    actor_email: str
    ip_address: Optional[str] = None
    event_name: str  # e.g. CHANGE_USER_SETTING, CREATE_USER, GRANT_ADMIN_PRIVILEGE
    event_type: Optional[str] = None
    target_user: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)


class CloudAnomalyAlert(BaseModel):
    """Forensic alert for detected cloud threats, inbox manipulation, or account takeover."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime
    provider: CloudProvider
    classification: CloudThreatClassification
    severity: str = "HIGH"  # MEDIUM, HIGH, CRITICAL
    actor_user: str
    target_mailbox_or_user: Optional[str] = None
    client_ip: Optional[str] = None
    mitre_attack_technique: Optional[str] = None
    detection_reason: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class CloudAuditReport(BaseModel):
    """Master forensic report for Cloud Audit Log triage (M365 & Google Workspace)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    file_path: Optional[str] = None
    filename: str
    size_bytes: int = 0
    hashes: Dict[str, str] = Field(default_factory=dict)
    detected_provider: CloudProvider = CloudProvider.UNKNOWN

    # Event Counts
    total_records_parsed: int = 0
    total_inbox_rules: int = 0
    total_mailbox_delegations: int = 0
    total_oauth_consents: int = 0
    total_logins: int = 0
    total_admin_events: int = 0
    events_by_operation: Dict[str, int] = Field(default_factory=dict)

    # Timeline bounds
    timeline_start: Optional[datetime] = None
    timeline_end: Optional[datetime] = None

    # Extracted Records
    inbox_rules: List[M365InboxRuleRecord] = Field(default_factory=list)
    mailbox_delegations: List[M365MailboxPermissionRecord] = Field(default_factory=list)
    oauth_consents: List[CloudOAuthConsentRecord] = Field(default_factory=list)
    logins: List[CloudLoginRecord] = Field(default_factory=list)
    google_admin_events: List[GoogleAdminAuditEvent] = Field(default_factory=list)

    # Threat Findings
    anomalies: List[CloudAnomalyAlert] = Field(default_factory=list)

    # Summaries
    unique_users: List[str] = Field(default_factory=list)
    unique_client_ips: List[str] = Field(default_factory=list)
    external_forwarding_destinations: List[str] = Field(default_factory=list)

    # Master Timeline Events
    timeline_events: List[TimelineEvent] = Field(default_factory=list)

    # Threat Scoring & Attribution
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    verdict: str = "BENIGN"  # BENIGN, SUSPICIOUS, MALICIOUS
    extracted_iocs: List[str] = Field(default_factory=list)
    executive_summary: str = ""
    remediation_guidance: List[str] = Field(default_factory=list)

    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to a JSON-compatible Python dictionary."""
        return self.model_dump(mode="json")
