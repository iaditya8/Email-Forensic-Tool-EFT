"""Forensic data models for Windows logon analysis, privilege escalation, and persistence detection."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from eft.models.timeline import TimelineEvent


class WindowsLogonType(int, Enum):
    """Windows Security Logon Types (Event 4624 / 4625)."""

    INTERACTIVE = 2  # Console / Local keyboard logon
    NETWORK = 3  # Network logon (SMB, RPC, IIS)
    BATCH = 4  # Scheduled batch job
    SERVICE = 5  # Windows Service logon
    UNLOCK = 7  # Workstation unlock
    NETWORK_CLEARTEXT = 8  # Cleartext credentials sent over network
    NEW_CREDENTIALS = 9  # RunAs / Pass-the-Hash / Overpass-the-Hash
    REMOTE_INTERACTIVE = 10  # RDP / Remote Desktop / Terminal Services
    CACHED_INTERACTIVE = 11  # Logon with cached domain credentials (offline)
    CACHED_REMOTE_INTERACTIVE = 12
    CACHED_UNLOCK = 13
    UNKNOWN = 0


class SecurityThreatClassification(str, Enum):
    """Behavioral threat classification for Windows security events."""

    BENIGN = "BENIGN"
    BRUTE_FORCE_ATTACK = "BRUTE_FORCE_ATTACK"
    PASSWORD_SPRAY = "PASSWORD_SPRAY"
    PASS_THE_HASH = "PASS_THE_HASH"
    ANOMALOUS_ADMIN_LOGON = "ANOMALOUS_ADMIN_LOGON"
    OFF_HOURS_LOGON = "OFF_HOURS_LOGON"
    CLEARTEXT_LOGON = "CLEARTEXT_LOGON"
    SUSPICIOUS_SERVICE_INSTALLATION = "SUSPICIOUS_SERVICE_INSTALLATION"
    SUSPICIOUS_SCHEDULED_TASK = "SUSPICIOUS_SCHEDULED_TASK"
    UNAUTHORIZED_ACCOUNT_CREATION = "UNAUTHORIZED_ACCOUNT_CREATION"
    PRIVILEGE_GROUP_ESCALATION = "PRIVILEGE_GROUP_ESCALATION"


class LogonEvent(BaseModel):
    """Parsed Windows Security Event 4624 (Success) or 4625 (Failure)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: int  # 4624 or 4625
    record_id: int = 0
    timestamp: datetime
    is_success: bool = True
    logon_type: WindowsLogonType = WindowsLogonType.UNKNOWN
    logon_type_id: int = 0
    target_user_name: str
    target_domain_name: Optional[str] = None
    target_user_sid: Optional[str] = None
    target_logon_id: Optional[str] = None
    subject_user_name: Optional[str] = None
    subject_domain_name: Optional[str] = None
    subject_user_sid: Optional[str] = None
    ip_address: Optional[str] = None
    ip_port: Optional[int] = None
    workstation_name: Optional[str] = None
    authentication_package_name: Optional[str] = None
    logon_process_name: Optional[str] = None
    elevated_token: Optional[bool] = None
    status: Optional[str] = None  # e.g. 0x0
    sub_status: Optional[str] = None  # e.g. 0xC000006A (bad password)
    failure_reason: Optional[str] = None


class PrivilegeAssignedEvent(BaseModel):
    """Parsed Windows Security Event 4672 (Special Privileges Assigned to New Logon)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: int = 4672
    record_id: int = 0
    timestamp: datetime
    subject_user_name: str
    subject_domain_name: Optional[str] = None
    subject_user_sid: Optional[str] = None
    subject_logon_id: Optional[str] = None
    privilege_list: List[str] = Field(default_factory=list)  # e.g. SeDebugPrivilege, SeTcbPrivilege


class ServiceInstalledEvent(BaseModel):
    """Parsed Windows System Event 7045 or Security Event 4697 (Service Installed)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: int = 7045  # 7045 or 4697
    record_id: int = 0
    timestamp: datetime
    service_name: str
    image_path: str
    service_type: Optional[str] = None  # e.g. user mode service, kernel driver
    start_type: Optional[str] = None  # e.g. auto start, demand start
    account_name: Optional[str] = None  # e.g. LocalSystem, Administrator
    subject_user_name: Optional[str] = None


class ScheduledTaskEvent(BaseModel):
    """Parsed Windows Security Event 4698 (Task Created) or 4702 (Task Updated)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: int = 4698
    record_id: int = 0
    timestamp: datetime
    task_name: str
    action_command: Optional[str] = None
    action_arguments: Optional[str] = None
    user_context: Optional[str] = None
    subject_user_name: Optional[str] = None
    task_xml_raw: Optional[str] = None


class AccountManagementEvent(BaseModel):
    """Parsed Windows Security Event 4720 (User Created) or 4728/4732/4756 (Group Member Added)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: int  # 4720, 4728, 4732, 4756
    record_id: int = 0
    timestamp: datetime
    action: (
        str  # "USER_CREATED", "MEMBER_ADDED_TO_GLOBAL_GROUP", "MEMBER_ADDED_TO_LOCAL_GROUP", etc.
    )
    target_user_name: str
    target_domain_name: Optional[str] = None
    target_sid: Optional[str] = None
    group_name: Optional[str] = None
    group_domain_name: Optional[str] = None
    group_sid: Optional[str] = None
    subject_user_name: Optional[str] = None
    subject_domain_name: Optional[str] = None


class SecurityAnomalyAlert(BaseModel):
    """Forensic alert for detected authentication anomalies, persistence, or privilege abuse."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime
    classification: SecurityThreatClassification
    severity: str = "HIGH"  # MEDIUM, HIGH, CRITICAL
    target_user: Optional[str] = None
    source_ip: Optional[str] = None
    mitre_attack_technique: Optional[str] = None
    detection_reason: str
    evidence_count: int = 1
    associated_records: List[int] = Field(default_factory=list)


class SecurityLogonReport(BaseModel):
    """Master forensic report for Windows Security logons, persistence mechanisms, and timeline."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    file_path: Optional[str] = None
    filename: str
    size_bytes: int = 0
    hashes: Dict[str, str] = Field(default_factory=dict)

    # Event Counts
    total_events_parsed: int = 0
    total_successful_logons: int = 0
    total_failed_logons: int = 0
    total_admin_logons: int = 0
    total_services_installed: int = 0
    total_scheduled_tasks: int = 0
    total_account_changes: int = 0
    events_by_id: Dict[int, int] = Field(default_factory=dict)

    # Timeline bounds
    timeline_start: Optional[datetime] = None
    timeline_end: Optional[datetime] = None

    # Extracted Records
    logons: List[LogonEvent] = Field(default_factory=list)
    special_privileges: List[PrivilegeAssignedEvent] = Field(default_factory=list)
    services_installed: List[ServiceInstalledEvent] = Field(default_factory=list)
    scheduled_tasks: List[ScheduledTaskEvent] = Field(default_factory=list)
    account_management_events: List[AccountManagementEvent] = Field(default_factory=list)

    # Behavioral Threat Findings
    anomalies: List[SecurityAnomalyAlert] = Field(default_factory=list)

    # Summaries
    unique_users: List[str] = Field(default_factory=list)
    unique_source_ips: List[str] = Field(default_factory=list)
    logons_by_type: Dict[str, int] = Field(default_factory=dict)

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
