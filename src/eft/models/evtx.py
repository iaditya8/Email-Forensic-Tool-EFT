"""Forensic data models for Windows Event Log (EVTX) and Sysmon correlation."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class SysmonEventType(str, Enum):
    """Categorized Microsoft Sysmon event IDs."""

    PROCESS_CREATION = "PROCESS_CREATION"  # Event ID 1
    FILE_CREATION_TIME = "FILE_CREATION_TIME"  # Event ID 2
    NETWORK_CONNECT = "NETWORK_CONNECT"  # Event ID 3
    SERVICE_STATE_CHANGE = "SERVICE_STATE_CHANGE"  # Event ID 4
    PROCESS_TERMINATED = "PROCESS_TERMINATED"  # Event ID 5
    DRIVER_LOADED = "DRIVER_LOADED"  # Event ID 6
    IMAGE_LOADED = "IMAGE_LOADED"  # Event ID 7
    CREATE_REMOTE_THREAD = "CREATE_REMOTE_THREAD"  # Event ID 8
    RAW_ACCESS_READ = "RAW_ACCESS_READ"  # Event ID 9
    PROCESS_ACCESS = "PROCESS_ACCESS"  # Event ID 10
    FILE_CREATE = "FILE_CREATE"  # Event ID 11
    REGISTRY_EVENT = "REGISTRY_EVENT"  # Event ID 12, 13, 14
    FILE_CREATE_STREAM = "FILE_CREATE_STREAM"  # Event ID 15
    NAMED_PIPE = "NAMED_PIPE"  # Event ID 17, 18
    WMI_EVENT = "WMI_EVENT"  # Event ID 19, 20, 21
    DNS_QUERY = "DNS_QUERY"  # Event ID 22
    FILE_DELETE = "FILE_DELETE"  # Event ID 23, 26
    PROCESS_TAMPERING = "PROCESS_TAMPERING"  # Event ID 25
    SECURITY_PROCESS_CREATION = "SECURITY_PROCESS_CREATION"  # Event ID 4688
    UNKNOWN = "UNKNOWN"


class ProcessThreatClassification(str, Enum):
    """Forensic behavioral threat classification for process execution."""

    BENIGN = "BENIGN"
    OFFICE_MACRO_SPAWN = "OFFICE_MACRO_SPAWN"
    WEB_SHELL_SPAWN = "WEB_SHELL_SPAWN"
    LOLBAS_ABUSE = "LOLBAS_ABUSE"
    SUSPICIOUS_PARENT_CHILD = "SUSPICIOUS_PARENT_CHILD"
    ENCODED_COMMAND_EXECUTION = "ENCODED_COMMAND_EXECUTION"
    CREDENTIAL_DUMPING_ATTEMPT = "CREDENTIAL_DUMPING_ATTEMPT"
    SUSPICIOUS_SERVICE_SPAWN = "SUSPICIOUS_SERVICE_SPAWN"


class SysmonProcessCreateEvent(BaseModel):
    """Sysmon Event ID 1 or Security Event ID 4688 Process Creation record."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: int = 1
    timestamp: datetime
    record_id: int = 0
    process_guid: Optional[str] = None
    process_id: int
    image: str
    command_line: str
    current_directory: Optional[str] = None
    user: Optional[str] = None
    logon_guid: Optional[str] = None
    logon_id: Optional[str] = None
    terminal_session_id: Optional[int] = None
    integrity_level: Optional[str] = None
    hashes: Dict[str, str] = Field(default_factory=dict)  # md5, sha256, imphash
    parent_process_guid: Optional[str] = None
    parent_process_id: int = 0
    parent_image: Optional[str] = None
    parent_command_line: Optional[str] = None
    parent_user: Optional[str] = None


class SysmonNetworkEvent(BaseModel):
    """Sysmon Event ID 3 Network Connection record."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: int = 3
    timestamp: datetime
    record_id: int = 0
    process_guid: Optional[str] = None
    process_id: int
    image: str
    user: Optional[str] = None
    protocol: str = "tcp"
    initiated: bool = True
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    destination_hostname: Optional[str] = None
    destination_port_name: Optional[str] = None


class SysmonImageLoadEvent(BaseModel):
    """Sysmon Event ID 7 Image / Module Loaded record."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: int = 7
    timestamp: datetime
    record_id: int = 0
    process_guid: Optional[str] = None
    process_id: int
    image: str
    image_loaded: str
    file_version: Optional[str] = None
    description: Optional[str] = None
    product: Optional[str] = None
    company: Optional[str] = None
    hashes: Dict[str, str] = Field(default_factory=dict)
    signed: Optional[bool] = None
    signature: Optional[str] = None
    signature_status: Optional[str] = None


class SysmonFileCreateEvent(BaseModel):
    """Sysmon Event ID 11 File Create record."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: int = 11
    timestamp: datetime
    record_id: int = 0
    process_guid: Optional[str] = None
    process_id: int
    image: str
    target_filename: str
    creation_time: Optional[datetime] = None


class SuspiciousProcessAnomaly(BaseModel):
    """Forensic alert for an anomalous or malicious process execution."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime
    classification: ProcessThreatClassification
    severity: str = "HIGH"  # MEDIUM, HIGH, CRITICAL
    process_image: str
    process_pid: int
    command_line: str
    parent_image: Optional[str] = None
    parent_pid: int = 0
    mitre_attack_technique: Optional[str] = None  # e.g., "T1059.001 - PowerShell"
    detection_reason: str
    associated_process_guid: Optional[str] = None


class ProcessTreeNode(BaseModel):
    """Correlated node in a process execution hierarchy."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    process_guid: Optional[str] = None
    process_id: int
    image: str
    command_line: str
    user: Optional[str] = None
    start_time: datetime
    parent_guid: Optional[str] = None
    parent_pid: int = 0
    parent_image: Optional[str] = None
    children: List[ProcessTreeNode] = Field(default_factory=list)
    network_connections: List[SysmonNetworkEvent] = Field(default_factory=list)
    loaded_images: List[SysmonImageLoadEvent] = Field(default_factory=list)
    created_files: List[SysmonFileCreateEvent] = Field(default_factory=list)
    threat_classification: ProcessThreatClassification = ProcessThreatClassification.BENIGN
    anomalies: List[SuspiciousProcessAnomaly] = Field(default_factory=list)


class EVTXAnalysisReport(BaseModel):
    """Master forensic report for Windows Event Log (EVTX) and Sysmon activity."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    file_path: Optional[str] = None
    filename: str
    size_bytes: int = 0
    hashes: Dict[str, str] = Field(default_factory=dict)

    # Event Counts
    total_records_parsed: int = 0
    total_sysmon_events: int = 0
    total_security_events: int = 0
    events_by_id: Dict[int, int] = Field(default_factory=dict)
    event_timeline_start: Optional[datetime] = None
    event_timeline_end: Optional[datetime] = None

    # Correlated Process & Activity Trees
    process_trees: List[ProcessTreeNode] = Field(default_factory=list)
    anomalies: List[SuspiciousProcessAnomaly] = Field(default_factory=list)

    # Summaries
    unique_images_executed: List[str] = Field(default_factory=list)
    unique_users: List[str] = Field(default_factory=list)
    network_destinations: List[str] = Field(default_factory=list)

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
