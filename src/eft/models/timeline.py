"""Canonical data models for email timeline synthesis, anomaly detection, and visual reporting."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class TimelineEventType(str, Enum):
    """Classification of forensic timeline event origins."""

    CLIENT_DATE = "CLIENT_DATE"
    MTA_TRANSIT_HOP = "MTA_TRANSIT_HOP"
    DKIM_SIGNATURE = "DKIM_SIGNATURE"
    DKIM_EXPIRATION = "DKIM_EXPIRATION"
    ATTACHMENT_EXTRACTION = "ATTACHMENT_EXTRACTION"
    INGESTION_ACQUISITION = "INGESTION_ACQUISITION"
    CUSTOM_EVENT = "CUSTOM_EVENT"


class TimelineAnomalyType(str, Enum):
    """Categorization of chronological discrepancies and anti-forensic anomalies."""

    NEGATIVE_TIME_TRAVEL = "NEGATIVE_TIME_TRAVEL"
    EXCESSIVE_TRANSIT_DELAY = "EXCESSIVE_TRANSIT_DELAY"
    FUTURE_TIMESTAMP = "FUTURE_TIMESTAMP"
    CLOCK_DRIFT = "CLOCK_DRIFT"
    TIMEZONE_DISCREPANCY = "TIMEZONE_DISCREPANCY"


class TimelineEvent(BaseModel):
    """A single discrete chronological forensic event with delta timing and anomaly tags."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: str = Field(
        default_factory=lambda: f"TLE-{uuid.uuid4().hex[:10].upper()}",
        description="Unique identifier for this timeline event",
    )
    timestamp_utc: datetime = Field(
        ...,
        description="Standardized UTC timestamp of the event",
    )
    timestamp_raw: Optional[str] = Field(
        default=None,
        description="Original unparsed timestamp string from header or payload",
    )
    event_type: str = Field(
        ...,
        description="Type of event (CLIENT_DATE, MTA_TRANSIT_HOP, DKIM_SIGNATURE, etc.)",
    )
    source: str = Field(
        ...,
        description="Origin source of the timestamp (e.g., 'Header: Date', 'Hop 1', 'DKIM Signature')",
    )
    description: str = Field(
        ...,
        description="Human-readable description of the event action or transition",
    )
    actor_or_host: Optional[str] = Field(
        default=None,
        description="Identity, MTA server hostname, or IP associated with event",
    )
    hop_number: Optional[int] = Field(
        default=None,
        description="Relay hop index if this event originated from a Received transit header",
    )
    time_delta_seconds: Optional[float] = Field(
        default=None,
        description="Elapsed time in seconds since the preceding timeline event",
    )
    time_delta_formatted: Optional[str] = Field(
        default=None,
        description="Human-friendly elapsed duration string (e.g. '+2.4s', '+1h 12m')",
    )
    anomalies: List[str] = Field(
        default_factory=list,
        description="Chronological anomalies detected at this event (e.g. 'NEGATIVE_TIME_TRAVEL')",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary structured context (IPs, ciphers, selectors)",
    )


class ForensicTimelineReport(BaseModel):
    """Complete forensic timeline synthesis report containing ordered events, anomaly metrics, and Mermaid diagrams."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    total_events: int = Field(default=0, description="Total number of events in timeline")
    first_event_utc: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp of the earliest recorded event",
    )
    last_event_utc: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp of the latest recorded event",
    )
    total_span_seconds: float = Field(
        default=0.0,
        description="Total duration in seconds from first event to last event",
    )
    total_span_formatted: str = Field(
        default="0s",
        description="Human-readable total span of the email lifecycle",
    )
    events: List[TimelineEvent] = Field(
        default_factory=list,
        description="Chronologically sorted sequence of all forensic events",
    )
    has_time_travel_anomaly: bool = Field(
        default=False,
        description="True if any MTA hop or event recorded an impossible negative time delta",
    )
    has_clock_drift: bool = Field(
        default=False,
        description="True if server clock drift was detected between transit hops",
    )
    has_excessive_delay: bool = Field(
        default=False,
        description="True if any transit interval exceeded the excessive delay threshold",
    )
    has_future_timestamp: bool = Field(
        default=False,
        description="True if any timestamp occurred in the future relative to delivery or ingestion",
    )
    anomalies: List[str] = Field(
        default_factory=list,
        description="Comprehensive list of timeline anomaly summary strings",
    )
    mermaid_timeline: str = Field(
        default="",
        description="Rendered pure Mermaid diagram syntax representing the timeline visually",
    )
    summary_markdown: str = Field(
        default="",
        description="Executive markdown summary and event table for DFIR reports",
    )
