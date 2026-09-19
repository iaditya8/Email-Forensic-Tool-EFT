"""Comprehensive unit and integration tests for Chronological Timeline Generator."""

from datetime import datetime, timedelta, timezone

import pytest

from eft.models.canonical import (
    CanonicalEmail,
    DKIMSignatureArtifact,
    EmailAuthenticationReport,
    ExtractedAttachment,
    RelayHop,
    SourceFileInfo,
    TransitRoute,
)
from eft.models.timeline import (
    ForensicTimelineReport,
    TimelineAnomalyType,
    TimelineEventType,
)
from eft.reporting.timeline import TimelineGenerator


def test_parse_header_date_formats():
    # RFC 2822 with numeric offset
    dt1 = TimelineGenerator.parse_header_date("Mon, 19 Sep 2026 14:00:00 +0000")
    assert dt1 is not None
    assert dt1.tzinfo == timezone.utc
    assert dt1.year == 2026
    assert dt1.month == 9
    assert dt1.day == 19
    assert dt1.hour == 14

    # RFC 2822 with negative offset (-0500)
    dt2 = TimelineGenerator.parse_header_date("19 Sep 2026 09:00:00 -0500")
    assert dt2 is not None
    assert dt2.hour == 14  # 09:00 -0500 converted to UTC is 14:00

    # RFC 2822 with trailing comment
    dt3 = TimelineGenerator.parse_header_date("Mon, 19 Sep 2026 14:00:00 +0000 (UTC)")
    assert dt3 is not None
    assert dt3.hour == 14

    # ISO-8601 with Z
    dt4 = TimelineGenerator.parse_header_date("2026-09-19T14:00:00Z")
    assert dt4 is not None
    assert dt4.hour == 14

    # Empty / Invalid inputs
    assert TimelineGenerator.parse_header_date(None) is None
    assert TimelineGenerator.parse_header_date("") is None
    assert TimelineGenerator.parse_header_date("NOT_A_DATE") is None


def test_format_duration():
    assert TimelineGenerator.format_duration(0.0) == "+0.0s"
    assert TimelineGenerator.format_duration(2.4) == "+2.4s"
    assert TimelineGenerator.format_duration(-5.0) == "-5.0s"
    assert TimelineGenerator.format_duration(125.0) == "+2m 5s"
    assert TimelineGenerator.format_duration(3665.0) == "+1h 1m"
    assert TimelineGenerator.format_duration(90000.0) == "+1d 1h"


@pytest.fixture
def base_canonical_email() -> CanonicalEmail:
    t0 = datetime(2026, 9, 19, 10, 0, 0, tzinfo=timezone.utc)
    t_ingest = t0 + timedelta(minutes=10)

    hop1 = RelayHop(
        hop_number=1,
        from_host="client.sender.org",
        from_ip="198.51.100.10",
        by_host="smtp.sender.org",
        by_ip="198.51.100.25",
        timestamp_utc=t0 + timedelta(seconds=5),
        delay_seconds=5.0,
    )
    hop2 = RelayHop(
        hop_number=2,
        from_host="smtp.sender.org",
        from_ip="198.51.100.25",
        by_host="mx.recipient.com",
        by_ip="203.0.113.50",
        timestamp_utc=t0 + timedelta(seconds=12),
        delay_seconds=7.0,
    )

    dkim = DKIMSignatureArtifact(
        domain="sender.org",
        selector="s2026",
        timestamp_signed=t0 + timedelta(seconds=4),
    )

    att = ExtractedAttachment(
        attachment_index=0,
        filename="report.pdf",
        safe_filename="report.pdf",
        size_bytes=1024,
        hashes={"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
        extracted_timestamp_utc=t0 + timedelta(minutes=9),
    )

    return CanonicalEmail(
        message_id="<test-msg-01@sender.org>",
        date="Sat, 19 Sep 2026 10:00:00 +0000",
        from_address="alice@sender.org",
        to_addresses=["bob@recipient.com"],
        subject="Normal Email Flow",
        transit_route=TransitRoute(total_hops=2, hops=[hop1, hop2]),
        authentication_report=EmailAuthenticationReport(dkim_signatures=[dkim]),
        extracted_attachments=[att],
        ingestion_timestamp_utc=t_ingest,
        source_file=SourceFileInfo(
            file_path="/evidence/msg.eml",
            file_name="msg.eml",
            file_format="eml",
            file_size_bytes=5000,
        ),
    )


def test_generate_timeline_normal_flow(base_canonical_email: CanonicalEmail):
    report = TimelineGenerator.generate_timeline(base_canonical_email)

    assert isinstance(report, ForensicTimelineReport)
    assert report.total_events == 6  # Date, DKIM, Hop 1, Hop 2, Attachment, Ingestion
    assert report.has_time_travel_anomaly is False
    assert report.has_clock_drift is False
    assert report.has_excessive_delay is False
    assert report.has_future_timestamp is False
    assert len(report.anomalies) == 0

    # Verify chronological ordering
    timestamps = [e.timestamp_utc for e in report.events]
    assert timestamps == sorted(timestamps)

    # First event is Client Date (10:00:00)
    assert report.events[0].event_type == TimelineEventType.CLIENT_DATE.value
    assert report.events[0].time_delta_seconds == 0.0

    # Next is DKIM (10:00:04, +4.0s)
    assert report.events[1].event_type == TimelineEventType.DKIM_SIGNATURE.value
    assert report.events[1].time_delta_seconds == 4.0

    # Next is Hop 1 (10:00:05, +1.0s)
    assert report.events[2].event_type == TimelineEventType.MTA_TRANSIT_HOP.value
    assert report.events[2].time_delta_seconds == 1.0

    # Total span
    assert report.total_span_seconds == 600.0
    assert report.total_span_formatted == "+10m 0s"

    # Mermaid diagram check
    assert "timeline" in report.mermaid_timeline
    assert "title Forensic Email Chronological Transit Timeline" in report.mermaid_timeline

    # Markdown summary check
    assert "# Forensic Email Chronological Timeline" in report.summary_markdown
    assert "CHRONOLOGICALLY CONSISTENT" in report.summary_markdown


def test_generate_timeline_time_travel_anomaly(base_canonical_email: CanonicalEmail):
    t0 = datetime(2026, 9, 19, 10, 0, 0, tzinfo=timezone.utc)
    assert base_canonical_email.transit_route is not None

    # Corrupt Hop 2 to occur BEFORE Hop 1 (Negative Time Travel)
    base_canonical_email.transit_route.hops[0].timestamp_utc = t0 + timedelta(seconds=20)
    base_canonical_email.transit_route.hops[1].timestamp_utc = t0 + timedelta(seconds=10)

    report = TimelineGenerator.generate_timeline(base_canonical_email)

    assert report.has_time_travel_anomaly is True
    assert any(TimelineAnomalyType.NEGATIVE_TIME_TRAVEL.value in e.anomalies for e in report.events)
    assert any("TIME TRAVEL ANOMALY" in a for a in report.anomalies)
    assert "ANOMALIES DETECTED" in report.summary_markdown


def test_generate_timeline_excessive_delay(base_canonical_email: CanonicalEmail):
    t0 = datetime(2026, 9, 19, 10, 0, 0, tzinfo=timezone.utc)
    assert base_canonical_email.transit_route is not None

    # Delay Hop 2 by 4 hours
    base_canonical_email.transit_route.hops[1].timestamp_utc = t0 + timedelta(hours=4)
    base_canonical_email.ingestion_timestamp_utc = t0 + timedelta(hours=5)

    report = TimelineGenerator.generate_timeline(
        base_canonical_email, max_delay_threshold_seconds=3600.0
    )

    assert report.has_excessive_delay is True
    assert any(
        TimelineAnomalyType.EXCESSIVE_TRANSIT_DELAY.value in e.anomalies for e in report.events
    )
    assert any("EXCESSIVE DELAY" in a for a in report.anomalies)


def test_generate_timeline_future_timestamp(base_canonical_email: CanonicalEmail):
    t0 = datetime(2026, 9, 19, 10, 0, 0, tzinfo=timezone.utc)
    assert base_canonical_email.transit_route is not None

    # Set Hop 2 timestamp 2 days into the future
    base_canonical_email.transit_route.hops[1].timestamp_utc = t0 + timedelta(days=2)

    report = TimelineGenerator.generate_timeline(base_canonical_email)

    assert report.has_future_timestamp is True
    assert any(TimelineAnomalyType.FUTURE_TIMESTAMP.value in e.anomalies for e in report.events)
    assert any("FUTURE TIMESTAMP" in a for a in report.anomalies)


def test_generate_timeline_clock_drift(base_canonical_email: CanonicalEmail):
    # Set Date header 3 days before Hop 1
    base_canonical_email.date = "Wed, 16 Sep 2026 10:00:00 +0000"

    report = TimelineGenerator.generate_timeline(base_canonical_email)

    assert report.has_clock_drift is True
    assert any(TimelineAnomalyType.CLOCK_DRIFT.value in e.anomalies for e in report.events)
    assert any("CLOCK DRIFT" in a for a in report.anomalies)


def test_generate_timeline_dkim_expiration(base_canonical_email: CanonicalEmail):
    t0 = datetime(2026, 9, 19, 10, 0, 0, tzinfo=timezone.utc)
    assert base_canonical_email.authentication_report is not None
    base_canonical_email.authentication_report.dkim_signatures[0].expiration = t0 + timedelta(
        days=7
    )

    report = TimelineGenerator.generate_timeline(base_canonical_email)
    exp_events = [
        e for e in report.events if e.event_type == TimelineEventType.DKIM_EXPIRATION.value
    ]
    assert len(exp_events) == 1

    assert exp_events[0].actor_or_host == "sender.org"
