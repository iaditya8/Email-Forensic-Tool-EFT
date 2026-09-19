"""Chronological timeline synthesis, anti-forensic anomaly detection, and visual reporting engine."""

from __future__ import annotations

import email.utils
import re
from datetime import datetime, timezone
from typing import List, Optional

from eft.models.canonical import CanonicalEmail
from eft.models.timeline import (
    ForensicTimelineReport,
    TimelineAnomalyType,
    TimelineEvent,
    TimelineEventType,
)


class TimelineGenerator:
    """Forensic timeline synthesis engine that reconstructs chronological email lifecycles."""

    @classmethod
    def parse_header_date(cls, date_str: Optional[str]) -> Optional[datetime]:
        """Safely parse RFC 2822, RFC 5322, or ISO formatted date strings into UTC datetime.

        Args:
            date_str: Raw date header or timestamp string.

        Returns:
            Timezone-aware UTC datetime, or None if unparseable.
        """
        if not date_str:
            return None

        cleaned = date_str.strip()
        # Strip trailing comments in parentheses (e.g., "(UTC)")

        cleaned = re.sub(r"\s*\([^)]*\)", "", cleaned).strip()

        # 1. Try standard email parsedate_to_datetime
        try:
            dt = email.utils.parsedate_to_datetime(cleaned)
            if dt is not None:
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
        except Exception:
            pass

        # 2. Try ISO-8601 format
        try:
            iso_clean = cleaned.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

        return None

    @classmethod
    def format_duration(cls, seconds: float) -> str:
        """Format an elapsed duration in seconds to a human-friendly string.

        Args:
            seconds: Elapsed duration in seconds (can be negative).

        Returns:
            Human readable string, e.g. '+0.0s', '+3.4s', '-12.0s', '+5m 20s', '+2h 15m'.
        """
        prefix = "+" if seconds >= 0 else "-"
        abs_sec = abs(seconds)

        if abs_sec < 60:
            return f"{prefix}{abs_sec:.1f}s"
        elif abs_sec < 3600:
            minutes = int(abs_sec // 60)
            rem_sec = int(abs_sec % 60)
            return f"{prefix}{minutes}m {rem_sec}s"
        elif abs_sec < 86400:
            hours = int(abs_sec // 3600)
            rem_min = int((abs_sec % 3600) // 60)
            return f"{prefix}{hours}h {rem_min}m"
        else:
            days = int(abs_sec // 86400)
            rem_hours = int((abs_sec % 86400) // 3600)
            return f"{prefix}{days}d {rem_hours}h"

    @classmethod
    def generate_timeline(
        cls,
        email_obj: CanonicalEmail,
        max_delay_threshold_seconds: float = 3600.0,
    ) -> ForensicTimelineReport:
        """Synthesize all lifecycle timestamps into an ordered forensic timeline report.

        Args:
            email_obj: The CanonicalEmail instance with headers, transit route, and auth info.
            max_delay_threshold_seconds: Transit interval threshold above which a delay is flagged (default 1h).

        Returns:
            Comprehensive ForensicTimelineReport.
        """
        raw_events: List[TimelineEvent] = []

        # 1. Client Submission Date Header
        client_date_str: Optional[str] = None
        if email_obj.date:
            client_date_str = email_obj.date
        elif "date" in email_obj.headers:
            val = email_obj.headers["date"]
            if isinstance(val, list) and val:
                client_date_str = val[0]
            elif isinstance(val, str):
                client_date_str = val

        if client_date_str:
            client_dt = cls.parse_header_date(client_date_str)
            if client_dt:
                raw_events.append(
                    TimelineEvent(
                        timestamp_utc=client_dt,
                        timestamp_raw=client_date_str,
                        event_type=TimelineEventType.CLIENT_DATE.value,
                        source="Header: Date",
                        description=f"Client composed/submitted message from {email_obj.from_address or 'sender'}",
                        actor_or_host=email_obj.from_address,
                        details={"date_header_raw": client_date_str},
                    )
                )

        # 2. MTA Transit Relay Hops
        if email_obj.transit_route and email_obj.transit_route.hops:
            for hop in email_obj.transit_route.hops:
                hop_dt = hop.timestamp_utc or cls.parse_header_date(hop.timestamp_raw)
                if hop_dt:
                    from_desc = hop.from_host or hop.from_ip or "origin"
                    by_desc = hop.by_host or hop.by_ip or "recipient-mta"
                    raw_events.append(
                        TimelineEvent(
                            timestamp_utc=hop_dt,
                            timestamp_raw=hop.timestamp_raw,
                            event_type=TimelineEventType.MTA_TRANSIT_HOP.value,
                            source=f"MTA Hop {hop.hop_number}",
                            description=f"Relayed from '{from_desc}' by '{by_desc}' ({hop.protocol or 'ESMTP'})",
                            actor_or_host=hop.by_host or hop.by_ip,
                            hop_number=hop.hop_number,
                            details={
                                "from_host": hop.from_host,
                                "from_ip": hop.from_ip,
                                "by_host": hop.by_host,
                                "by_ip": hop.by_ip,
                                "tls_cipher": hop.tls_cipher,
                                "delay_seconds": hop.delay_seconds,
                            },
                        )
                    )

        # 3. DKIM Signature Cryptographic Timestamps
        if email_obj.authentication_report and email_obj.authentication_report.dkim_signatures:
            for dkim in email_obj.authentication_report.dkim_signatures:
                if dkim.timestamp_signed:
                    raw_events.append(
                        TimelineEvent(
                            timestamp_utc=dkim.timestamp_signed,
                            timestamp_raw=dkim.timestamp_signed.isoformat(),
                            event_type=TimelineEventType.DKIM_SIGNATURE.value,
                            source=f"DKIM Signature (d={dkim.domain})",
                            description=f"Cryptographic signature generated (selector: s={dkim.selector}, alg: {dkim.algorithm})",
                            actor_or_host=dkim.domain,
                            details={
                                "selector": dkim.selector,
                                "domain": dkim.domain,
                                "algorithm": dkim.algorithm,
                                "status": dkim.status,
                            },
                        )
                    )
                if dkim.expiration:
                    raw_events.append(
                        TimelineEvent(
                            timestamp_utc=dkim.expiration,
                            timestamp_raw=dkim.expiration.isoformat(),
                            event_type=TimelineEventType.DKIM_EXPIRATION.value,
                            source=f"DKIM Expiration (d={dkim.domain})",
                            description=f"Cryptographic signature expiration deadline for domain '{dkim.domain}'",
                            actor_or_host=dkim.domain,
                            details={"domain": dkim.domain, "selector": dkim.selector},
                        )
                    )

        # 4. Attachment Extraction Timestamps
        if email_obj.extracted_attachments:
            for att in email_obj.extracted_attachments:
                raw_events.append(
                    TimelineEvent(
                        timestamp_utc=att.extracted_timestamp_utc,
                        timestamp_raw=att.extracted_timestamp_utc.isoformat(),
                        event_type=TimelineEventType.ATTACHMENT_EXTRACTION.value,
                        source=f"Attachment: {att.safe_filename}",
                        description=f"Forensically extracted attachment '{att.filename}' ({att.size_bytes:,} bytes, SHA-256: {att.hashes.get('sha256', '')[:12]}...)",
                        actor_or_host="EFT-Attachment-Extractor",
                        details={
                            "filename": att.filename,
                            "size_bytes": att.size_bytes,
                            "hashes": att.hashes,
                        },
                    )
                )

        # 5. Ingestion Acquisition Timestamp
        raw_events.append(
            TimelineEvent(
                timestamp_utc=email_obj.ingestion_timestamp_utc,
                timestamp_raw=email_obj.ingestion_timestamp_utc.isoformat(),
                event_type=TimelineEventType.INGESTION_ACQUISITION.value,
                source="EFT Evidence Ingestion",
                description="Forensic evidence ingested and parsed into canonical representation",
                actor_or_host="EFT Core Engine",
                details={
                    "file_name": email_obj.source_file.file_name if email_obj.source_file else None
                },
            )
        )

        # Sort all events chronologically
        sorted_events = sorted(raw_events, key=lambda e: e.timestamp_utc)

        # Detect Chronological Anomalies and Calculate Deltas
        global_anomalies: List[str] = []
        has_time_travel = False
        has_clock_drift = False
        has_excessive_delay = False
        has_future_timestamp = False

        # Track MTA hop progression specifically to check for logical ordering vs chronological ordering
        hop_events = [
            e for e in sorted_events if e.event_type == TimelineEventType.MTA_TRANSIT_HOP.value
        ]
        # Check if hop_numbers are strictly non-decreasing in chronological timeline
        last_seen_hop = 0
        for hop_evt in hop_events:
            current_hop_num = hop_evt.hop_number or 0
            if current_hop_num < last_seen_hop:
                has_time_travel = True
                anomaly_msg = (
                    f"TIME TRAVEL ANOMALY: Hop {current_hop_num} ({hop_evt.actor_or_host}) "
                    f"has an earlier timestamp than upstream Hop {last_seen_hop}."
                )
                hop_evt.anomalies.append(TimelineAnomalyType.NEGATIVE_TIME_TRAVEL.value)
                if anomaly_msg not in global_anomalies:
                    global_anomalies.append(anomaly_msg)
            else:
                last_seen_hop = current_hop_num

        # Check deltas between sequential events
        for i, event in enumerate(sorted_events):
            if i == 0:
                event.time_delta_seconds = 0.0
                event.time_delta_formatted = "+0.0s"
            else:
                prev_event = sorted_events[i - 1]
                delta_sec = (event.timestamp_utc - prev_event.timestamp_utc).total_seconds()
                event.time_delta_seconds = delta_sec
                event.time_delta_formatted = cls.format_duration(delta_sec)

                # Check excessive delay between transit events
                if (
                    delta_sec > max_delay_threshold_seconds
                    and event.event_type == TimelineEventType.MTA_TRANSIT_HOP.value
                ):
                    has_excessive_delay = True
                    delay_msg = (
                        f"EXCESSIVE DELAY: {cls.format_duration(delta_sec)} transit delay observed "
                        f"between '{prev_event.source}' and '{event.source}' (threshold: {max_delay_threshold_seconds:.0f}s)."
                    )
                    event.anomalies.append(TimelineAnomalyType.EXCESSIVE_TRANSIT_DELAY.value)
                    if delay_msg not in global_anomalies:
                        global_anomalies.append(delay_msg)

            # Check future timestamp relative to ingestion
            if (event.timestamp_utc - email_obj.ingestion_timestamp_utc).total_seconds() > 300:
                has_future_timestamp = True
                future_msg = (
                    f"FUTURE TIMESTAMP: Event '{event.source}' recorded timestamp "
                    f"{event.timestamp_utc.strftime('%Y-%m-%d %H:%M:%S UTC')} after ingestion."
                )
                event.anomalies.append(TimelineAnomalyType.FUTURE_TIMESTAMP.value)
                if future_msg not in global_anomalies:
                    global_anomalies.append(future_msg)

        # Check client Date vs Hop 1 drift
        client_evts = [
            e for e in sorted_events if e.event_type == TimelineEventType.CLIENT_DATE.value
        ]
        if client_evts and hop_events:
            c_ts = client_evts[0].timestamp_utc
            h1_ts = hop_events[0].timestamp_utc
            diff_sec = (h1_ts - c_ts).total_seconds()
            if diff_sec < -60 or diff_sec > 86400:
                has_clock_drift = True
                drift_msg = (
                    f"CLOCK DRIFT: Client Date header and Hop 1 timestamp differ by "
                    f"{cls.format_duration(diff_sec)}."
                )
                client_evts[0].anomalies.append(TimelineAnomalyType.CLOCK_DRIFT.value)
                if drift_msg not in global_anomalies:
                    global_anomalies.append(drift_msg)

        first_evt_dt = sorted_events[0].timestamp_utc if sorted_events else None
        last_evt_dt = sorted_events[-1].timestamp_utc if sorted_events else None
        total_span = (
            (last_evt_dt - first_evt_dt).total_seconds() if first_evt_dt and last_evt_dt else 0.0
        )

        report = ForensicTimelineReport(
            total_events=len(sorted_events),
            first_event_utc=first_evt_dt,
            last_event_utc=last_evt_dt,
            total_span_seconds=total_span,
            total_span_formatted=cls.format_duration(total_span),
            events=sorted_events,
            has_time_travel_anomaly=has_time_travel,
            has_clock_drift=has_clock_drift,
            has_excessive_delay=has_excessive_delay,
            has_future_timestamp=has_future_timestamp,
            anomalies=global_anomalies,
        )

        # Render visualizations
        report.mermaid_timeline = cls.generate_mermaid_timeline(report)
        report.summary_markdown = cls.generate_markdown_timeline(report)

        return report

    @classmethod
    def generate_mermaid_timeline(cls, report: ForensicTimelineReport) -> str:
        """Generate a pure Mermaid timeline diagram visualizing chronological email transit.

        Args:
            report: The compiled ForensicTimelineReport.

        Returns:
            Valid Mermaid timeline syntax string.
        """
        lines = [
            "timeline",
            "    title Forensic Email Chronological Transit Timeline",
        ]

        # Group events by date or distinct timestamp periods
        for event in report.events:
            date_key = event.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

            # Sanitize description for Mermaid syntax
            clean_desc = event.description.replace('"', "'").replace(":", " -").replace("#", "")
            clean_source = event.source.replace('"', "'").replace(":", " -")
            anomaly_tag = f" [ANOMALY: {','.join(event.anomalies)}]" if event.anomalies else ""

            entry_label = f"{clean_source}{anomaly_tag} : {clean_desc}"
            lines.append(f"    {date_key} : {entry_label}")

        return "\n".join(lines)

    @classmethod
    def generate_markdown_timeline(cls, report: ForensicTimelineReport) -> str:
        """Format an executive markdown table and timeline summary card.

        Args:
            report: The compiled ForensicTimelineReport.

        Returns:
            Markdown document string.
        """
        status = "ANOMALIES DETECTED" if report.anomalies else "CHRONOLOGICALLY CONSISTENT"
        lines = [
            "# Forensic Email Chronological Timeline",
            f"- **Timeline Status:** `{status}`",
            f"- **Total Events:** {report.total_events}",
            f"- **First Event (UTC):** {report.first_event_utc.strftime('%Y-%m-%d %H:%M:%S UTC') if report.first_event_utc else 'N/A'}",
            f"- **Last Event (UTC):** {report.last_event_utc.strftime('%Y-%m-%d %H:%M:%S UTC') if report.last_event_utc else 'N/A'}",
            f"- **Total Span:** `{report.total_span_formatted}`",
        ]

        if report.anomalies:
            lines.extend(
                [
                    "",
                    "### ⚠️ Chronological & Clock Anomalies",
                ]
            )
            for anomaly in report.anomalies:
                lines.append(f"- **{anomaly}**")

        lines.extend(
            [
                "",
                "### Detailed Event Sequence",
                "| # | Timestamp (UTC) | Delta | Source | Event Type | Description | Anomalies |",
                "|---|---|---|---|---|---|---|",
            ]
        )

        for idx, evt in enumerate(report.events, 1):
            ts = evt.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S")
            delta = evt.time_delta_formatted or "+0.0s"
            src = evt.source.replace("|", "\\|")
            desc = evt.description.replace("|", "\\|")
            anom = ", ".join(evt.anomalies) if evt.anomalies else "-"
            lines.append(
                f"| {idx} | {ts} | `{delta}` | {src} | `{evt.event_type}` | {desc} | `{anom}` |"
            )

        lines.extend(
            [
                "",
                "### Mermaid Timeline Visualization",
                "```mermaid",
                report.mermaid_timeline,
                "```",
            ]
        )

        return "\n".join(lines)
