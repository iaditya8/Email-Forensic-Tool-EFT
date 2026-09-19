"""MTA Relay Hop reconstruction, transit latency calculation, and routing anomaly detector."""

from __future__ import annotations

import email.utils
import ipaddress
import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from eft.models.canonical import CanonicalEmail, RelayHop, TransitRoute

# Regular expressions for standard RFC 5321/5322 Received header tokens
FROM_CLAUSE_REGEX = re.compile(r"\bfrom\s+([^\s;]+(?:\s*\([^)]*\))?)", re.IGNORECASE)
BY_CLAUSE_REGEX = re.compile(r"\bby\s+([^\s;]+(?:\s*\([^)]*\))?)", re.IGNORECASE)
WITH_CLAUSE_REGEX = re.compile(r"\bwith\s+([a-zA-Z0-9_-]+)", re.IGNORECASE)
ID_CLAUSE_REGEX = re.compile(r"\bid\s+([^\s;]+)", re.IGNORECASE)
FOR_CLAUSE_REGEX = re.compile(r"\bfor\s+(<[^>]+>|[^\s;]+)", re.IGNORECASE)
AUTH_CLAUSE_REGEX = re.compile(r"\b(?:authenticated as|auth=)\s*([^\s;)]+)", re.IGNORECASE)
TLS_CLAUSE_REGEX = re.compile(r"\b(?:using TLS|cipher=)\s*([^;)]+)", re.IGNORECASE)

# IP Pattern matching (captures potential IPv4 and IPv6 strings)
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_REGEX = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F:]{1,7}\b"
    r"|\[([0-9a-fA-F:]+)\]"
)


class RelayAnalyzer:
    """Reconstructs MTA relay hops, measures hop latencies, and detects route anomalies."""

    @classmethod
    def extract_ips(cls, text: str) -> List[str]:
        """Extract and validate all IPv4 and IPv6 addresses from a string.

        Filters out non-IP numbers (e.g. software version numbers like 8.14.4.1).

        Args:
            text: Arbitrary string snippet (e.g., within parentheses/brackets).

        Returns:
            List of valid IP address strings.
        """
        valid_ips: List[str] = []
        if not text:
            return valid_ips

        # 1. Search IPv4 candidates
        for match in IPV4_REGEX.finditer(text):
            candidate = match.group(0)
            try:
                ip4 = ipaddress.IPv4Address(candidate)
                valid_ips.append(str(ip4))
            except (ipaddress.AddressValueError, ValueError):
                continue

        # 2. Search IPv6 candidates
        for match in IPV6_REGEX.finditer(text):
            candidate = match.group(1) if match.group(1) else match.group(0)
            candidate = candidate.strip("[]")
            try:
                ip6 = ipaddress.IPv6Address(candidate)
                valid_ips.append(str(ip6))
            except (ipaddress.AddressValueError, ValueError):
                continue

        return valid_ips

    @classmethod
    def is_ip_private(cls, ip_str: Optional[str]) -> bool:
        """Check if an IP address is an internal private, loopback, or link-local address."""
        if not ip_str:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    @classmethod
    def parse_timestamp(cls, date_str: str) -> Tuple[Optional[str], Optional[datetime]]:
        """Parse an RFC 2822 / 5322 date string and normalize it to UTC datetime.

        Args:
            date_str: Raw date substring from Received header.

        Returns:
            Tuple of (cleaned_raw_string, datetime_utc_or_none).
        """
        clean_str = date_str.strip()
        if not clean_str:
            return None, None

        # Clean off trailing parenthetical comments like '(UTC)' or '(EDT)'
        normalized_str = re.sub(r"\s*\([^)]*\)\s*$", "", clean_str).strip()

        try:
            dt = email.utils.parsedate_to_datetime(normalized_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return clean_str, dt
        except Exception:
            return clean_str, None

    @classmethod
    def parse_received_header(cls, raw_header: str, hop_index: int = 1) -> RelayHop:
        """Parse a single RFC 5321/5322 Received header into a structured RelayHop model.

        Args:
            raw_header: Complete string value of the Received header.
            hop_index: 1-indexed position in the chronological transmission sequence.

        Returns:
            RelayHop model populated with hosts, IPs, protocols, and timestamp.
        """
        anomalies: List[str] = []
        normalized_header = re.sub(r"\s+", " ", raw_header).strip()

        # Split on the last semicolon delimiter separating clauses from timestamp
        if ";" in normalized_header:
            clauses_part, _, date_part = normalized_header.rpartition(";")
        else:
            clauses_part = normalized_header
            date_part = ""
            anomalies.append("Missing semicolon timestamp delimiter in Received header.")

        timestamp_raw, timestamp_utc = cls.parse_timestamp(date_part)
        if date_part and timestamp_utc is None:
            anomalies.append(f"Unparseable timestamp format: '{date_part.strip()}'.")

        # Extract clauses
        from_host: Optional[str] = None
        from_ip: Optional[str] = None
        by_host: Optional[str] = None
        by_ip: Optional[str] = None

        from_match = FROM_CLAUSE_REGEX.search(clauses_part)
        if from_match:
            from_text = from_match.group(1).strip()
            # Extract IPs from 'from' clause
            from_ips = cls.extract_ips(from_text)
            if from_ips:
                from_ip = from_ips[0]
            # Extract host name (first token or rdns)
            host_tokens = from_text.split()
            if host_tokens:
                from_host = host_tokens[0].rstrip("()")

        by_match = BY_CLAUSE_REGEX.search(clauses_part)
        if by_match:
            by_text = by_match.group(1).strip()
            by_ips = cls.extract_ips(by_text)
            if by_ips:
                by_ip = by_ips[0]
            by_tokens = by_text.split()
            if by_tokens:
                by_host = by_tokens[0].rstrip("()")

        # Extract protocol and id
        protocol: Optional[str] = None
        proto_match = WITH_CLAUSE_REGEX.search(clauses_part)
        if proto_match:
            protocol = proto_match.group(1).upper()

        msg_id: Optional[str] = None
        id_match = ID_CLAUSE_REGEX.search(clauses_part)
        if id_match:
            msg_id = id_match.group(1).strip()

        auth_user: Optional[str] = None
        auth_match = AUTH_CLAUSE_REGEX.search(clauses_part)
        if auth_match:
            auth_user = auth_match.group(1).strip()

        tls_cipher: Optional[str] = None
        tls_match = TLS_CLAUSE_REGEX.search(clauses_part)
        if tls_match:
            tls_cipher = tls_match.group(1).strip()

        # Check if from_ip is private
        is_private = cls.is_ip_private(from_ip)

        return RelayHop(
            hop_number=hop_index,
            raw_header=normalized_header,
            from_host=from_host,
            from_ip=from_ip,
            by_host=by_host,
            by_ip=by_ip,
            protocol=protocol,
            auth_user=auth_user,
            tls_cipher=tls_cipher,
            message_id_stamp=msg_id,
            timestamp_raw=timestamp_raw,
            timestamp_utc=timestamp_utc,
            delay_seconds=0.0,
            is_private_ip=is_private,
            is_originating_hop=(hop_index == 1),
            anomalies=anomalies,
        )

    @classmethod
    def reconstruct_route(cls, received_headers: List[str]) -> TransitRoute:
        """Reconstruct chronological transit route from an email's Received headers.

        Important: `received_headers` in email headers are top-down (newest/recipient MTA first).
        This method reverses them to produce chronological Hop 1 -> Hop N order.

        Args:
            received_headers: Ordered list of Received header string values.

        Returns:
            TransitRoute model with chronological hops, delays, originating IP, and anomalies.
        """
        if not received_headers:
            return TransitRoute(
                total_hops=0,
                total_transit_seconds=0.0,
                originating_ip=None,
                originating_host=None,
                hops=[],
                anomalies_detected=[],
            )

        # RFC 5321 Reversal: Bottom Received header is Hop 1 (earliest origin), Top is Hop N (final recipient)
        chronological_headers = list(reversed(received_headers))
        hops: List[RelayHop] = []
        global_anomalies: List[str] = []

        prev_timestamp: Optional[datetime] = None

        for idx, raw_hdr in enumerate(chronological_headers, start=1):
            hop = cls.parse_received_header(raw_hdr, hop_index=idx)

            # Compute hop transit delay if both timestamps are valid
            if hop.timestamp_utc and prev_timestamp:
                delta = (hop.timestamp_utc - prev_timestamp).total_seconds()
                hop.delay_seconds = delta

                if delta < 0:
                    anomaly_msg = (
                        f"Hop {idx}: Negative transit delay ({delta:.1f}s) relative to Hop {idx - 1} "
                        f"(possible clock skew, NTP desynchronization, or forged transit header)."
                    )
                    hop.anomalies.append(anomaly_msg)
                    global_anomalies.append(anomaly_msg)
                elif delta > 86400:
                    anomaly_msg = (
                        f"Hop {idx}: Excessive transit latency ({delta / 3600:.1f} hours)."
                    )
                    hop.anomalies.append(anomaly_msg)
                    global_anomalies.append(anomaly_msg)
            else:
                hop.delay_seconds = 0.0

            if hop.timestamp_utc:
                prev_timestamp = hop.timestamp_utc

            # Check for suspicious private IP in intermediate or external hops
            if idx > 1 and hop.is_private_ip and not cls.is_ip_private(hop.by_ip):
                anomaly_msg = f"Hop {idx}: Internal private IP '{hop.from_ip}' received by external host '{hop.by_host}'."
                hop.anomalies.append(anomaly_msg)
                global_anomalies.append(anomaly_msg)

            hops.append(hop)

        # Determine Originating IP & Host
        originating_ip: Optional[str] = None
        originating_host: Optional[str] = None

        # Prioritize first hop with a valid public IP, or fallback to hop 1
        for hop in hops:
            if hop.from_ip and not hop.is_private_ip:
                originating_ip = hop.from_ip
                originating_host = hop.from_host
                break

        if not originating_ip and hops:
            originating_ip = hops[0].from_ip
            originating_host = hops[0].from_host

        total_transit = sum(max(0.0, h.delay_seconds) for h in hops)

        return TransitRoute(
            total_hops=len(hops),
            total_transit_seconds=total_transit,
            originating_ip=originating_ip,
            originating_host=originating_host,
            hops=hops,
            anomalies_detected=global_anomalies,
        )

    @classmethod
    def analyze_email(cls, email: CanonicalEmail) -> TransitRoute:
        """Analyze a CanonicalEmail instance, reconstruct route, and populate email.transit_route.

        Args:
            email: CanonicalEmail containing header decomposition or ordered headers.

        Returns:
            Populated TransitRoute model.
        """
        received_list: List[str] = []

        if email.header_decomposition and email.header_decomposition.received_headers:
            received_list = email.header_decomposition.received_headers
        else:
            # Extract from ordered headers or headers dict
            for name, val in email.ordered_headers:
                if name.lower() == "received":
                    received_list.append(val)

        if not received_list and "received" in email.headers:
            header_val = email.headers["received"]
            if isinstance(header_val, list):
                received_list = list(header_val)
            elif isinstance(header_val, str):
                received_list = [header_val]

        route = cls.reconstruct_route(received_list)
        email.transit_route = route
        return route
