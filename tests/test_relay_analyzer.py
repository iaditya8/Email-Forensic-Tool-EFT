"""Unit tests for MTA relay hop reconstruction, latency calculation, and anomaly detection."""

from datetime import datetime, timezone

from eft.analysis.relay_analyzer import RelayAnalyzer
from eft.models.canonical import CanonicalEmail, HeaderDecomposition


def test_extract_ips():
    """Test extraction and validation of IPv4 and IPv6 addresses."""
    text1 = "from mail.server.com (unknown [209.85.208.177]) by mx.google.com"
    assert RelayAnalyzer.extract_ips(text1) == ["209.85.208.177"]

    text2 = "from ([2001:db8::1]) by ipv6.relay.net"
    assert RelayAnalyzer.extract_ips(text2) == ["2001:db8::1"]

    text3 = "version 8.14.4 (not an ip) and text without ip"
    assert RelayAnalyzer.extract_ips(text3) == []

    text4 = "both ips: 10.0.0.1 and 192.168.1.1 in one line"
    assert RelayAnalyzer.extract_ips(text4) == ["10.0.0.1", "192.168.1.1"]


def test_is_ip_private():
    """Test private vs public IP classification across IPv4 and IPv6."""
    # Private / Local IPv4
    assert RelayAnalyzer.is_ip_private("10.0.0.1") is True
    assert RelayAnalyzer.is_ip_private("172.16.5.10") is True
    assert RelayAnalyzer.is_ip_private("192.168.1.100") is True
    assert RelayAnalyzer.is_ip_private("127.0.0.1") is True

    # Public IPv4
    assert RelayAnalyzer.is_ip_private("8.8.8.8") is False
    assert RelayAnalyzer.is_ip_private("209.85.208.177") is False
    assert RelayAnalyzer.is_ip_private("185.220.101.5") is False

    # IPv6
    assert RelayAnalyzer.is_ip_private("::1") is True
    assert RelayAnalyzer.is_ip_private("fe80::1") is True
    assert RelayAnalyzer.is_ip_private("2001:4860:4860::8888") is False

    # Edge cases
    assert RelayAnalyzer.is_ip_private(None) is False
    assert RelayAnalyzer.is_ip_private("invalid_ip") is False


def test_parse_single_received_header():
    """Test parsing a single standard RFC 5321 Received header."""
    header = (
        "from mail-lj1-f177.google.com (mail-lj1-f177.google.com [209.85.208.177]) "
        "by mx.victimcorp.com with ESMTPS id abc.123 "
        "for <target@victimcorp.com>; Wed, 19 Sep 2026 12:00:05 +0000 (UTC)"
    )

    hop = RelayAnalyzer.parse_received_header(header, hop_index=2)

    assert hop.hop_number == 2
    assert hop.from_host == "mail-lj1-f177.google.com"
    assert hop.from_ip == "209.85.208.177"
    assert hop.by_host == "mx.victimcorp.com"
    assert hop.protocol == "ESMTPS"
    assert hop.message_id_stamp == "abc.123"
    assert hop.is_private_ip is False
    assert hop.timestamp_utc == datetime(2026, 9, 19, 12, 0, 5, tzinfo=timezone.utc)
    assert len(hop.anomalies) == 0


def test_chronological_route_reconstruction_and_latency():
    """Test reverse chronological ordering and hop transit latency calculation."""
    # Top-down order as received in email headers
    headers = [
        # Top header (Hop 3 - final recipient MTA)
        "from relay.google.com ([209.85.208.1]) by recipient.local with ESMTPS; Wed, 19 Sep 2026 12:00:10 +0000",
        # Middle header (Hop 2 - cloud relay)
        "from mail.sender.com ([198.185.159.25]) by relay.google.com with ESMTP id m1; Wed, 19 Sep 2026 12:00:04 +0000",
        # Bottom header (Hop 1 - originating client submission)
        "from client-pc ([192.168.1.50]) by mail.sender.com with ESMTPA id c1; Wed, 19 Sep 2026 12:00:00 +0000",
    ]

    route = RelayAnalyzer.reconstruct_route(headers)

    assert route.total_hops == 3
    assert route.total_transit_seconds == 10.0

    # Verify Hop 1 (Origin)
    hop1 = route.hops[0]
    assert hop1.hop_number == 1
    assert hop1.from_host == "client-pc"
    assert hop1.from_ip == "192.168.1.50"
    assert hop1.is_private_ip is True
    assert hop1.is_originating_hop is True
    assert hop1.delay_seconds == 0.0

    # Verify Hop 2
    hop2 = route.hops[1]
    assert hop2.hop_number == 2
    assert hop2.from_host == "mail.sender.com"
    assert hop2.from_ip == "198.185.159.25"
    assert hop2.delay_seconds == 4.0

    # Verify Hop 3
    hop3 = route.hops[2]
    assert hop3.hop_number == 3
    assert hop3.from_host == "relay.google.com"
    assert hop3.from_ip == "209.85.208.1"
    assert hop3.delay_seconds == 6.0

    # Verify Originating Public IP identification (198.185.159.25)
    assert route.originating_ip == "198.185.159.25"
    assert route.originating_host == "mail.sender.com"
    assert len(route.anomalies_detected) == 0


def test_negative_transit_delay_anomaly():
    """Test anomaly detection for negative transit delay (clock skew or forged header)."""
    headers = [
        # Final Hop received at 11:59:50 (earlier than previous hop)
        "from mail.forwarder.com ([203.0.113.10]) by mx.corp.com with ESMTP; Wed, 19 Sep 2026 11:59:50 +0000",
        # Initial Hop sent at 12:00:00
        "from sender ([198.185.159.1]) by mail.forwarder.com with ESMTP; Wed, 19 Sep 2026 12:00:00 +0000",
    ]

    route = RelayAnalyzer.reconstruct_route(headers)

    assert route.total_hops == 2
    assert len(route.anomalies_detected) > 0
    assert any("Negative transit delay" in a for a in route.anomalies_detected)
    assert route.hops[1].delay_seconds == -10.0


def test_missing_timestamp_delimiter():
    """Test resilient parsing when semicolon delimiter is absent."""
    header = "from evil.com by relay.com with ESMTP id 123"
    hop = RelayAnalyzer.parse_received_header(header, hop_index=1)

    assert hop.from_host == "evil.com"
    assert hop.by_host == "relay.com"
    assert hop.timestamp_utc is None
    assert any("Missing semicolon" in a for a in hop.anomalies)


def test_empty_route():
    """Test route reconstruction with empty headers list."""
    route = RelayAnalyzer.reconstruct_route([])
    assert route.total_hops == 0
    assert route.hops == []
    assert route.originating_ip is None


def test_analyze_email_integration():
    """Test full integration with CanonicalEmail model."""
    received = [
        "from relay.net ([198.185.159.99]) by dest.com with ESMTP; Wed, 19 Sep 2026 12:05:00 +0000",
        "from origin.org ([198.185.159.10]) by relay.net with ESMTP; Wed, 19 Sep 2026 12:04:30 +0000",
    ]
    email = CanonicalEmail(
        message_id="<test-route@forensics.local>",
        subject="Route Analysis Test",
        header_decomposition=HeaderDecomposition(
            received_headers=received,
        ),
    )

    route = RelayAnalyzer.analyze_email(email)

    assert route is not None
    assert email.transit_route is not None
    assert email.transit_route.total_hops == 2
    assert email.transit_route.originating_ip == "198.185.159.10"
    assert email.transit_route.total_transit_seconds == 30.0
