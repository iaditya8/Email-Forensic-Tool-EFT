"""Comprehensive test suite for TransitMapVisualizer (Task 5.2)."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from eft.models.canonical import (
    CanonicalEmail,
    IPNetworkIntelligence,
    RelayHop,
    TransitRoute,
)
from eft.ui.map_visualizer import TransitMapVisualizer


@pytest.fixture
def sample_transit_route() -> TransitRoute:
    """Construct a realistic 3-hop transit route with GeoIP data and anomalies."""
    hop1 = RelayHop(
        hop_number=1,
        raw_header="from [198.51.100.24] by mail.sender.com with ESMTP id ABC; Mon, 15 Jan 2024 10:00:00 +0000",
        from_host="client-pc.home.net",
        from_ip="198.51.100.24",
        by_host="mail.sender.com",
        by_ip="198.51.100.1",
        protocol="ESMTP",
        tls_cipher="TLS_AES_256_GCM_SHA384",
        timestamp_raw="Mon, 15 Jan 2024 10:00:00 +0000",
        timestamp_utc=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        delay_seconds=0.0,
        is_originating_hop=True,
        network_intelligence=IPNetworkIntelligence(
            ip="198.51.100.24",
            country="United States",
            country_code="US",
            city="New York",
            latitude=40.7128,
            longitude=-74.0060,
            asn=13335,
            as_org="Cloudflare Inc",
            isp="Cloudflare",
            is_cloud_provider=True,
            cloud_provider_name="Cloudflare",
        ),
    )

    hop2 = RelayHop(
        hop_number=2,
        raw_header="from mail.sender.com by relay.transit.org with ESMTPS id DEF; Mon, 15 Jan 2024 10:00:02 +0000",
        from_host="mail.sender.com",
        from_ip="203.0.113.50",
        by_host="relay.transit.org",
        by_ip="203.0.113.1",
        protocol="ESMTPS",
        tls_cipher="TLS_CHACHA20_POLY1305_SHA256",
        timestamp_raw="Mon, 15 Jan 2024 10:00:02 +0000",
        timestamp_utc=datetime(2024, 1, 15, 10, 0, 2, tzinfo=timezone.utc),
        delay_seconds=2.0,
        network_intelligence=IPNetworkIntelligence(
            ip="203.0.113.50",
            country="Germany",
            country_code="DE",
            city="Frankfurt",
            latitude=50.1109,
            longitude=8.6821,
            asn=24940,
            as_org="Hetzner Online GmbH",
            isp="Hetzner",
            is_vpn=True,
        ),
    )

    hop3 = RelayHop(
        hop_number=3,
        raw_header="from relay.transit.org by mx.recipient.com with SMTP id GHI; Mon, 15 Jan 2024 10:00:01 +0000",
        from_host="relay.transit.org",
        from_ip="192.168.1.100",
        by_host="mx.recipient.com",
        by_ip="192.168.1.1",
        protocol="SMTP",
        tls_cipher=None,  # Plaintext
        timestamp_raw="Mon, 15 Jan 2024 10:00:01 +0000",
        timestamp_utc=datetime(2024, 1, 15, 10, 0, 1, tzinfo=timezone.utc),
        delay_seconds=-1.0,  # Negative latency anomaly!
        is_private_ip=True,
        anomalies=["Hop 3: Negative transit delay (-1.0s) relative to Hop 2"],
        network_intelligence=IPNetworkIntelligence(
            ip="192.168.1.100",
            country=None,
            is_private=True,
        ),
    )

    return TransitRoute(
        total_hops=3,
        total_transit_seconds=1.0,
        originating_ip="198.51.100.24",
        originating_host="client-pc.home.net",
        hops=[hop1, hop2, hop3],
        anomalies_detected=["Hop 3: Negative transit delay (-1.0s) relative to Hop 2"],
    )


@pytest.fixture
def sample_email(sample_transit_route: TransitRoute) -> CanonicalEmail:
    """Construct a CanonicalEmail instance embedding the sample transit route."""
    return CanonicalEmail(
        transit_route=sample_transit_route,
        ordered_headers=[
            ("From", "alice@sender.com"),
            ("To", "bob@recipient.com"),
            ("Subject", "Quarterly Forensic Review"),
        ],
        body_plain="Please find the attached report.",
    )


def test_coordinate_projection():
    """Verify Equirectangular projection math and bounds clamping."""
    # Center (Equator / Prime Meridian)
    coords = TransitMapVisualizer.project_coordinates(0.0, 0.0, width=1000, height=500)
    assert coords == (500.0, 250.0)

    # Top-Left (-180 lon, 90 lat)
    coords_tl = TransitMapVisualizer.project_coordinates(90.0, -180.0, width=1000, height=500)
    assert coords_tl == (0.0, 0.0)

    # Bottom-Right (180 lon, -90 lat)
    coords_br = TransitMapVisualizer.project_coordinates(-90.0, 180.0, width=1000, height=500)
    assert coords_br == (1000.0, 500.0)

    # Clamping out-of-bounds latitude/longitude
    coords_clamped = TransitMapVisualizer.project_coordinates(120.0, -250.0, width=1000, height=500)
    assert coords_clamped == (0.0, 0.0)

    # None inputs
    assert TransitMapVisualizer.project_coordinates(None, -74.0) is None
    assert TransitMapVisualizer.project_coordinates(40.0, None) is None
    assert TransitMapVisualizer.project_coordinates(None, None) is None


def test_generate_mermaid_transit_flow_empty():
    """Verify Mermaid generation when no hops exist."""
    empty_route = TransitRoute()
    mermaid_code = TransitMapVisualizer.generate_mermaid_transit_flow(empty_route)
    assert "flowchart LR" in mermaid_code
    assert "No MTA Relay Hops Found" in mermaid_code


def test_generate_mermaid_transit_flow_populated(sample_transit_route: TransitRoute):
    """Verify Mermaid generation with origins, relays, anomalies, and edge delays."""
    mermaid_code = TransitMapVisualizer.generate_mermaid_transit_flow(sample_transit_route)
    assert "flowchart LR" in mermaid_code
    assert "classDef origin" in mermaid_code
    assert "classDef anomaly" in mermaid_code
    assert "HOP_1" in mermaid_code
    assert "HOP_2" in mermaid_code
    assert "HOP_3" in mermaid_code
    assert "class HOP_1 origin;" in mermaid_code
    assert "class HOP_3 anomaly;" in mermaid_code
    assert "+2.0s delay" in mermaid_code
    assert "Clock Drift" in mermaid_code


def test_generate_svg_map_empty():
    """Verify standalone SVG map generation on empty route."""
    empty_route = TransitRoute()
    svg = TransitMapVisualizer.generate_svg_map(empty_route)
    assert svg.startswith("<svg")
    assert svg.endswith("</svg>")
    assert "MTA Geographical Transit Trace" in svg
    assert "Total Hops: 0" in svg


def test_generate_svg_map_populated(sample_transit_route: TransitRoute):
    """Verify standalone SVG map generation with vectors, flight arcs, and node circles."""
    svg = TransitMapVisualizer.generate_svg_map(sample_transit_route, width=1200, height=600)
    assert svg.startswith("<svg")
    assert 'viewBox="0 0 1200 600"' in svg
    # Contains flight path bezier curve
    assert '<path d="M' in svg
    # Contains node circles
    assert "<circle cx=" in svg
    # Contains labels
    assert "New York, US" in svg
    assert "Frankfurt, DE" in svg
    assert "Total Hops: 3" in svg


def test_generate_transit_map_html_standalone(sample_email: CanonicalEmail, tmp_path: Path):
    """Verify standalone interactive HTML dashboard generation, air-gap safety, and file saving."""
    out_file = tmp_path / "transit_map.html"
    html_output = TransitMapVisualizer.generate_transit_map_html(
        sample_email,
        output_path=out_file,
        title="Forensic Routing Inspection",
    )

    assert out_file.is_file()
    assert out_file.read_text(encoding="utf-8") == html_output

    # Validate structure & elements
    assert "<!DOCTYPE html>" in html_output
    assert "<title>Forensic Routing Inspection</title>" in html_output
    assert "MTA Hop Reconstruction Pipeline" in html_output
    assert "Geographic Transit Path (Offline Vector Map)" in html_output
    assert "Visual Mermaid Transit Flow Definition" in html_output
    assert "198.51.100.24" in html_output
    assert "New York, United States" in html_output
    assert "Frankfurt, Germany" in html_output
    assert "Negative transit delay" in html_output
    assert "TLS_AES_256_GCM_SHA384" in html_output

    # Strict Air-Gap Verification: Ensure NO remote script or css includes exist
    assert "http://" not in html_output.replace('xmlns="http://www.w3.org/2000/svg"', "")
    assert "https://" not in html_output
    assert "<script src=" not in html_output
    assert '<link rel="stylesheet" href="http' not in html_output


def test_generate_cli_transit_view(sample_transit_route: TransitRoute):
    """Verify Rich table output for CLI inspection."""
    table = TransitMapVisualizer.generate_cli_transit_view(sample_transit_route)
    assert table is not None
    assert table.title == "[bold cyan]EFT Transit Hop & MTA Reconstruction[/bold cyan]"
    assert len(table.columns) == 7

    # Empty route CLI rendering
    empty_table = TransitMapVisualizer.generate_cli_transit_view(TransitRoute())
    assert empty_table is not None
