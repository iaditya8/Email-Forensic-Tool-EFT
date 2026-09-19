"""Interactive MTA Relay Hop and Geographic Transit Map Visualizer for Email Forensics."""

from __future__ import annotations

import html
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from rich.table import Table as RichTable

from eft.models.canonical import CanonicalEmail, RelayHop, TransitRoute

# Embedded Simplified Landmass Vector Polygons for Air-Gapped SVG World Map (WGS84 Equirectangular)
# Landmass contours approximate major continents for offline rendering without external tile servers.
WORLD_MAP_LANDMASS_PATHS = [
    # North America
    "M 160 70 L 190 60 L 230 55 L 280 60 L 320 80 L 340 110 L 310 130 L 290 170 L 260 190 L 240 220 L 220 250 L 200 240 L 180 200 L 150 170 L 130 140 L 140 100 Z",
    # Greenland
    "M 330 35 L 370 30 L 390 55 L 360 75 L 330 65 Z",
    # South America
    "M 270 260 L 320 280 L 350 320 L 340 380 L 310 440 L 280 470 L 270 430 L 260 360 L 250 300 Z",
    # Europe
    "M 470 90 L 520 80 L 560 95 L 550 140 L 510 160 L 480 150 L 460 120 Z",
    # Great Britain & Ireland
    "M 450 105 L 465 100 L 460 125 L 445 120 Z",
    # Africa
    "M 470 170 L 530 170 L 580 220 L 560 300 L 530 370 L 490 360 L 460 270 L 450 200 Z",
    # Asia & Siberia
    "M 560 85 L 680 70 L 800 65 L 890 80 L 880 140 L 810 160 L 780 220 L 720 250 L 660 220 L 610 190 L 570 150 Z",
    # Indian Subcontinent & SE Asia
    "M 670 190 L 710 210 L 720 270 L 680 280 L 660 230 Z M 750 220 L 800 250 L 780 310 L 740 290 Z",
    # Japan
    "M 860 140 L 880 160 L 870 190 L 850 170 Z",
    # Australia & New Zealand
    "M 780 340 L 850 330 L 880 380 L 850 430 L 790 410 L 760 360 Z M 900 420 L 920 440 L 900 460 Z",
    # Antarctica
    "M 100 485 L 900 485 L 880 495 L 120 495 Z",
]


class TransitMapVisualizer:
    """Forensic visualizer for reconstructing and plotting email MTA relay paths."""

    MAP_WIDTH: int = 1000
    MAP_HEIGHT: int = 500

    @classmethod
    def project_coordinates(
        cls,
        lat: Optional[float],
        lon: Optional[float],
        width: int = 1000,
        height: int = 500,
    ) -> Optional[Tuple[float, float]]:
        """Project WGS84 Latitude and Longitude to SVG coordinate space using Equirectangular projection.

        Args:
            lat: Latitude between -90.0 and 90.0
            lon: Longitude between -180.0 and 180.0
            width: Target SVG width in pixels
            height: Target SVG height in pixels

        Returns:
            Tuple of (x, y) coordinates or None if inputs are invalid/missing.
        """
        if lat is None or lon is None:
            return None

        # Clamp latitude and longitude to valid ranges
        clamped_lat = max(-90.0, min(90.0, float(lat)))
        clamped_lon = max(-180.0, min(180.0, float(lon)))

        # Equirectangular transformation
        x = (clamped_lon + 180.0) * (width / 360.0)
        y = (90.0 - clamped_lat) * (height / 180.0)

        return round(x, 2), round(y, 2)

    @classmethod
    def _extract_route(cls, email_or_route: Union[CanonicalEmail, TransitRoute]) -> TransitRoute:
        """Extract or normalize a TransitRoute instance."""
        if isinstance(email_or_route, CanonicalEmail):
            if email_or_route.transit_route:
                return email_or_route.transit_route
            return TransitRoute()
        return email_or_route

    @classmethod
    def generate_mermaid_transit_flow(
        cls,
        email_or_route: Union[CanonicalEmail, TransitRoute],
    ) -> str:
        """Generate a compliant Mermaid flowchart visualizing the MTA transit sequence.

        Follows repository standards: Strictly Mermaid diagram (never ASCII art).

        Args:
            email_or_route: CanonicalEmail or TransitRoute instance.

        Returns:
            Mermaid diagram definition string.
        """
        route = cls._extract_route(email_or_route)
        if not route.hops:
            return 'flowchart LR\n    EMPTY["No MTA Relay Hops Found"]'

        lines = [
            "flowchart LR",
            "    %% Node Style Classes",
            "    classDef origin fill:#1e3a8a,stroke:#3b82f6,stroke-width:2px,color:#ffffff;",
            "    classDef relay fill:#1e293b,stroke:#64748b,stroke-width:1.5px,color:#ffffff;",
            "    classDef destination fill:#065f46,stroke:#10b981,stroke-width:2px,color:#ffffff;",
            "    classDef anomaly fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#ffffff;",
            "",
        ]

        total_hops = len(route.hops)
        for i, hop in enumerate(route.hops):
            node_id = f"HOP_{hop.hop_number}"
            is_origin = (i == 0) or hop.is_originating_hop
            is_dest = i == (total_hops - 1)
            has_anomaly = bool(hop.anomalies)

            # Node title
            if is_origin:
                role = "Hop 1: Origin Sender"
            elif is_dest:
                role = f"Hop {hop.hop_number}: Final Recipient MTA"
            else:
                role = f"Hop {hop.hop_number}: Relay MTA"

            # Label elements
            label_parts = [f"<b>{role}</b>"]
            if hop.from_ip:
                label_parts.append(f"IP: {hop.from_ip}")
            if hop.from_host:
                clean_host = hop.from_host.replace('"', "")
                label_parts.append(f"Host: {clean_host[:30]}")

            # Geo details
            if hop.network_intelligence and hop.network_intelligence.country:
                country_str = hop.network_intelligence.country
                if hop.network_intelligence.city:
                    country_str = f"{hop.network_intelligence.city}, {country_str}"
                label_parts.append(f"📍 {country_str}")

            # Security / TLS
            if hop.tls_cipher:
                label_parts.append("🔒 TLS Secured")
            elif hop.protocol:
                label_parts.append(f"Protocol: {hop.protocol}")

            # Anomalies
            if has_anomaly:
                label_parts.append("⚠️ ANOMALY DETECTED")

            node_label = "<br/>".join(label_parts)
            lines.append(f'    {node_id}["{node_label}"]')

            # Apply style class
            if has_anomaly:
                lines.append(f"    class {node_id} anomaly;")
            elif is_origin:
                lines.append(f"    class {node_id} origin;")
            elif is_dest:
                lines.append(f"    class {node_id} destination;")
            else:
                lines.append(f"    class {node_id} relay;")

        # Render edges with delays
        lines.append("")
        for i in range(len(route.hops) - 1):
            curr_hop = route.hops[i]
            next_hop = route.hops[i + 1]
            src_id = f"HOP_{curr_hop.hop_number}"
            dst_id = f"HOP_{next_hop.hop_number}"

            delay_str = ""
            if next_hop.delay_seconds > 0:
                if next_hop.delay_seconds < 60:
                    delay_str = f"+{next_hop.delay_seconds:.1f}s delay"
                elif next_hop.delay_seconds < 3600:
                    delay_str = f"+{next_hop.delay_seconds / 60:.1f}m delay"
                else:
                    delay_str = f"+{next_hop.delay_seconds / 3600:.1f}h delay"
            elif next_hop.delay_seconds < 0:
                delay_str = f"⚠️ {next_hop.delay_seconds:.1f}s (Clock Drift)"

            if delay_str:
                lines.append(f'    {src_id} -->|"{delay_str}"| {dst_id}')
            else:
                lines.append(f"    {src_id} --> {dst_id}")

        return "\n".join(lines)

    @classmethod
    def generate_svg_map(
        cls,
        email_or_route: Union[CanonicalEmail, TransitRoute],
        width: int = 1000,
        height: int = 500,
    ) -> str:
        """Generate a standalone SVG image rendering the world map and plotted hop path.

        Args:
            email_or_route: CanonicalEmail or TransitRoute instance.
            width: Output SVG width in pixels.
            height: Output SVG height in pixels.

        Returns:
            Clean standalone SVG XML string.
        """
        route = cls._extract_route(email_or_route)
        scale_x = width / cls.MAP_WIDTH
        scale_y = height / cls.MAP_HEIGHT

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'width="{width}" height="{height}" style="background: #0b0f19; font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">',
            "  <defs>",
            "    <!-- Background Gradients -->",
            '    <linearGradient id="grid-grad" x1="0%" y1="0%" x2="100%" y2="100%">',
            '      <stop offset="0%" stop-color="#111827" stop-opacity="0.8" />',
            '      <stop offset="100%" stop-color="#0b0f19" stop-opacity="0.9" />',
            "    </linearGradient>",
            "    <!-- Flight Path Glow Filter -->",
            '    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">',
            '      <feGaussianBlur stdDeviation="3" result="blur" />',
            '      <feComposite in="SourceGraphic" in2="blur" operator="over" />',
            "    </filter>",
            "    <!-- Arrow Marker -->",
            '    <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
            '      <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />',
            "    </marker>",
            '    <marker id="arrow-anomaly" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
            '      <path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444" />',
            "    </marker>",
            "  </defs>",
            "",
            "  <!-- Map Background -->",
            f'  <rect width="{width}" height="{height}" fill="url(#grid-grad)" />',
            "",
            "  <!-- Lat/Lon Coordinate Grid Lines -->",
            '  <g stroke="#1f2937" stroke-width="0.75" stroke-dasharray="3,3" opacity="0.6">',
        ]

        # Draw Grid Lines
        for lat_line in [30, 60, -30, -60]:
            y_pos = (90.0 - lat_line) * (height / 180.0)
            svg_parts.append(f'    <line x1="0" y1="{y_pos:.1f}" x2="{width}" y2="{y_pos:.1f}" />')
        # Equator
        y_eq = height / 2.0
        svg_parts.append(
            f'    <line x1="0" y1="{y_eq:.1f}" x2="{width}" y2="{y_eq:.1f}" stroke="#374151" stroke-width="1.2" stroke-dasharray="none" />'
        )

        for lon_line in [-120, -60, 60, 120]:
            x_pos = (lon_line + 180.0) * (width / 360.0)
            svg_parts.append(f'    <line x1="{x_pos:.1f}" y1="0" x2="{x_pos:.1f}" y2="{height}" />')
        # Prime Meridian
        x_pm = width / 2.0
        svg_parts.append(
            f'    <line x1="{x_pm:.1f}" y1="0" x2="{x_pm:.1f}" y2="{height}" stroke="#374151" stroke-width="1.2" stroke-dasharray="none" />'
        )
        svg_parts.append("  </g>")

        # Draw World Landmass Vector Paths
        svg_parts.append("\n  <!-- Vector Landmass Continents -->")
        svg_parts.append(
            f'  <g transform="scale({scale_x:.4f}, {scale_y:.4f})" fill="#1e293b" stroke="#334155" stroke-width="0.8" opacity="0.75">'
        )
        for path_d in WORLD_MAP_LANDMASS_PATHS:
            svg_parts.append(f'    <path d="{path_d}" />')
        svg_parts.append("  </g>")

        # Collect Projected Hops with Coordinates
        projected_hops: List[Tuple[RelayHop, Tuple[float, float]]] = []
        for hop in route.hops:
            lat = hop.network_intelligence.latitude if hop.network_intelligence else None
            lon = hop.network_intelligence.longitude if hop.network_intelligence else None
            coords = cls.project_coordinates(lat, lon, width, height)
            if coords:
                projected_hops.append((hop, coords))

        # Render Transit Path Arcs between Consecutive Geo Hops
        svg_parts.append("\n  <!-- Transit Routing Flight Arcs -->")
        svg_parts.append("  <g>")
        for i in range(len(projected_hops) - 1):
            h1, (x1, y1) = projected_hops[i]
            h2, (x2, y2) = projected_hops[i + 1]

            # Calculate curved quadratic control point
            dx = x2 - x1
            dy = y2 - y1
            dist = math.hypot(dx, dy)

            # Arc elevation proportional to distance
            arc_height = min(80.0, max(25.0, dist * 0.25))
            ctrl_x = (x1 + x2) / 2.0
            ctrl_y = ((y1 + y2) / 2.0) - arc_height

            is_anomalous = bool(h2.anomalies)
            stroke_color = "#ef4444" if is_anomalous else "#38bdf8"
            marker_id = "arrow-anomaly" if is_anomalous else "arrow"

            # Path with glow
            svg_parts.append(
                f'    <path d="M {x1:.1f} {y1:.1f} Q {ctrl_x:.1f} {ctrl_y:.1f} {x2:.1f} {y2:.1f}" '
                f'fill="none" stroke="{stroke_color}" stroke-width="2.5" stroke-dasharray="6,4" '
                f'filter="url(#glow)" marker-end="url(#{marker_id})" opacity="0.9" />'
            )

            # Delay badge along path center
            if h2.delay_seconds > 0:
                delay_label = (
                    f"+{h2.delay_seconds:.1f}s"
                    if h2.delay_seconds < 60
                    else f"+{h2.delay_seconds / 60:.1f}m"
                )
                svg_parts.append(
                    f'    <rect x="{ctrl_x - 22:.1f}" y="{ctrl_y - 10:.1f}" width="44" height="16" rx="4" fill="#0f172a" stroke="{stroke_color}" stroke-width="1" />'
                )
                svg_parts.append(
                    f'    <text x="{ctrl_x:.1f}" y="{ctrl_y + 2:.1f}" fill="#f8fafc" font-size="9" font-weight="600" text-anchor="middle">{delay_label}</text>'
                )

        svg_parts.append("  </g>")

        # Render Hop Node Markers (Pins)
        svg_parts.append("\n  <!-- Plotted Hop Location Nodes -->")
        svg_parts.append("  <g>")
        for i, (hop, (px, py)) in enumerate(projected_hops):
            is_origin = (i == 0) or hop.is_originating_hop
            is_dest = i == (len(projected_hops) - 1)
            is_anomalous = bool(hop.anomalies)

            if is_anomalous:
                pin_fill = "#ef4444"
                pin_stroke = "#b91c1c"
            elif is_origin:
                pin_fill = "#3b82f6"
                pin_stroke = "#60a5fa"
            elif is_dest:
                pin_fill = "#10b981"
                pin_stroke = "#34d399"
            else:
                pin_fill = "#a855f7"
                pin_stroke = "#c084fc"

            # Outer pulse ring
            svg_parts.append(
                f'    <circle cx="{px:.1f}" cy="{py:.1f}" r="12" fill="{pin_fill}" opacity="0.25" />'
            )
            # Main Node Circle
            svg_parts.append(
                f'    <circle cx="{px:.1f}" cy="{py:.1f}" r="8" fill="{pin_fill}" stroke="{pin_stroke}" stroke-width="2" />'
            )
            # Node Number Label
            svg_parts.append(
                f'    <text x="{px:.1f}" y="{py + 3.5:.1f}" fill="#ffffff" font-size="10" font-weight="bold" text-anchor="middle">{hop.hop_number}</text>'
            )

            # Country / City tooltip label
            loc_label = ""
            if hop.network_intelligence:
                if hop.network_intelligence.city and hop.network_intelligence.country_code:
                    loc_label = (
                        f"{hop.network_intelligence.city}, {hop.network_intelligence.country_code}"
                    )
                elif hop.network_intelligence.country:
                    loc_label = hop.network_intelligence.country

            if loc_label:
                svg_parts.append(
                    f'    <text x="{px:.1f}" y="{py - 14:.1f}" fill="#cbd5e1" font-size="9.5" font-weight="500" text-anchor="middle">{loc_label}</text>'
                )

        svg_parts.append("  </g>")

        # Header Title and Watermark inside SVG
        svg_parts.append(
            '  <text x="20" y="30" fill="#f8fafc" font-size="14" font-weight="bold">MTA Geographical Transit Trace</text>'
        )
        svg_parts.append(
            f'  <text x="20" y="46" fill="#94a3b8" font-size="10">Total Hops: {len(route.hops)} | Geo-Plotted: {len(projected_hops)} | Anomalies: {len(route.anomalies_detected)}</text>'
        )

        svg_parts.append("</svg>")
        return "\n".join(svg_parts)

    @classmethod
    def generate_transit_map_html(
        cls,
        email_or_route: Union[CanonicalEmail, TransitRoute],
        output_path: Optional[Union[str, Path]] = None,
        title: str = "EFT Transit & Geographic Hop Route Analysis",
    ) -> str:
        """Generate a complete standalone, interactive, 100% air-gapped HTML transit dashboard.

        Args:
            email_or_route: CanonicalEmail or TransitRoute instance.
            output_path: Optional destination path to write the HTML file.
            title: Dashboard title string.

        Returns:
            Complete HTML document string.
        """
        route = cls._extract_route(email_or_route)
        svg_map = cls.generate_svg_map(route, width=1000, height=500)
        mermaid_code = cls.generate_mermaid_transit_flow(route)

        # Statistics
        total_hops = len(route.hops)
        total_delay = route.total_transit_seconds
        total_anomalies = len(route.anomalies_detected) + sum(len(h.anomalies) for h in route.hops)
        tls_hops = sum(1 for h in route.hops if h.tls_cipher)
        tls_percentage = round((tls_hops / total_hops) * 100) if total_hops > 0 else 0

        # Prepare JSON payload for client-side interactivity
        hops_json_list: List[Dict[str, Any]] = []
        for h in route.hops:
            geo_info = None
            if h.network_intelligence:
                geo_info = {
                    "country": h.network_intelligence.country or "Unknown",
                    "country_code": h.network_intelligence.country_code or "",
                    "city": h.network_intelligence.city or "Unknown",
                    "lat": h.network_intelligence.latitude,
                    "lon": h.network_intelligence.longitude,
                    "asn": h.network_intelligence.asn,
                    "as_org": h.network_intelligence.as_org or "Unknown",
                    "isp": h.network_intelligence.isp or "Unknown",
                    "is_cloud": h.network_intelligence.is_cloud_provider,
                    "cloud_provider": h.network_intelligence.cloud_provider_name,
                    "is_tor": h.network_intelligence.is_tor_exit_node,
                    "is_vpn": h.network_intelligence.is_vpn,
                    "threat_tags": h.network_intelligence.threat_tags,
                }

            hops_json_list.append(
                {
                    "hop_number": h.hop_number,
                    "from_host": h.from_host or "Unknown",
                    "from_ip": h.from_ip or "Unknown",
                    "by_host": h.by_host or "Unknown",
                    "by_ip": h.by_ip or "Unknown",
                    "protocol": h.protocol or "SMTP",
                    "tls_cipher": h.tls_cipher,
                    "delay_seconds": h.delay_seconds,
                    "timestamp_raw": h.timestamp_raw or "",
                    "timestamp_utc": (h.timestamp_utc.isoformat() if h.timestamp_utc else "N/A"),
                    "is_private_ip": h.is_private_ip,
                    "is_origin": h.is_originating_hop,
                    "anomalies": h.anomalies,
                    "network_intelligence": geo_info,
                }
            )

        json_data_str = json.dumps(hops_json_list, indent=2)

        # Build Interactive Hop Nodes HTML
        hop_cards_html = []
        for i, hop in enumerate(route.hops):
            is_origin = (i == 0) or hop.is_originating_hop
            is_dest = i == (total_hops - 1)
            has_anomaly = bool(hop.anomalies)

            card_class = "hop-card"
            if has_anomaly:
                card_class += " hop-anomaly"
            elif is_origin:
                card_class += " hop-origin"
            elif is_dest:
                card_class += " hop-dest"

            # Badge tags
            badges = []
            if is_origin:
                badges.append('<span class="badge badge-blue">Origin Hop</span>')
            elif is_dest:
                badges.append('<span class="badge badge-green">Final Destination</span>')

            if hop.tls_cipher:
                badges.append(
                    f'<span class="badge badge-emerald" title="{html.escape(hop.tls_cipher)}">🔒 TLS Secured</span>'
                )
            else:
                badges.append('<span class="badge badge-amber">⚠️ Plaintext SMTP</span>')

            if hop.is_private_ip:
                badges.append('<span class="badge badge-purple">Private RFC 1918</span>')

            if hop.network_intelligence and hop.network_intelligence.is_tor_exit_node:
                badges.append('<span class="badge badge-rose">🚨 Tor Exit Node</span>')
            if hop.network_intelligence and hop.network_intelligence.is_vpn:
                badges.append('<span class="badge badge-orange">🛡️ VPN Service</span>')
            if hop.network_intelligence and hop.network_intelligence.is_cloud_provider:
                cloud_name = hop.network_intelligence.cloud_provider_name or "Cloud"
                badges.append(
                    f'<span class="badge badge-indigo">☁️ {html.escape(cloud_name)}</span>'
                )

            # Location label
            geo_text = "No GeoIP (Private/Local)"
            if hop.network_intelligence and hop.network_intelligence.latitude is not None:
                geo_text = f"📍 {hop.network_intelligence.city or 'Unknown'}, {hop.network_intelligence.country or 'Unknown'} ({hop.network_intelligence.latitude:.2f}, {hop.network_intelligence.longitude:.2f})"

            # Delay formatted
            delay_text = "0.0s (Origin)"
            if hop.delay_seconds > 0:
                delay_text = (
                    f"+{hop.delay_seconds:.2f}s"
                    if hop.delay_seconds < 60
                    else f"+{hop.delay_seconds / 60:.2f} min"
                )
            elif hop.delay_seconds < 0:
                delay_text = f"⚠️ {hop.delay_seconds:.2f}s (Clock Drift/Time Travel)"

            # Anomalies list
            anomalies_html = ""
            if hop.anomalies:
                anomalies_html = '<div class="anomaly-alert"><b>⚠️ Forensic Anomalies:</b><ul>'
                for anom in hop.anomalies:
                    anomalies_html += f"<li>{html.escape(anom)}</li>"
                anomalies_html += "</ul></div>"

            hop_cards_html.append(f"""
            <div class="{card_class}" id="hop-card-{hop.hop_number}" data-hop="{hop.hop_number}">
              <div class="hop-header">
                <div class="hop-title-wrap">
                  <span class="hop-num">#{hop.hop_number}</span>
                  <h4 class="hop-host">{html.escape(hop.from_host or "Unknown Host")}</h4>
                </div>
                <div class="hop-delay-pill">{delay_text}</div>
              </div>

              <div class="hop-badges">
                {" ".join(badges)}
              </div>

              <div class="hop-grid">
                <div class="hop-field">
                  <span class="field-label">From IP:</span>
                  <span class="field-val code-font">{html.escape(hop.from_ip or "N/A")}</span>
                </div>
                <div class="hop-field">
                  <span class="field-label">By Host:</span>
                  <span class="field-val">{html.escape(hop.by_host or "N/A")}</span>
                </div>
                <div class="hop-field">
                  <span class="field-label">Location:</span>
                  <span class="field-val">{html.escape(geo_text)}</span>
                </div>
                <div class="hop-field">
                  <span class="field-label">Timestamp:</span>
                  <span class="field-val code-font">{html.escape(hop.timestamp_raw or "N/A")}</span>
                </div>
              </div>

              {anomalies_html}
            </div>
            """)

        cards_combined_html = "\n".join(hop_cards_html)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      --bg-base: #090d16;
      --bg-surface: #111827;
      --bg-card: #1e293b;
      --bg-card-hover: #263347;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --border-color: #334155;
      --accent-blue: #38bdf8;
      --accent-green: #10b981;
      --accent-red: #ef4444;
      --accent-purple: #a855f7;
      --accent-amber: #f59e0b;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      padding: 24px;
    }}

    .container {{
      max-width: 1400px;
      margin: 0 auto;
    }}

    header.dashboard-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border-color);
    }}

    .header-title h1 {{
      font-size: 1.5rem;
      font-weight: 700;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .header-title p {{
      color: var(--text-muted);
      font-size: 0.875rem;
      margin-top: 4px;
    }}

    .stats-bar {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}

    .stat-card {{
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
    }}

    .stat-label {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }}

    .stat-value {{
      font-size: 1.5rem;
      font-weight: 700;
      margin-top: 4px;
      color: var(--accent-blue);
    }}

    .stat-value.red {{ color: var(--accent-red); }}
    .stat-value.green {{ color: var(--accent-green); }}

    .main-grid {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 24px;
    }}

    .card-panel {{
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      overflow: hidden;
    }}

    .panel-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 20px;
      background-color: rgba(17, 24, 39, 0.8);
      border-bottom: 1px solid var(--border-color);
    }}

    .panel-title {{
      font-size: 1rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    .map-container {{
      width: 100%;
      background-color: #0b0f19;
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 12px;
      overflow-x: auto;
    }}

    .map-container svg {{
      max-width: 100%;
      height: auto;
      border-radius: 6px;
    }}

    .hop-cards-container {{
      display: flex;
      flex-direction: column;
      gap: 14px;
      padding: 20px;
    }}

    .hop-card {{
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      transition: all 0.2s ease;
    }}

    .hop-card:hover {{
      background-color: var(--bg-card-hover);
      border-color: var(--accent-blue);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }}

    .hop-card.hop-origin {{
      border-left: 4px solid var(--accent-blue);
    }}

    .hop-card.hop-dest {{
      border-left: 4px solid var(--accent-green);
    }}

    .hop-card.hop-anomaly {{
      border-left: 4px solid var(--accent-red);
      background-color: rgba(239, 68, 68, 0.05);
    }}

    .hop-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }}

    .hop-title-wrap {{
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .hop-num {{
      background-color: #334155;
      color: #ffffff;
      font-size: 0.75rem;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
    }}

    .hop-host {{
      font-size: 1rem;
      font-weight: 600;
      color: var(--text-main);
    }}

    .hop-delay-pill {{
      background-color: rgba(56, 189, 248, 0.15);
      color: var(--accent-blue);
      border: 1px solid rgba(56, 189, 248, 0.3);
      font-size: 0.75rem;
      font-weight: 600;
      padding: 2px 10px;
      border-radius: 12px;
      font-family: var(--font-mono);
    }}

    .hop-badges {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 12px;
    }}

    .badge {{
      font-size: 0.7rem;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 4px;
    }}

    .badge-blue {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }}
    .badge-green {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }}
    .badge-emerald {{ background: rgba(5, 150, 105, 0.2); color: #10b981; border: 1px solid rgba(5, 150, 105, 0.4); }}
    .badge-amber {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
    .badge-purple {{ background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }}
    .badge-rose {{ background: rgba(244, 63, 94, 0.2); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.4); }}
    .badge-orange {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
    .badge-indigo {{ background: rgba(99, 102, 241, 0.2); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.4); }}

    .hop-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
      font-size: 0.8125rem;
    }}

    .hop-field {{
      display: flex;
      flex-direction: column;
      gap: 2px;
    }}

    .field-label {{
      color: var(--text-muted);
      font-size: 0.7rem;
      text-transform: uppercase;
    }}

    .field-val {{
      color: var(--text-main);
      word-break: break-all;
    }}

    .code-font {{
      font-family: var(--font-mono);
    }}

    .anomaly-alert {{
      margin-top: 12px;
      padding: 10px 14px;
      background-color: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 6px;
      color: #fca5a5;
      font-size: 0.8125rem;
    }}

    .anomaly-alert ul {{
      margin-left: 18px;
      margin-top: 4px;
    }}

    .btn {{
      background-color: #334155;
      color: #ffffff;
      border: none;
      padding: 6px 12px;
      border-radius: 4px;
      font-size: 0.8125rem;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: background-color 0.15s;
    }}

    .btn:hover {{
      background-color: #475569;
    }}

    .btn-primary {{
      background-color: #2563eb;
    }}
    .btn-primary:hover {{
      background-color: #1d4ed8;
    }}

    .code-box {{
      background-color: #0b0f19;
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 14px;
      font-family: var(--font-mono);
      font-size: 0.8125rem;
      color: #cbd5e1;
      overflow-x: auto;
      white-space: pre;
    }}

    .filter-bar {{
      display: flex;
      gap: 10px;
      padding: 12px 20px;
      background-color: rgba(15, 23, 42, 0.6);
      border-bottom: 1px solid var(--border-color);
    }}

    .filter-input {{
      background-color: var(--bg-base);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      padding: 6px 12px;
      color: var(--text-main);
      font-size: 0.8125rem;
      flex: 1;
    }}
  </style>
</head>
<body>

<div class="container">
  <header class="dashboard-header">
    <div class="header-title">
      <h1>🌐 {html.escape(title)}</h1>
      <p>MTA Relay Reconstruction, Forensic Routing Graph & Geographic Trace</p>
    </div>
    <div style="display: flex; gap: 8px;">
      <button class="btn" onclick="copyMermaid()">📋 Copy Mermaid Diagram</button>
      <button class="btn" onclick="copyHopsJson()">📦 Copy JSON Payload</button>
    </div>
  </header>

  <div class="stats-bar">
    <div class="stat-card">
      <div class="stat-label">Total Relay Hops</div>
      <div class="stat-value">{total_hops}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Cumulative Latency</div>
      <div class="stat-value">{total_delay:.2f}s</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">TLS Security Rate</div>
      <div class="stat-value {"green" if tls_percentage >= 80 else "red"}">{tls_percentage}%</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Detected Anomalies</div>
      <div class="stat-value {"red" if total_anomalies > 0 else "green"}">{total_anomalies}</div>
    </div>
  </div>

  <div class="main-grid">
    <!-- Map Visualization Panel -->
    <div class="card-panel">
      <div class="panel-header">
        <span class="panel-title">🗺️ Geographic Transit Path (Offline Vector Map)</span>
        <span style="font-size: 0.75rem; color: var(--text-muted);">Air-Gapped WGS84 Equirectangular Projection</span>
      </div>
      <div class="map-container">
        {svg_map}
      </div>
    </div>

    <!-- Hop Sequence List -->
    <div class="card-panel">
      <div class="panel-header">
        <span class="panel-title">⛓️ MTA Hop Reconstruction Pipeline</span>
        <span style="font-size: 0.75rem; color: var(--text-muted);">{total_hops} Verified Chronological Hops</span>
      </div>
      <div class="filter-bar">
        <input type="text" id="hopSearchInput" class="filter-input" placeholder="Filter hops by Hostname, IP, City, Country, or Anomaly..." onkeyup="filterHops()" />
      </div>
      <div class="hop-cards-container" id="hopCardsList">
        {cards_combined_html}
      </div>
    </div>

    <!-- Mermaid Diagram Code Block -->
    <div class="card-panel">
      <div class="panel-header">
        <span class="panel-title">📊 Visual Mermaid Transit Flow Definition</span>
      </div>
      <div style="padding: 16px;">
        <div class="code-box" id="mermaidCodeBlock">{html.escape(mermaid_code)}</div>
      </div>
    </div>
  </div>
</div>

<script>
  const HOPS_DATA = {json_data_str};

  function filterHops() {{
    const query = document.getElementById('hopSearchInput').value.toLowerCase();
    const cards = document.querySelectorAll('.hop-card');
    cards.forEach(card => {{
      const text = card.innerText.toLowerCase();
      if (text.includes(query)) {{
        card.style.display = 'block';
      }} else {{
        card.style.display = 'none';
      }}
    }});
  }}

  function copyMermaid() {{
    const code = document.getElementById('mermaidCodeBlock').innerText;
    navigator.clipboard.writeText(code).then(() => {{
      alert('Mermaid diagram code copied to clipboard!');
    }}).catch(err => {{
      console.error('Failed to copy: ', err);
    }});
  }}

  function copyHopsJson() {{
    navigator.clipboard.writeText(JSON.stringify(HOPS_DATA, null, 2)).then(() => {{
      alert('Hops JSON payload copied to clipboard!');
    }}).catch(err => {{
      console.error('Failed to copy: ', err);
    }});
  }}
</script>

</body>
</html>
"""

        if output_path:
            out_file = Path(output_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(html_template, encoding="utf-8")

        return html_template

    @classmethod
    def generate_cli_transit_view(
        cls,
        email_or_route: Union[CanonicalEmail, TransitRoute],
    ) -> Any:
        """Generate a Rich layout / Table visualizer for terminal investigation.

        Args:
            email_or_route: CanonicalEmail or TransitRoute instance.

        Returns:
            Rich Table displaying the chronological transit route.
        """
        route = cls._extract_route(email_or_route)

        table = RichTable(
            title="[bold cyan]EFT Transit Hop & MTA Reconstruction[/bold cyan]",
            border_style="blue",
            header_style="bold magenta",
        )

        table.add_column("Hop", justify="center", style="cyan", width=5)
        table.add_column("From Host / IP", style="white", min_width=24)
        table.add_column("By Host", style="white", min_width=20)
        table.add_column("Geo Location", style="green", min_width=20)
        table.add_column("Delay", justify="right", style="yellow", width=12)
        table.add_column("Security", justify="center", width=12)
        table.add_column("Anomalies", style="red", min_width=20)

        if not route.hops:
            table.add_row("-", "No Relay Hops Available", "-", "-", "-", "-", "-")
            return table

        for i, hop in enumerate(route.hops):
            is_origin = (i == 0) or hop.is_originating_hop
            hop_num_str = f"#{hop.hop_number}"
            if is_origin:
                hop_num_str += " [bold blue](Origin)[/bold blue]"

            host_ip = f"{hop.from_host or 'Unknown'}\n[dim]{hop.from_ip or ''}[/dim]"

            geo_str = "-"
            if hop.network_intelligence:
                if hop.network_intelligence.city and hop.network_intelligence.country:
                    geo_str = f"{hop.network_intelligence.city}, {hop.network_intelligence.country}"
                elif hop.network_intelligence.country:
                    geo_str = hop.network_intelligence.country

            delay_str = f"+{hop.delay_seconds:.1f}s" if hop.delay_seconds > 0 else "0.0s"
            if hop.delay_seconds < 0:
                delay_str = f"[bold red]{hop.delay_seconds:.1f}s[/bold red]"

            sec_str = "[green]🔒 TLS[/green]" if hop.tls_cipher else "[yellow]Plaintext[/yellow]"
            anom_str = "\n".join(hop.anomalies) if hop.anomalies else "[dim]None[/dim]"

            table.add_row(
                hop_num_str,
                host_ip,
                hop.by_host or "-",
                geo_str,
                delay_str,
                sec_str,
                anom_str,
            )

        return table
