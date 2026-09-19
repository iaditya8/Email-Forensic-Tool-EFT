"""Threat Score and Composite Risk Indicator Card UI & Visualization Engine."""

from __future__ import annotations

import html
import math
from pathlib import Path
from typing import Any, Optional, Union

from rich.panel import Panel
from rich.table import Table as RichTable

from eft.analysis.threat_scorer import ThreatScorer
from eft.models.canonical import CanonicalEmail
from eft.models.threat import (
    CompositeRiskReport,
    RiskSeverity,
)


class ThreatCardRenderer:
    """Forensic threat risk card renderer producing standalone HTML, SVG gauges, and Mermaid charts."""

    @classmethod
    def _extract_report(
        cls, email_or_report: Union[CanonicalEmail, CompositeRiskReport]
    ) -> CompositeRiskReport:
        """Extract or compute CompositeRiskReport from CanonicalEmail or existing report."""
        if isinstance(email_or_report, CanonicalEmail):
            return ThreatScorer.calculate_composite_risk(email_or_report)
        return email_or_report

    @classmethod
    def generate_svg_gauge(
        cls,
        score: float,
        risk_level: Union[str, RiskSeverity] = RiskSeverity.CLEAN,
        width: int = 320,
        height: int = 220,
    ) -> str:
        """Generate a standalone SVG semicircular speedometer threat gauge.

        Args:
            score: Overall threat score (0.0 to 100.0).
            risk_level: Risk severity tier name or enum.
            width: Width of SVG in pixels.
            height: Height of SVG in pixels.

        Returns:
            SVG XML markup string.
        """
        clamped_score = max(0.0, min(100.0, float(score)))
        level_str = risk_level.value if isinstance(risk_level, RiskSeverity) else risk_level

        # Needle angle in degrees: 0 score = -90 deg (left), 100 score = +90 deg (right)
        angle_deg = -90.0 + (clamped_score / 100.0) * 180.0
        angle_rad = math.radians(angle_deg)

        # Center coordinates
        cx = width / 2.0
        cy = height - 45.0
        radius = min(cx - 30.0, cy - 25.0)

        # Needle endpoint
        needle_len = radius * 0.85
        nx = cx + needle_len * math.cos(angle_rad)
        ny = cy + needle_len * math.sin(angle_rad)

        # Theme color based on risk level
        if "CRITICAL" in level_str:
            theme_color = "#ef4444"
        elif "MALICIOUS" in level_str:
            theme_color = "#f97316"
        elif "MEDIUM" in level_str:
            theme_color = "#f59e0b"
        elif "LOW" in level_str:
            theme_color = "#38bdf8"
        else:
            theme_color = "#10b981"

        svg_lines = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'width="{width}" height="{height}" style="background: transparent; font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">',
            "  <defs>",
            '    <filter id="gauge-glow" x="-20%" y="-20%" width="140%" height="140%">',
            '      <feGaussianBlur stdDeviation="4" result="blur" />',
            '      <feComposite in="SourceGraphic" in2="blur" operator="over" />',
            "    </filter>",
            "  </defs>",
            "",
            "  <!-- Background Gauge Arc -->",
            f'  <path d="M {cx - radius:.1f} {cy:.1f} A {radius:.1f} {radius:.1f} 0 0 1 {cx + radius:.1f} {cy:.1f}" '
            f'fill="none" stroke="#1e293b" stroke-width="20" stroke-linecap="round" />',
            "",
            "  <!-- Colored Severity Zones -->",
            "  <!-- Clean (0-20) -->",
            f'  <path d="M {cx - radius:.1f} {cy:.1f} A {radius:.1f} {radius:.1f} 0 0 1 {cx - radius * 0.809:.1f} {cy - radius * 0.5878:.1f}" '
            f'fill="none" stroke="#10b981" stroke-width="20" stroke-linecap="round" opacity="0.85" />',
            "  <!-- Low Suspicious (20-40) -->",
            f'  <path d="M {cx - radius * 0.809:.1f} {cy - radius * 0.5878:.1f} A {radius:.1f} {radius:.1f} 0 0 1 {cx - radius * 0.309:.1f} {cy - radius * 0.951:.1f}" '
            f'fill="none" stroke="#38bdf8" stroke-width="20" opacity="0.85" />',
            "  <!-- Medium Suspicious (40-70) -->",
            f'  <path d="M {cx - radius * 0.309:.1f} {cy - radius * 0.951:.1f} A {radius:.1f} {radius:.1f} 0 0 1 {cx + radius * 0.5878:.1f} {cy - radius * 0.809:.1f}" '
            f'fill="none" stroke="#f59e0b" stroke-width="20" opacity="0.85" />',
            "  <!-- Malicious High (70-90) -->",
            f'  <path d="M {cx + radius * 0.5878:.1f} {cy - radius * 0.809:.1f} A {radius:.1f} {radius:.1f} 0 0 1 {cx + radius * 0.951:.1f} {cy - radius * 0.309:.1f}" '
            f'fill="none" stroke="#f97316" stroke-width="20" opacity="0.85" />',
            "  <!-- Critical (90-100) -->",
            f'  <path d="M {cx + radius * 0.951:.1f} {cy - radius * 0.309:.1f} A {radius:.1f} {radius:.1f} 0 0 1 {cx + radius:.1f} {cy:.1f}" '
            f'fill="none" stroke="#ef4444" stroke-width="20" stroke-linecap="round" opacity="0.85" />',
            "",
            "  <!-- Needle Indicator -->",
            f'  <line x1="{cx:.1f}" y1="{cy:.1f}" x2="{nx:.1f}" y2="{ny:.1f}" '
            f'stroke="{theme_color}" stroke-width="3.5" stroke-linecap="round" filter="url(#gauge-glow)" />',
            f'  <circle cx="{cx:.1f}" cy="{cy:.1f}" r="8" fill="#0f172a" stroke="{theme_color}" stroke-width="3" />',
            "",
            "  <!-- Score Readout Text -->",
            f'  <text x="{cx:.1f}" y="{cy - 20:.1f}" fill="#f8fafc" font-size="28" font-weight="800" text-anchor="middle">{clamped_score:.1f}</text>',
            f'  <text x="{cx:.1f}" y="{cy + 22:.1f}" fill="{theme_color}" font-size="12" font-weight="700" letter-spacing="1" text-anchor="middle">{html.escape(level_str)}</text>',
            f'  <text x="{cx:.1f}" y="{cy + 36:.1f}" fill="#94a3b8" font-size="9" text-anchor="middle">OUT OF 100</text>',
            "</svg>",
        ]
        return "\n".join(svg_lines)

    @classmethod
    def generate_mermaid_risk_tree(cls, report: CompositeRiskReport) -> str:
        """Generate a compliant Mermaid flowchart visualizing risk factor decomposition.

        Strictly follows repository guidelines: **Mermaid only, NO ASCII art**.

        Args:
            report: CompositeRiskReport instance.

        Returns:
            Mermaid diagram definition string.
        """
        lines = [
            "flowchart TD",
            "    %% Node Style Classes",
            "    classDef root fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#ffffff;",
            "    classDef vector fill:#1e293b,stroke:#64748b,stroke-width:1.5px,color:#ffffff;",
            "    classDef clean fill:#065f46,stroke:#10b981,stroke-width:1.5px,color:#ffffff;",
            "    classDef low fill:#1e3a8a,stroke:#3b82f6,stroke-width:1.5px,color:#ffffff;",
            "    classDef medium fill:#78350f,stroke:#f59e0b,stroke-width:1.5px,color:#ffffff;",
            "    classDef high fill:#7c2d12,stroke:#f97316,stroke-width:1.5px,color:#ffffff;",
            "    classDef critical fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#ffffff;",
            "",
        ]

        # Root Node
        root_label = f"<b>Composite Threat Score: {report.overall_score:.1f} / 100</b><br/>Level: {report.risk_level.value}"
        lines.append(f'    ROOT["{root_label}"]:::root')
        lines.append("")

        # Vector Nodes & Factors
        idx = 1
        for vec_name, vec_score in report.vector_breakdown.items():
            vec_id = f"VEC_{idx}"
            v_label = (
                f"<b>{vec_name}</b><br/>Score: {vec_score.score:.1f} / {vec_score.max_score:.1f}"
            )
            lines.append(f'    {vec_id}["{v_label}"]:::vector')
            lines.append(f"    ROOT --> {vec_id}")

            # Child Factors
            if vec_score.factors:
                for f_idx, factor in enumerate(vec_score.factors):
                    f_id = f"F_{idx}_{f_idx + 1}"
                    f_sev = factor.severity.upper()
                    f_class = (
                        "critical"
                        if "CRITICAL" in f_sev
                        else (
                            "high"
                            if "HIGH" in f_sev
                            else (
                                "medium"
                                if "MEDIUM" in f_sev
                                else ("low" if "LOW" in f_sev else "clean")
                            )
                        )
                    )

                    clean_name = factor.name.replace('"', "")
                    f_label = f"{clean_name}<br/>(+{factor.score_contribution:.1f} pts)"
                    lines.append(f'    {f_id}["{f_label}"]:::{f_class}')
                    lines.append(f"    {vec_id} --> {f_id}")
            else:
                f_id = f"F_{idx}_clean"
                lines.append(f'    {f_id}["✓ Clean / No Threats Detected"]:::clean')
                lines.append(f"    {vec_id} --> {f_id}")

            lines.append("")
            idx += 1

        return "\n".join(lines)

    @classmethod
    def generate_card_html(
        cls,
        email_or_report: Union[CanonicalEmail, CompositeRiskReport],
        output_path: Optional[Union[str, Path]] = None,
        title: str = "EFT Composite Threat Risk Assessment",
    ) -> str:
        """Generate a standalone, 100% air-gapped HTML risk card and widget.

        Args:
            email_or_report: CanonicalEmail or CompositeRiskReport instance.
            output_path: Optional destination path to write the HTML file.
            title: Title string.

        Returns:
            Complete HTML string.
        """
        report = cls._extract_report(email_or_report)
        svg_gauge = cls.generate_svg_gauge(
            report.overall_score, report.risk_level, width=320, height=220
        )
        mermaid_code = cls.generate_mermaid_risk_tree(report)

        # Vector breakdown HTML
        vector_bars_html = []
        for vec_name, vec_score in report.vector_breakdown.items():
            pct = (
                (vec_score.score / vec_score.max_score) * 100.0 if vec_score.max_score > 0 else 0.0
            )
            pct_clamped = max(0.0, min(100.0, pct))

            # Bar color
            if pct >= 75.0:
                bar_color = "linear-gradient(90deg, #f97316, #ef4444)"
            elif pct >= 40.0:
                bar_color = "linear-gradient(90deg, #f59e0b, #f97316)"
            elif pct > 0:
                bar_color = "linear-gradient(90deg, #38bdf8, #818cf8)"
            else:
                bar_color = "#334155"

            vector_bars_html.append(f"""
            <div class="vector-row">
              <div class="vector-meta">
                <span class="vector-name">{html.escape(vec_name)}</span>
                <span class="vector-score">{vec_score.score:.1f} / {vec_score.max_score:.1f} pts</span>
              </div>
              <div class="progress-track">
                <div class="progress-fill" style="width: {pct_clamped:.1f}%; background: {bar_color};"></div>
              </div>
            </div>
            """)

        vector_bars_combined = "\n".join(vector_bars_html)

        # Factor accordion cards HTML
        factor_cards_html = []
        if report.all_factors:
            for i, f in enumerate(report.all_factors):
                sev = f.severity.upper()
                badge_class = (
                    "badge-red"
                    if "CRITICAL" in sev
                    else (
                        "badge-orange"
                        if "HIGH" in sev
                        else ("badge-amber" if "MEDIUM" in sev else "badge-blue")
                    )
                )

                factor_cards_html.append(f"""
                <div class="factor-item">
                  <div class="factor-top">
                    <div style="display: flex; align-items: center; gap: 8px;">
                      <span class="badge {badge_class}">{html.escape(sev)}</span>
                      <h4 class="factor-name">{html.escape(f.name)}</h4>
                    </div>
                    <span class="factor-pts">+{f.score_contribution:.1f} pts</span>
                  </div>
                  <p class="factor-desc">{html.escape(f.description)}</p>
                  {f'<div class="factor-ref"><b>Evidence:</b> <code>{html.escape(f.evidence_reference)}</code></div>' if f.evidence_reference else ""}
                </div>
                """)
        else:
            factor_cards_html.append(
                '<div class="factor-clean-banner">🛡️ No forensic threat factors or security anomalies detected.</div>'
            )

        factor_cards_combined = "\n".join(factor_cards_html)

        # Recommendation Banner Style
        action_class = "action-clean"
        if report.risk_level == RiskSeverity.CRITICAL:
            action_class = "action-critical"
        elif report.risk_level == RiskSeverity.MALICIOUS_HIGH:
            action_class = "action-high"
        elif report.risk_level == RiskSeverity.SUSPICIOUS_MEDIUM:
            action_class = "action-medium"
        elif report.risk_level == RiskSeverity.SUSPICIOUS_LOW:
            action_class = "action-low"

        # Export JSON payload
        report_json = report.model_dump_json(indent=2)

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
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --border-color: #334155;
      --accent-blue: #38bdf8;
      --accent-green: #10b981;
      --accent-red: #ef4444;
      --accent-orange: #f97316;
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
      max-width: 1200px;
      margin: 0 auto;
    }}

    header.card-header {{
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

    .action-banner {{
      padding: 16px 20px;
      border-radius: 8px;
      margin-bottom: 24px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}

    .action-critical {{ background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); color: #fca5a5; }}
    .action-high {{ background: rgba(249, 115, 22, 0.15); border: 1px solid rgba(249, 115, 22, 0.4); color: #fdba74; }}
    .action-medium {{ background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.4); color: #fde68a; }}
    .action-low {{ background: rgba(56, 189, 248, 0.15); border: 1px solid rgba(56, 189, 248, 0.4); color: #bae6fd; }}
    .action-clean {{ background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.4); color: #a7f3d0; }}

    .action-title {{
      font-size: 1rem;
      font-weight: 700;
      letter-spacing: 0.02em;
    }}

    .action-summary {{
      font-size: 0.875rem;
      opacity: 0.9;
    }}

    .top-overview-grid {{
      display: grid;
      grid-template-columns: 340px 1fr;
      gap: 24px;
      margin-bottom: 24px;
    }}

    @media (max-width: 860px) {{
      .top-overview-grid {{
        grid-template-columns: 1fr;
      }}
    }}

    .card-panel {{
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }}

    .panel-header {{
      padding: 14px 20px;
      background-color: rgba(17, 24, 39, 0.8);
      border-bottom: 1px solid var(--border-color);
      font-weight: 600;
      font-size: 0.9375rem;
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    .gauge-wrapper {{
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 20px;
      flex: 1;
    }}

    .vector-bars-wrap {{
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
      justify-content: center;
      flex: 1;
    }}

    .vector-row {{
      display: flex;
      flex-direction: column;
      gap: 6px;
    }}

    .vector-meta {{
      display: flex;
      justify-content: space-between;
      font-size: 0.8125rem;
    }}

    .vector-name {{
      font-weight: 600;
      color: var(--text-main);
    }}

    .vector-score {{
      color: var(--text-muted);
      font-family: var(--font-mono);
    }}

    .progress-track {{
      width: 100%;
      height: 8px;
      background-color: #1e293b;
      border-radius: 4px;
      overflow: hidden;
    }}

    .progress-fill {{
      height: 100%;
      border-radius: 4px;
      transition: width 0.3s ease;
    }}

    .factors-list {{
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }}

    .factor-item {{
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 14px 16px;
    }}

    .factor-top {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }}

    .factor-name {{
      font-size: 0.9375rem;
      font-weight: 600;
      color: var(--text-main);
    }}

    .factor-pts {{
      font-family: var(--font-mono);
      font-size: 0.8125rem;
      font-weight: 700;
      color: var(--accent-orange);
    }}

    .factor-desc {{
      font-size: 0.8125rem;
      color: var(--text-muted);
      margin-bottom: 6px;
    }}

    .factor-ref {{
      font-size: 0.75rem;
      color: #94a3b8;
    }}

    .factor-ref code {{
      background: #0b0f19;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: var(--font-mono);
      color: #38bdf8;
    }}

    .factor-clean-banner {{
      padding: 20px;
      text-align: center;
      color: var(--accent-green);
      font-weight: 600;
    }}

    .badge {{
      font-size: 0.6875rem;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}

    .badge-red {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .badge-orange {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
    .badge-amber {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
    .badge-blue {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }}

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
    }}

    .btn:hover {{
      background-color: #475569;
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
  </style>
</head>
<body>

<div class="container">
  <header class="card-header">
    <div class="header-title">
      <h1>🎯 {html.escape(title)}</h1>
      <p>Overarching 0–100 Forensic Risk Scoring & Factor Attribution</p>
    </div>
    <div style="display: flex; gap: 8px;">
      <button class="btn" onclick="copyMermaid()">📋 Copy Mermaid Graph</button>
      <button class="btn" onclick="copyRiskJson()">📦 Copy JSON Report</button>
    </div>
  </header>

  <!-- Recommendation Action Banner -->
  <div class="action-banner {action_class}">
    <div class="action-title">RECOMMENDED ACTION: {html.escape(report.recommended_action)}</div>
    <div class="action-summary">{html.escape(report.summary)}</div>
  </div>

  <!-- Top Overview: Dial Gauge & Vector Breakdown -->
  <div class="top-overview-grid">
    <div class="card-panel">
      <div class="panel-header">⏱️ Composite Risk Dial</div>
      <div class="gauge-wrapper">
        {svg_gauge}
      </div>
    </div>

    <div class="card-panel">
      <div class="panel-header">📊 Vector Contribution Breakdown</div>
      <div class="vector-bars-wrap">
        {vector_bars_combined}
      </div>
    </div>
  </div>

  <!-- Triggered Threat Factors -->
  <div class="card-panel" style="margin-bottom: 24px;">
    <div class="panel-header">🔍 Identified Forensic Threat Indicators ({len(report.all_factors)} factors)</div>
    <div class="factors-list">
      {factor_cards_combined}
    </div>
  </div>

  <!-- Mermaid Risk Decomposition Tree -->
  <div class="card-panel">
    <div class="panel-header">🌲 Mermaid Risk Factor Decomposition Flowchart</div>
    <div style="padding: 16px;">
      <div class="code-box" id="mermaidCodeBlock">{html.escape(mermaid_code)}</div>
    </div>
  </div>
</div>

<script>
  const RISK_DATA = {report_json};

  function copyMermaid() {{
    const code = document.getElementById('mermaidCodeBlock').innerText;
    navigator.clipboard.writeText(code).then(() => {{
      alert('Mermaid risk diagram copied to clipboard!');
    }}).catch(err => {{
      console.error('Failed to copy: ', err);
    }});
  }}

  function copyRiskJson() {{
    navigator.clipboard.writeText(JSON.stringify(RISK_DATA, null, 2)).then(() => {{
      alert('Risk report JSON copied to clipboard!');
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
    def generate_cli_card(
        cls,
        email_or_report: Union[CanonicalEmail, CompositeRiskReport],
    ) -> Any:
        """Generate a Rich visual terminal panel for triage analysts.

        Args:
            email_or_report: CanonicalEmail or CompositeRiskReport instance.

        Returns:
            Rich Panel containing composite score, vector table, and recommendations.
        """
        report = cls._extract_report(email_or_report)

        table = RichTable(
            title=f"[bold]EFT Threat Risk Score: {report.overall_score:.1f} / 100 ({report.risk_level.value})[/bold]",
            border_style="blue",
            header_style="bold cyan",
        )

        table.add_column("Threat Vector", style="white", min_width=25)
        table.add_column("Score", justify="right", style="yellow", width=12)
        table.add_column("Max", justify="right", style="dim", width=8)
        table.add_column("Triggered Factors", style="red", min_width=30)

        for vec_name, vec_score in report.vector_breakdown.items():
            factor_summary = (
                ", ".join(f.name for f in vec_score.factors)
                if vec_score.factors
                else "[green]Clean[/green]"
            )
            score_style = (
                "[red]"
                if vec_score.score >= (vec_score.max_score * 0.6)
                else "[yellow]"
                if vec_score.score > 0
                else "[green]"
            )
            table.add_row(
                vec_name,
                f"{score_style}{vec_score.score:.1f}[/]",
                f"{vec_score.max_score:.1f}",
                factor_summary,
            )

        content = (
            f"[bold magenta]RECOMMENDED ACTION:[/bold magenta] {report.recommended_action}\n"
            f"[dim]{report.summary}[/dim]\n"
        )

        return Panel(
            table,
            title="[bold red]Forensic Threat Risk Indicator[/bold red]",
            subtitle=content,
            border_style="red"
            if report.risk_level in (RiskSeverity.CRITICAL, RiskSeverity.MALICIOUS_HIGH)
            else "green",
        )
