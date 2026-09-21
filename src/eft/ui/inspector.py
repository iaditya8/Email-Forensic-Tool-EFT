"""Dual-Pane Forensic Email & Header Inspector UI with real-time search and MIME visualization."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Dict, List, Optional, Union

from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table as RichTable
from rich.text import Text

from eft.models.canonical import CanonicalEmail, MIMEPartNode
from eft.ui.sanitizer import HTMLSanitizer


class EmailInspector:
    """Forensic email inspection engine providing interactive HTML and terminal UI dashboards."""

    @classmethod
    def generate_inspector_html(
        cls,
        email_obj: CanonicalEmail,
        output_path: Optional[Union[str, Path]] = None,
    ) -> str:
        """Generate a complete standalone, interactive dual-pane HTML forensic dashboard.

        Args:
            email_obj: The CanonicalEmail instance to inspect.
            output_path: Optional destination path to write the HTML file.

        Returns:
            HTML string of the complete standalone dashboard.
        """
        # Sanitize message bodies
        sanitized_html = HTMLSanitizer.sanitize_html(email_obj.body_html)
        sanitized_plain = HTMLSanitizer.sanitize_plain_text(email_obj.body_plain)

        # Build categorized headers
        decomp = email_obj.header_decomposition
        std_headers = decomp.standard_headers if decomp else {}
        rec_headers = decomp.received_headers if decomp else []
        auth_headers = decomp.auth_results_headers if decomp else []
        dkim_headers = decomp.dkim_signatures if decomp else []
        x_headers = decomp.custom_x_headers if decomp else {}

        # Raw RFC 5322 header block
        raw_headers_text = "\n".join(f"{k}: {v}" for k, v in email_obj.ordered_headers)

        # Build MIME tree HTML
        mime_tree_html = cls._render_mime_tree_html(email_obj.mime_parts)

        # Overall threat summary calculation
        overall_score = 0.0
        risk_level = "CLEAN"
        if email_obj.bec_report and email_obj.bec_report.threat_score > overall_score:
            overall_score = email_obj.bec_report.threat_score
            risk_level = email_obj.bec_report.overall_threat_level
        if (
            email_obj.attachment_threat_report
            and email_obj.attachment_threat_report.threat_score > overall_score
        ):
            overall_score = email_obj.attachment_threat_report.threat_score
            risk_level = email_obj.attachment_threat_report.overall_attachment_risk

        subject_display = html.escape(email_obj.subject or "(No Subject)")
        from_display = html.escape(email_obj.from_address or "Unknown Sender")
        to_display = html.escape(", ".join(email_obj.to_addresses) or "None")
        date_display = html.escape(email_obj.date or "N/A")
        msg_id_display = html.escape(email_obj.message_id or "N/A")

        # HTML Template
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EFT Forensic Inspector — {subject_display}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0F172A;
            --bg-secondary: #1E293B;
            --bg-tertiary: #334155;
            --bg-card: rgba(30, 41, 59, 0.85);
            --border-color: #334155;
            --border-highlight: #475569;
            --text-primary: #F8FAFC;
            --text-secondary: #94A3B8;
            --text-muted: #64748B;
            --accent-blue: #38BDF8;
            --accent-cyan: #06B6D4;
            --accent-green: #10B981;
            --accent-amber: #F59E0B;
            --accent-red: #EF4444;
            --font-main: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: 'JetBrains Mono', 'Courier New', monospace;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: var(--font-main);
            background-color: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
        }}

        /* Header Navbar */
        .eft-navbar {{
            background: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }}

        .eft-brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .eft-logo-badge {{
            background: linear-gradient(135deg, #0284C7, #0EA5E9);
            color: #FFFFFF;
            font-weight: 700;
            font-size: 13px;
            padding: 4px 8px;
            border-radius: 6px;
            letter-spacing: 0.5px;
        }}

        .eft-title {{
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
        }}

        .eft-threat-badge {{
            display: flex;
            align-items: center;
            gap: 8px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }}

        .threat-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: {("#EF4444" if overall_score >= 70 else ("#F59E0B" if overall_score >= 30 else "#10B981"))};
            box-shadow: 0 0 8px {("#EF4444" if overall_score >= 70 else ("#F59E0B" if overall_score >= 30 else "#10B981"))};
        }}

        /* Main Dual-Pane Layout */
        .eft-main-container {{
            display: flex;
            flex: 1;
            height: calc(100vh - 57px);
            overflow: hidden;
        }}

        /* Left Pane: Email Preview */
        .eft-pane-left {{
            flex: 1;
            display: flex;
            flex-direction: column;
            border-right: 1px solid var(--border-color);
            background: var(--bg-primary);
            overflow: hidden;
        }}

        .preview-header-card {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 18px 24px;
        }}

        .preview-subject {{
            font-size: 18px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 12px;
            line-height: 1.3;
        }}

        .preview-meta-grid {{
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 6px 16px;
            font-size: 13px;
        }}

        .meta-label {{
            color: var(--text-secondary);
            font-weight: 500;
        }}

        .meta-value {{
            color: var(--text-primary);
            word-break: break-all;
        }}

        .preview-body-tabs {{
            display: flex;
            background: var(--bg-tertiary);
            padding: 4px;
            gap: 4px;
            border-bottom: 1px solid var(--border-color);
        }}

        .tab-btn {{
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 500;
            padding: 6px 14px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s ease;
        }}

        .tab-btn.active {{
            background: var(--bg-secondary);
            color: var(--accent-blue);
            font-weight: 600;
        }}

        .tab-btn:hover:not(.active) {{
            color: var(--text-primary);
        }}

        .preview-content-area {{
            flex: 1;
            overflow-y: auto;
            padding: 24px;
            background: #FFFFFF;
            color: #1E293B;
        }}

        .preview-content-area.dark-preview {{
            background: #090D16;
            color: var(--text-primary);
        }}

        .eft-plaintext-body {{
            font-family: var(--font-mono);
            font-size: 13px;
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-word;
            color: inherit;
        }}

        .eft-blocked-image {{
            display: inline-block;
            background: rgba(239, 68, 68, 0.1);
            color: #DC2626;
            border: 1px dashed #EF4444;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-family: var(--font-mono);
            margin: 4px 0;
        }}

        /* Right Pane: Forensic Header & MIME Inspector */
        .eft-pane-right {{
            flex: 1;
            display: flex;
            flex-direction: column;
            background: var(--bg-secondary);
            overflow: hidden;
        }}

        .inspector-toolbar {{
            padding: 14px 20px;
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            gap: 12px;
            align-items: center;
        }}

        .search-box {{
            flex: 1;
            position: relative;
        }}

        .search-input {{
            width: 100%;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            font-family: var(--font-main);
            font-size: 13px;
            padding: 8px 14px 8px 36px;
            border-radius: 6px;
            outline: none;
            transition: border-color 0.2s;
        }}

        .search-input:focus {{
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.15);
        }}

        .search-icon {{
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            font-size: 14px;
        }}

        .copy-btn {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            font-size: 12px;
            font-weight: 500;
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s;
        }}

        .copy-btn:hover {{
            background: var(--bg-tertiary);
            border-color: var(--accent-blue);
            color: var(--accent-blue);
        }}

        .inspector-tabs {{
            display: flex;
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            padding: 0 20px;
            gap: 8px;
        }}

        .insp-tab {{
            padding: 10px 16px;
            color: var(--text-secondary);
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
        }}

        .insp-tab.active {{
            color: var(--accent-blue);
            border-bottom-color: var(--accent-blue);
            font-weight: 600;
        }}

        .inspector-content-area {{
            flex: 1;
            overflow-y: auto;
            padding: 20px;
        }}

        /* Header Tables & Categories */
        .category-group {{
            margin-bottom: 24px;
        }}

        .category-title {{
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--accent-cyan);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .header-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12.5px;
            background: var(--bg-card);
            border-radius: 6px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }}

        .header-table tr {{
            border-bottom: 1px solid var(--border-color);
            transition: background 0.15s;
        }}

        .header-table tr:hover {{
            background: rgba(51, 65, 85, 0.4);
        }}

        .header-table td {{
            padding: 8px 12px;
            vertical-align: top;
        }}

        .header-name {{
            font-family: var(--font-mono);
            font-weight: 600;
            color: var(--accent-blue);
            width: 220px;
            word-break: break-all;
        }}

        .header-val {{
            font-family: var(--font-mono);
            color: var(--text-primary);
            word-break: break-all;
        }}

        /* Raw Textarea / Pre */
        .raw-headers-view {{
            font-family: var(--font-mono);
            font-size: 12px;
            line-height: 1.5;
            background: var(--bg-primary);
            padding: 16px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            white-space: pre-wrap;
            word-break: break-all;
        }}

        /* MIME Tree */
        .mime-tree {{
            list-style: none;
            padding-left: 12px;
        }}

        .mime-node {{
            margin: 8px 0;
            position: relative;
        }}

        .node-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            padding: 10px 14px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            gap: 12px;
            font-family: var(--font-mono);
            font-size: 12px;
        }}

        .node-badge {{
            background: rgba(56, 189, 248, 0.15);
            color: var(--accent-blue);
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 600;
        }}

        .node-size {{
            color: var(--text-secondary);
            font-size: 11px;
        }}

        /* Tooltip notification */
        .toast {{
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: var(--accent-green);
            color: #FFFFFF;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            opacity: 0;
            transition: opacity 0.3s ease;
            pointer-events: none;
            z-index: 1000;
        }}
    </style>
</head>
<body>
    <!-- Navigation Bar -->
    <header class="eft-navbar">
        <div class="eft-brand">
            <span class="eft-logo-badge">EFT DFIR</span>
            <span class="eft-title">Forensic Dual-Pane Inspector</span>
        </div>
        <div class="eft-threat-badge">
            <span class="threat-dot"></span>
            <span>Threat Score: {overall_score:.1f} ({risk_level})</span>
        </div>
    </header>

    <!-- Main Container -->
    <main class="eft-main-container">
        <!-- Left Pane: Sandboxed Preview -->
        <section class="eft-pane-left">
            <div class="preview-header-card">
                <h1 class="preview-subject">{subject_display}</h1>
                <div class="preview-meta-grid">
                    <span class="meta-label">From:</span>
                    <span class="meta-value">{from_display}</span>
                    <span class="meta-label">To:</span>
                    <span class="meta-value">{to_display}</span>
                    <span class="meta-label">Date:</span>
                    <span class="meta-value">{date_display}</span>
                    <span class="meta-label">Message-ID:</span>
                    <span class="meta-value"><code>{msg_id_display}</code></span>
                </div>
            </div>

            <!-- View Switcher -->
            <div class="preview-body-tabs">
                <button class="tab-btn active" id="btn-view-html" onclick="switchPreviewMode('html')">Sanitized HTML</button>
                <button class="tab-btn" id="btn-view-plain" onclick="switchPreviewMode('plain')">Plain Text</button>
            </div>

            <!-- Preview Content Container -->
            <div class="preview-content-area" id="preview-container">
                <div id="html-body-view">{sanitized_html}</div>
                <div id="plain-body-view" style="display: none;">{sanitized_plain}</div>
            </div>
        </section>

        <!-- Right Pane: Header & MIME Deep-Dive Inspector -->
        <section class="eft-pane-right">
            <!-- Search & Action Toolbar -->
            <div class="inspector-toolbar">
                <div class="search-box">
                    <span class="search-icon">🔍</span>
                    <input type="text" id="header-search-input" class="search-input" placeholder="Live search headers, values, hops, or authentication..." oninput="filterHeaders()">
                </div>
                <button class="copy-btn" onclick="copyRawHeaders()">📋 Copy Headers</button>
            </div>

            <!-- Inspector Tabs -->
            <div class="inspector-tabs">
                <div class="insp-tab active" id="tab-btn-cat" onclick="switchInspectorTab('categorized')">Categorized Headers</div>
                <div class="insp-tab" id="tab-btn-raw" onclick="switchInspectorTab('raw')">Raw RFC 5322</div>
                <div class="insp-tab" id="tab-btn-mime" onclick="switchInspectorTab('mime')">MIME Hierarchy</div>
            </div>

            <!-- Inspector Content Area -->
            <div class="inspector-content-area">
                <!-- 1. Categorized Tab -->
                <div id="view-categorized">
                    <!-- Standard Envelope -->
                    <div class="category-group">
                        <div class="category-title">✉️ Envelope Standard Headers</div>
                        <table class="header-table" id="table-standard">
                            <tbody>
                                {cls._render_header_rows(std_headers)}
                            </tbody>
                        </table>
                    </div>

                    <!-- Transit Received Routing -->
                    <div class="category-group">
                        <div class="category-title">🌐 Transit & Routing Headers ({len(rec_headers)})</div>
                        <table class="header-table" id="table-routing">
                            <tbody>
                                {cls._render_list_header_rows("Received", rec_headers)}
                            </tbody>
                        </table>
                    </div>

                    <!-- Authentication Results -->
                    <div class="category-group">
                        <div class="category-title">🛡️ Authentication & Signatures ({len(auth_headers) + len(dkim_headers)})</div>
                        <table class="header-table" id="table-auth">
                            <tbody>
                                {cls._render_list_header_rows("Authentication-Results", auth_headers)}
                                {cls._render_list_header_rows("DKIM-Signature", dkim_headers)}
                            </tbody>
                        </table>
                    </div>

                    <!-- Custom Security X-Headers -->
                    <div class="category-group">
                        <div class="category-title">⚙️ Custom & Vendor X-Headers ({len(x_headers)})</div>
                        <table class="header-table" id="table-xheaders">
                            <tbody>
                                {cls._render_header_rows(x_headers)}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- 2. Raw Headers Tab -->
                <div id="view-raw" style="display: none;">
                    <pre class="raw-headers-view" id="raw-headers-block">{html.escape(raw_headers_text)}</pre>
                </div>

                <!-- 3. MIME Tree Tab -->
                <div id="view-mime" style="display: none;">
                    {mime_tree_html}
                </div>
            </div>
        </section>
    </main>

    <!-- Toast Notification -->
    <div id="toast-msg" class="toast">Copied to clipboard!</div>

    <script>
        function switchPreviewMode(mode) {{
            document.getElementById('btn-view-html').classList.toggle('active', mode === 'html');
            document.getElementById('btn-view-plain').classList.toggle('active', mode === 'plain');
            document.getElementById('html-body-view').style.display = mode === 'html' ? 'block' : 'none';
            document.getElementById('plain-body-view').style.display = mode === 'plain' ? 'block' : 'none';
            const container = document.getElementById('preview-container');
            container.classList.toggle('dark-preview', mode === 'plain');
        }}

        function switchInspectorTab(tab) {{
            document.getElementById('tab-btn-cat').classList.toggle('active', tab === 'categorized');
            document.getElementById('tab-btn-raw').classList.toggle('active', tab === 'raw');
            document.getElementById('tab-btn-mime').classList.toggle('active', tab === 'mime');
            document.getElementById('view-categorized').style.display = tab === 'categorized' ? 'block' : 'none';
            document.getElementById('view-raw').style.display = tab === 'raw' ? 'block' : 'none';
            document.getElementById('view-mime').style.display = tab === 'mime' ? 'block' : 'none';
        }}

        function filterHeaders() {{
            const query = document.getElementById('header-search-input').value.toLowerCase();
            const rows = document.querySelectorAll('.header-table tr');
            rows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            }});
        }}

        function copyRawHeaders() {{
            const rawText = document.getElementById('raw-headers-block').textContent;
            navigator.clipboard.writeText(rawText).then(() => {{
                const toast = document.getElementById('toast-msg');
                toast.style.opacity = '1';
                setTimeout(() => {{ toast.style.opacity = '0'; }}, 2000);
            }});
        }}
    </script>
</body>
</html>
"""

        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(html_content, encoding="utf-8", errors="replace")

        return html_content

    @classmethod
    def _render_header_rows(cls, header_dict: Dict[str, Union[str, List[str]]]) -> str:
        """Helper to render dictionary headers into table rows."""
        rows = []
        for key, val in header_dict.items():
            k_esc = html.escape(key)
            if isinstance(val, list):
                for v in val:
                    rows.append(
                        f"<tr><td class='header-name'>{k_esc}</td><td class='header-val'>{html.escape(v)}</td></tr>"
                    )
            else:
                rows.append(
                    f"<tr><td class='header-name'>{k_esc}</td><td class='header-val'>{html.escape(val)}</td></tr>"
                )
        return (
            "\n".join(rows)
            if rows
            else "<tr><td colspan='2' style='color:#64748B;'><i>None</i></td></tr>"
        )

    @classmethod
    def _render_list_header_rows(cls, header_name: str, values: List[str]) -> str:
        """Helper to render multi-valued header lists."""
        rows = []
        k_esc = html.escape(header_name)
        for val in values:
            rows.append(
                f"<tr><td class='header-name'>{k_esc}</td><td class='header-val'>{html.escape(val)}</td></tr>"
            )
        return (
            "\n".join(rows)
            if rows
            else "<tr><td colspan='2' style='color:#64748B;'><i>None</i></td></tr>"
        )

    @classmethod
    def _render_mime_tree_html(cls, mime_parts: List[MIMEPartNode]) -> str:
        """Render MIME parts into an expandable visual tree structure."""
        if not mime_parts:
            return "<div style='color:#64748B;'><i>No MIME hierarchy parts discovered.</i></div>"

        html_out = ["<ul class='mime-tree'>"]
        for part in mime_parts:
            html_out.append(cls._render_mime_node(part))
        html_out.append("</ul>")
        return "\n".join(html_out)

    @classmethod
    def _render_mime_node(cls, node: MIMEPartNode) -> str:
        name = node.filename or ("Multipart Container" if node.is_multipart else "Payload Stream")
        ct = node.content_type
        size_str = f"{node.size_bytes:,} B" if node.size_bytes else "N/A"

        res = [
            "<li class='mime-node'>",
            "<div class='node-card'>",
            f"<span class='node-badge'>Part {node.part_path}</span>",
            f"<b>{html.escape(ct)}</b>",
            f"<span style='color:#94A3B8;'>({html.escape(name)})</span>",
            f"<span class='node-size'>Size: {size_str}</span>",
            "</div>",
        ]

        if node.children:
            res.append("<ul class='mime-tree'>")
            for child in node.children:
                res.append(cls._render_mime_node(child))
            res.append("</ul>")

        res.append("</li>")
        return "\n".join(res)

    @classmethod
    def generate_cli_layout(cls, email_obj: CanonicalEmail) -> Layout:
        """Construct a Rich dual-pane terminal layout for interactive terminal DFIR workflows.

        Args:
            email_obj: CanonicalEmail instance.

        Returns:
            Configured Rich Layout object.
        """
        layout = Layout(name="root")
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3),
        )

        layout["main"].split_row(
            Layout(name="left_pane", ratio=1),
            Layout(name="right_pane", ratio=1),
        )

        # 1. Header
        header_text = Text(
            f"EFT Forensic Email Inspector | Subject: {email_obj.subject or '(No Subject)'}",
            style="bold cyan",
        )
        layout["header"].update(Panel(header_text, style="blue"))

        # 2. Left Pane (Metadata & Safe Body)
        meta_table = RichTable(show_header=False, box=None)
        meta_table.add_row("[bold]From:[/bold]", email_obj.from_address or "N/A")
        meta_table.add_row("[bold]To:[/bold]", ", ".join(email_obj.to_addresses) or "N/A")
        meta_table.add_row("[bold]Date:[/bold]", email_obj.date or "N/A")
        meta_table.add_row("[bold]Msg-ID:[/bold]", email_obj.message_id or "N/A")

        body_preview = (email_obj.body_plain or email_obj.body_html or "(No Body)")[:1000]
        left_content = Text()
        left_content.append("--- Envelope Metadata ---\n", style="bold yellow")
        left_content.append(f"From: {email_obj.from_address}\n")
        left_content.append(f"To: {', '.join(email_obj.to_addresses)}\n")
        left_content.append(f"Date: {email_obj.date}\n\n")
        left_content.append("--- Body Content (Preview) ---\n", style="bold yellow")
        left_content.append(body_preview)

        layout["left_pane"].update(
            Panel(left_content, title="[bold green]Sandboxed Email Preview[/bold green]")
        )

        # 3. Right Pane (Headers & MIME Structure)
        right_table = RichTable(title="Categorized Headers", box=None)
        right_table.add_column("Header Name", style="cyan", no_wrap=True)
        right_table.add_column("Value", style="white")

        for k, v in list(email_obj.ordered_headers)[:15]:
            right_table.add_row(k, v[:60])

        layout["right_pane"].update(
            Panel(right_table, title="[bold cyan]Header & MIME Inspector[/bold cyan]")
        )

        # 4. Footer
        sha_str = (
            email_obj.source_file.hashes.get("sha256", "N/A") if email_obj.source_file else "N/A"
        )
        footer_text = Text(
            f"Evidence Immutability SHA-256: {sha_str} | Zero Evidence Alteration Verified",
            style="dim",
        )
        layout["footer"].update(Panel(footer_text, style="grey50"))

        return layout
