"""Unified Command-Line Interface (CLI) Suite for Email Forensic Tool (EFT).

Provides structured sub-application command routing for all forensic domains:
- eft email <scan|report|inspect|map>
- eft file <inspect|entropy|exif>
- eft osint <lookup|domain|ip>
- eft pcap <analyze|dns|creds>
- eft log <evtx|sysmon|m365|google>
- eft mem <scan|strings|iocs|yara>
- eft serve [--host 127.0.0.1] [--port 8000]
"""

from __future__ import annotations

import json
import logging
import re
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from eft import __version__
from eft.analysis.attachment_scanner import AttachmentThreatScanner
from eft.analysis.auth_verifier import AuthenticationVerifier
from eft.analysis.bec_detector import BECDetector
from eft.analysis.binary_static_analyzer import BinaryStaticAnalyzer
from eft.analysis.cloud_audit_analyzer import CloudAuditAnalyzer
from eft.analysis.credential_leak_analyzer import CredentialLeakAnalyzer
from eft.analysis.dns_threat_analyzer import DNSThreatAnalyzer
from eft.analysis.domain_osint import DomainOSINTAnalyzer
from eft.analysis.evtx_analyzer import WindowsLogAnalyzer
from eft.analysis.file_analyzer import FileArtifactAnalyzer
from eft.analysis.logon_persistence_analyzer import WindowsSecurityAnalyzer
from eft.analysis.memory_analyzer import MemoryArtifactAnalyzer
from eft.analysis.memory_ioc_matcher import MemoryIoCMatcher
from eft.analysis.memory_yara_scanner import MemoryYARAScanner
from eft.analysis.metadata_extractor import MetadataExtractor
from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.analysis.obfuscation_detector import ContentObfuscationDetector
from eft.analysis.pcap_analyzer import NetworkPCAPAnalyzer
from eft.analysis.relay_analyzer import RelayAnalyzer
from eft.analysis.threat_scorer import ThreatScorer
from eft.analysis.url_analyzer import URLAnalyzer
from eft.core.integrity import compute_file_hashes
from eft.ingestion.attachment_extractor import AttachmentExtractor
from eft.ingestion.engine import EmailIngester
from eft.ingestion.header_decomposer import HeaderDecomposer
from eft.models.canonical import CanonicalEmail
from eft.models.osint import DomainOSINTReport
from eft.models.threat import CompositeRiskReport, RiskSeverity
from eft.reporting.custody import ChainOfCustodyManager
from eft.reporting.exporter import ForensicReportExporter
from eft.reporting.timeline import TimelineGenerator
from eft.ui.inspector import EmailInspector
from eft.ui.map_visualizer import TransitMapVisualizer

# Root Typer App
app = typer.Typer(
    name="eft",
    help="Email Forensic Tool (EFT) — Master Enterprise DFIR Forensics Workstation",
    no_args_is_help=True,
    add_completion=False,
)

# Sub-Typer Applications
email_app = typer.Typer(
    name="email",
    help="Email forensics: parsing, headers, transit maps, threat scoring, and reports",
    no_args_is_help=True,
)
file_app = typer.Typer(
    name="file",
    help="File & binary forensics: magic bytes, Shannon entropy, PE/OLE analysis, EXIF metadata",
    no_args_is_help=True,
)
osint_app = typer.Typer(
    name="osint",
    help="OSINT intelligence: domain authentication posture, lookalikes, IP Geolocation & ASN",
    no_args_is_help=True,
)
pcap_app = typer.Typer(
    name="pcap",
    help="Network forensics: PCAP streams, DNS tunneling detection, cleartext credential leakage",
    no_args_is_help=True,
)
log_app = typer.Typer(
    name="log",
    help="Event log forensics: Windows EVTX, Sysmon correlation, M365 & Google Workspace audit logs",
    no_args_is_help=True,
)
mem_app = typer.Typer(
    name="mem",
    help="Memory forensics: RAM dump ingestion, high-speed string extraction, regex IoCs, YARA scans",
    no_args_is_help=True,
)

# Mount Sub-Apps onto Root CLI
app.add_typer(email_app, name="email")
app.add_typer(file_app, name="file")
app.add_typer(osint_app, name="osint")
app.add_typer(pcap_app, name="pcap")
app.add_typer(log_app, name="log")
app.add_typer(mem_app, name="mem")

console = Console()
err_console = Console(stderr=True)


def version_callback(value: bool) -> None:
    """Print the version of the tool and exit."""
    if value:
        console.print(
            f"[bold cyan]Email Forensic Tool (EFT)[/bold cyan] version [bold green]{__version__}[/bold green]"
        )
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Display EFT version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-V",
        help="Enable detailed diagnostic and debug logging.",
    ),
) -> None:
    """Enterprise-Grade Digital Forensics & Incident Response (DFIR) Workstation."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)


# ---------------------------------------------------------------------------
# Pipeline Helpers
# ---------------------------------------------------------------------------


def _execute_analysis_pipeline(
    email: CanonicalEmail,
    output_dir: Optional[Path] = None,
    save_attachments: bool = False,
    custom_yara_rules: Optional[List[Dict[str, Any]]] = None,
    threat_hashes: Optional[set[str]] = None,
    protected_domains: Optional[List[str]] = None,
    protected_executives: Optional[List[Dict[str, str]]] = None,
    net_service: Optional[NetworkIntelligenceService] = None,
) -> CanonicalEmail:
    """Execute the full multi-vector forensic analysis pipeline on a single CanonicalEmail."""
    decomp = HeaderDecomposer.decompose(email.ordered_headers)
    email.header_decomposition = decomp

    if save_attachments and output_dir:
        clean_mid = re.sub(r'[<>:"/\\|?*]', "_", email.message_id or "msg")
        msg_out = output_dir / clean_mid
        email.extracted_attachments = AttachmentExtractor.extract_from_email(
            email, output_dir=msg_out, save_to_disk=True
        )
    else:
        email.extracted_attachments = AttachmentExtractor.extract_from_email(
            email, save_to_disk=False
        )

    received_hdrs = decomp.received_headers
    transit_route = RelayAnalyzer.reconstruct_route(received_hdrs)
    svc = net_service or NetworkIntelligenceService()
    email.transit_route = svc.enrich_route(transit_route)

    email.authentication_report = AuthenticationVerifier.verify_email(email)

    url_analyzer = URLAnalyzer()
    email.url_report = url_analyzer.extract_urls(email)

    bec_detector = BECDetector()
    email.bec_report = bec_detector.detect(
        email,
        protected_domains=protected_domains,
        protected_executives=protected_executives,
    )

    obf_detector = ContentObfuscationDetector()
    email.obfuscation_report = obf_detector.detect(email)

    scanner = AttachmentThreatScanner(custom_yara_rules=custom_yara_rules)
    email.attachment_threat_report = scanner.scan_email(email, known_bad_hashes=threat_hashes)

    email.timeline_report = TimelineGenerator.generate_timeline(email)
    return email


# ---------------------------------------------------------------------------
# 1. EMAIL FORENSICS SUB-APP (`eft email ...`)
# ---------------------------------------------------------------------------


@email_app.command("scan")
@app.command("scan")
def email_scan_command(
    evidence_path: Path = typer.Argument(
        ...,
        help="Path to the evidence email file (.eml, .msg) or mailbox archive (.mbox)",
        exists=True,
        readable=True,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Emit raw machine-readable JSON structured evidence model to stdout.",
    ),
    case_id: str = typer.Option("CASE-AUTO", "--case-id", "-c", help="DFIR Case/Incident ID"),
    examiner: str = typer.Option("Forensic Examiner", "--examiner", "-e", help="Investigator name"),
    agency: str = typer.Option("DFIR Unit", "--agency", "-a", help="Organization/Agency name"),
    save_attachments: bool = typer.Option(
        False, "--save-attachments", help="Extract and persist attachment payloads to disk"
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output-dir", "-o", help="Directory to save extracted attachments"
    ),
    config_file: Optional[Path] = typer.Option(
        None, "--config", help="Optional JSON/YAML config with protected domains & VIPs"
    ),
    ioc_file: Optional[Path] = typer.Option(
        None,
        "--ioc-file",
        "--ioc-hashes",
        "-i",
        help="Optional file containing known malicious threat hashes",
    ),
) -> None:
    """Run comprehensive DFIR email inspection, multi-vector threat scoring, and triage."""
    try:
        manifest = ChainOfCustodyManager.create_manifest(
            file_path=evidence_path,
            case_id=case_id,
            evidence_id=f"EVID-{evidence_path.stem}",
            examiner_name=examiner,
            examiner_agency=agency,
        )
        ledger = ChainOfCustodyManager.create_ledger(manifest)

        ingester = EmailIngester()
        ingest_result = ingester.ingest_file(evidence_path)

        if not ingest_result.success or not ingest_result.messages:
            err_console.print(f"[bold red]Ingestion failed for {evidence_path}[/bold red]")
            raise typer.Exit(code=1)

        threat_hashes: set[str] = set()
        if ioc_file and ioc_file.is_file():
            for line in ioc_file.read_text(encoding="utf-8").splitlines():
                h = line.strip()
                if h and not h.startswith("#"):
                    threat_hashes.add(h.lower())

        protected_domains: Optional[List[str]] = None
        protected_execs: Optional[List[Dict[str, str]]] = None
        if config_file and config_file.is_file():
            try:
                cfg_data = json.loads(config_file.read_text(encoding="utf-8"))
                protected_domains = cfg_data.get("protected_domains")
                protected_execs = cfg_data.get("protected_executives")
            except Exception as e:
                err_console.print(f"[yellow]Warning: Could not parse config file: {e}[/yellow]")

        analyzed_emails: List[CanonicalEmail] = []
        risk_reports: List[CompositeRiskReport] = []

        out_path = output_dir or (Path.cwd() / "eft_output")
        if save_attachments:
            out_path.mkdir(parents=True, exist_ok=True)

        for email in ingest_result.messages:
            analyzed = _execute_analysis_pipeline(
                email=email,
                output_dir=out_path,
                save_attachments=save_attachments,
                threat_hashes=threat_hashes,
                protected_domains=protected_domains,
                protected_executives=protected_execs,
            )
            risk = ThreatScorer.calculate_composite_risk(analyzed)
            analyzed_emails.append(analyzed)
            risk_reports.append(risk)

        is_valid, _ = ChainOfCustodyManager.verify_integrity(
            ledger, current_file_path=evidence_path
        )
        if not is_valid:
            err_console.print("[bold red]CRITICAL: Evidence hash mismatch detected![/bold red]")
            raise typer.Exit(code=2)

        if json_output:
            if len(analyzed_emails) == 1:
                typer.echo(ForensicReportExporter.export_json(analyzed_emails[0]))
            else:
                dump_list = [
                    json.loads(ForensicReportExporter.export_json(m)) for m in analyzed_emails
                ]
                typer.echo(json.dumps(dump_list, indent=2))
            return

        _format_scan_results(evidence_path, analyzed_emails, risk_reports, manifest=manifest)

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Scan error:[/bold red] {e}")
        raise typer.Exit(code=1)


def _format_scan_results(
    evidence_path: Path,
    emails: List[CanonicalEmail],
    reports: List[CompositeRiskReport],
    manifest: Optional[Any] = None,
) -> None:
    """Format and display email scan results in rich terminal formatting."""
    console.print()
    console.rule(
        f"[bold cyan]DIGITAL EVIDENCE REPORT & DFIR TRIAGE: {evidence_path.name}[/bold cyan]"
    )
    console.print(
        f"[dim]Evidence Path: {evidence_path.resolve()} | Messages Analyzed: {len(emails)}[/dim]\n"
    )

    if manifest:
        sha256_val = (
            manifest.pre_analysis_hashes.get("sha256", "N/A")
            if hasattr(manifest, "pre_analysis_hashes")
            else "N/A"
        )
        case_id = getattr(manifest, "case_id", "N/A")
        examiner = getattr(manifest, "examiner_name", "N/A")
        manifest_panel = (
            f"File: [bold]{evidence_path.name}[/bold]  |  Size: {evidence_path.stat().st_size} bytes\n"
            f"SHA-256: [dim]{sha256_val}[/dim]\n"
            f"Case ID: [bold]{case_id}[/bold]  |  Examiner: {examiner}"
        )
        console.print(
            Panel(manifest_panel, title="[bold]Evidence Ingestion & Custody Manifest[/bold]")
        )
        console.print()

    for idx, (email, report) in enumerate(zip(emails, reports), start=1):
        sev = report.risk_level
        if sev == RiskSeverity.CRITICAL:
            badge = "[bold white on red] CRITICAL THREAT [/bold white on red]"
            score_color = "red"
        elif sev == RiskSeverity.MALICIOUS_HIGH:
            badge = "[bold white on bright_red] HIGH RISK [/bold white on bright_red]"
            score_color = "bright_red"
        elif sev == RiskSeverity.SUSPICIOUS_MEDIUM:
            badge = "[bold black on dark_orange] MEDIUM RISK [/bold black on dark_orange]"
            score_color = "dark_orange"
        elif sev == RiskSeverity.SUSPICIOUS_LOW:
            badge = "[bold black on cyan] LOW SUSPICION [/bold black on cyan]"
            score_color = "cyan"
        else:
            badge = "[bold white on green] CLEAN / BENIGN [/bold white on green]"
            score_color = "green"

        prefix = f"Message #{idx}: " if len(emails) > 1 else ""
        console.rule(f"[bold]{prefix}{email.subject or '(No Subject)'}[/bold]")

        score_panel = (
            f"Overall Threat Score: [bold {score_color}]{report.overall_score:.1f} / 100.0[/bold {score_color}]  |  "
            f"Severity Tier: {badge}\n"
            f"Recommended Action: [bold]{report.recommended_action}[/bold]\n"
            f"Summary: {report.summary}"
        )
        console.print(Panel(score_panel, title="[bold]Forensic Threat Assessment[/bold]"))

        det_table = Table(show_header=True, header_style="bold blue", expand=True)
        det_table.add_column("Vector / Category", style="cyan", width=28)
        det_table.add_column("Status / Findings", style="white")

        det_table.add_row("From", email.from_address or "N/A")
        det_table.add_row("To", ", ".join(email.to_addresses) if email.to_addresses else "N/A")
        if email.reply_to:
            det_table.add_row("Reply-To", email.reply_to)
        det_table.add_row("Date", email.date or "N/A")

        auth = email.authentication_report
        if auth:
            spf_s = f"SPF: {auth.spf.status if auth.spf else 'N/A'}"
            dkim_s = f"DKIM: {', '.join(d.status for d in auth.dkim_signatures) if auth.dkim_signatures else 'N/A'}"
            dmarc_s = f"DMARC: {auth.dmarc.status if auth.dmarc else 'N/A'}"
            det_table.add_row(
                "Authentication", f"[{auth.overall_verdict}] {spf_s} | {dkim_s} | {dmarc_s}"
            )

        route = email.transit_route
        if route and route.hops:
            orig = route.originating_ip or "N/A"
            intel = route.originating_ip_intelligence
            geo_desc = (
                f"{intel.city or ''}, {intel.country or ''} (ASN: {intel.asn or 'N/A'})"
                if intel
                else ""
            )
            det_table.add_row(
                "MTA Transit Route",
                f"{route.total_hops} hops | Origin: {orig} {geo_desc}",
            )

        urls = email.url_report
        if urls:
            det_table.add_row(
                "Hyperlinks & URLs",
                f"{urls.total_urls_found} URLs ({urls.homographs_count} homoglyphs, {urls.ip_urls_count} IP hosts, {urls.anchor_mismatches_count} anchor mismatches)",
            )

        bec = email.bec_report
        if bec:
            bec_status = (
                "[bold red]SUSPECTED[/bold red]" if bec.is_bec_suspected else "[green]CLEAN[/green]"
            )
            det_table.add_row(
                "BEC / Executive Spoofing",
                f"{bec_status} (Score: {bec.threat_score:.1f}, {len(bec.indicators)} indicators)",
            )

        obf = email.obfuscation_report
        if obf:
            det_table.add_row(
                "Content Obfuscation",
                f"{obf.hidden_text_char_count} hidden chars (Zero-Width: {obf.has_zero_width_chars}, Blobs: {len(obf.decoded_blobs)})",
            )

        atts = email.extracted_attachments
        if atts:
            yara_cnt = 0
            if email.attachment_threat_report:
                yara_cnt = email.attachment_threat_report.total_yara_matches
            det_table.add_row(
                "Extracted Attachments",
                f"{len(atts)} attachment(s) fingerprinted ({yara_cnt} YARA matches)",
            )

        console.print(det_table)

        if report.all_factors:
            console.print()
            factor_table = Table(
                title="Forensic Threat Factors & Evidence Attribution",
                header_style="bold red",
                expand=True,
            )
            factor_table.add_column("Severity", width=12)
            factor_table.add_column("Threat Factor", style="bold")
            factor_table.add_column("Points", justify="right", width=10)
            factor_table.add_column("Evidence Reference", style="dim")

            for f in report.all_factors:
                factor_table.add_row(
                    f.severity, f.name, f"+{f.score_contribution:.1f}", f.evidence_reference or ""
                )

            console.print(factor_table)

        console.print()


@email_app.command("report")
@app.command("report")
def email_report_command(
    evidence_path: Path = typer.Argument(
        ...,
        help="Path to evidence email file (.eml, .msg) or mailbox (.mbox)",
        exists=True,
        readable=True,
    ),
    output_dir: Path = typer.Option(
        Path("forensic_reports"),
        "--output-dir",
        "-o",
        help="Destination directory where exported report files will be written.",
    ),
    format_type: str = typer.Option(
        "all",
        "--format",
        "-f",
        help="Report export format: 'all', 'pdf', 'json', 'csv', 'stix'",
    ),
    case_id: str = typer.Option("CASE-2026-001", "--case-id", "-c", help="DFIR Case ID"),
    examiner: str = typer.Option("Forensic Examiner", "--examiner", "-e", help="Examiner name"),
    agency: str = typer.Option("DFIR Unit", "--agency", "-a", help="Examiner agency name"),
) -> None:
    """Generate multi-format forensic evidence reports (PDF, JSON, CSV IoCs, STIX 2.1)."""
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        ingester = EmailIngester()
        ingest_result = ingester.ingest_file(evidence_path)

        if not ingest_result.success or not ingest_result.messages:
            err_console.print(f"[bold red]Failed to ingest evidence: {evidence_path}[/bold red]")
            raise typer.Exit(code=1)

        console.print(
            f"[cyan]Ingested [bold]{len(ingest_result.messages)}[/bold] message(s) from {evidence_path}[/cyan]"
        )

        for idx, email in enumerate(ingest_result.messages, start=1):
            analyzed = _execute_analysis_pipeline(email=email)
            ThreatScorer.calculate_composite_risk(analyzed)

            base_name = (
                f"{evidence_path.stem}"
                if len(ingest_result.messages) == 1
                else f"{evidence_path.stem}_msg_{idx}"
            )

            fmt = format_type.lower().strip()
            if fmt == "all":
                exports = ForensicReportExporter.export_all(
                    analyzed,
                    output_dir=output_dir,
                    base_name=base_name,
                    case_id=case_id,
                    examiner_name=examiner,
                    examiner_agency=agency,
                )
                console.print(
                    Panel(
                        f"[bold green]All 4 forensic report formats generated successfully:[/bold green]\n"
                        f"* PDF Report: [cyan]{exports['pdf']}[/cyan]\n"
                        f"* JSON Schema: [cyan]{exports['json']}[/cyan]\n"
                        f"* CSV IoCs: [cyan]{exports['csv']}[/cyan]\n"
                        f"* STIX 2.1: [cyan]{exports['stix']}[/cyan]",
                        title="[bold green]Report Export Complete[/bold green]",
                    )
                )
            elif fmt == "pdf":
                pdf_p = output_dir / f"{base_name}.pdf"
                ForensicReportExporter.export_pdf(
                    analyzed,
                    output_path=pdf_p,
                    case_id=case_id,
                    examiner_name=examiner,
                    examiner_agency=agency,
                )
                console.print(f"[OK] Generated PDF report: [cyan]{pdf_p}[/cyan]")
            elif fmt == "json":
                json_p = output_dir / f"{base_name}.json"
                ForensicReportExporter.export_json(analyzed, output_path=json_p)
                console.print(f"[OK] Generated JSON artifact: [cyan]{json_p}[/cyan]")
            elif fmt == "csv":
                csv_p = output_dir / f"{base_name}.csv"
                ForensicReportExporter.export_csv(analyzed, output_path=csv_p)
                console.print(f"[OK] Generated CSV IoCs: [cyan]{csv_p}[/cyan]")
            elif fmt == "stix":
                stix_p = output_dir / f"{base_name}.stix2.json"
                ForensicReportExporter.export_stix(analyzed, output_path=stix_p)
                console.print(f"[OK] Generated STIX 2.1 bundle: [cyan]{stix_p}[/cyan]")
            else:
                err_console.print(
                    f"[bold red]Unknown format '{format_type}'. Use 'all', 'pdf', 'json', 'csv', or 'stix'.[/bold red]"
                )
                raise typer.Exit(code=1)

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Error generating reports:[/bold red] {e}")
        raise typer.Exit(code=1)


@email_app.command("inspect")
@app.command("inspect")
def email_inspect_command(
    evidence_path: Path = typer.Argument(
        ...,
        help="Path to evidence email file (.eml, .msg)",
        exists=True,
        readable=True,
    ),
    output: Path = typer.Option(
        Path("inspection_report.html"),
        "--output",
        "-o",
        help="Path to write the standalone HTML inspector file",
    ),
    open_browser: bool = typer.Option(
        False,
        "--open",
        help="Automatically open the generated inspection dashboard in the default web browser",
    ),
) -> None:
    """Generate and view a standalone, air-gapped dual-pane email and header inspector."""
    try:
        ingester = EmailIngester()
        ingest_result = ingester.ingest_file(evidence_path)

        if not ingest_result.success or not ingest_result.messages:
            err_console.print(f"[bold red]Failed to ingest {evidence_path}[/bold red]")
            raise typer.Exit(code=1)

        email = _execute_analysis_pipeline(email=ingest_result.messages[0])
        EmailInspector.generate_inspector_html(email, output_path=output)

        console.print(
            f"[OK] [bold green]Standalone Dual-Pane HTML Inspector written to:[/bold green] [cyan]{output.resolve()}[/cyan]"
        )

        if open_browser:
            webbrowser.open(f"file://{output.resolve()}")

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Inspection error:[/bold red] {e}")
        raise typer.Exit(code=1)


@email_app.command("map")
@app.command("map")
def email_map_command(
    evidence_path: Path = typer.Argument(
        ...,
        help="Path to evidence email file (.eml, .msg)",
        exists=True,
        readable=True,
    ),
    output: Path = typer.Option(
        Path("transit_map.svg"),
        "--output",
        "-o",
        help="Destination SVG file path for the transit map",
    ),
    width: int = typer.Option(1000, "--width", help="SVG map width in pixels"),
    height: int = typer.Option(500, "--height", help="SVG map height in pixels"),
) -> None:
    """Reconstruct MTA relay hops and export an interactive SVG geodesic world transit map."""
    try:
        ingester = EmailIngester()
        ingest_result = ingester.ingest_file(evidence_path)

        if not ingest_result.success or not ingest_result.messages:
            err_console.print(f"[bold red]Failed to ingest {evidence_path}[/bold red]")
            raise typer.Exit(code=1)

        email = ingest_result.messages[0]
        decomp = HeaderDecomposer.decompose(email.ordered_headers)
        transit_route = RelayAnalyzer.reconstruct_route(decomp.received_headers)
        net_service = NetworkIntelligenceService()
        enriched_route = net_service.enrich_route(transit_route)

        svg_content = TransitMapVisualizer.generate_svg_map(
            enriched_route, width=width, height=height
        )

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(svg_content, encoding="utf-8", errors="replace")

        console.print(
            f"[OK] [bold green]MTA Transit Geodesic SVG Map ({enriched_route.total_hops} hops) saved to:[/bold green] [cyan]{output.resolve()}[/cyan]"
        )

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Transit map generation error:[/bold red] {e}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# 2. FILE & BINARY FORENSICS SUB-APP (`eft file ...`)
# ---------------------------------------------------------------------------


@file_app.command("inspect")
def file_inspect_command(
    file_path: Path = typer.Argument(
        ...,
        help="Path to binary, document, or archive file to inspect",
        exists=True,
        readable=True,
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output raw structured JSON inspection report"
    ),
) -> None:
    """Inspect file magic bytes, MIME spoofing, PE headers, and OLE macros."""
    try:
        static_analyzer = BinaryStaticAnalyzer()
        report = static_analyzer.analyze(file_path)

        file_analyzer = FileArtifactAnalyzer()
        artifact_report = file_analyzer.analyze_file(file_path)

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
            return

        console.print()
        console.rule(f"[bold cyan]FILE FORENSIC INSPECTION: {file_path.name}[/bold cyan]")
        console.print(
            f"[dim]Path: {file_path.resolve()} | Size: {file_path.stat().st_size} bytes[/dim]\n"
        )

        tab = Table(show_header=True, header_style="bold blue", expand=True)
        tab.add_column("Attribute / Metric", style="cyan", width=25)
        tab.add_column("Value / Details", style="white")

        tab.add_row("Format Category", report.format_category)
        tab.add_row("Identified Format", artifact_report.identification.detected_format)
        tab.add_row("MIME Type", artifact_report.identification.detected_mime)
        tab.add_row(
            "Declared Extension",
            f".{artifact_report.identification.declared_extension}"
            if artifact_report.identification.declared_extension
            else "None",
        )
        tab.add_row("Entropy Level", report.overall_entropy_level.value)
        tab.add_row("Shannon Entropy", f"{report.overall_entropy:.3f} / 8.0")
        tab.add_row(
            "Extension Spoofing Risk",
            "[bold red]HIGH SPOOFING RISK[/bold red]"
            if artifact_report.identification.is_extension_mismatch
            else "[green]CLEAN[/green]",
        )
        tab.add_row(
            "Double Extension Deception",
            f"[bold red]YES ({artifact_report.identification.detected_inner_extension})[/bold red]"
            if artifact_report.identification.is_double_extension
            else "[green]NO[/green]",
        )
        if report.pe_analysis:
            pe = report.pe_analysis
            tab.add_row("PE Architecture", pe.architecture)
            tab.add_row("PE Sections", f"{len(pe.sections)} sections")
            tab.add_row("Suspicious APIs", f"{len(pe.suspicious_apis)} suspicious imports")
        if report.ole_analysis:
            ole = report.ole_analysis
            tab.add_row(
                "VBA Macros Detected", "[bold red]YES[/bold red]" if ole.has_vba_macros else "No"
            )
            tab.add_row("Suspicious Macro Keywords", str(len(ole.all_suspicious_keywords)))
        tab.add_row(
            "Threat Verdict",
            f"[{'bold red' if report.verdict in ('SUSPICIOUS', 'MALICIOUS') else 'green'}]{report.verdict}[/]",
        )

        console.print(tab)
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]File inspection error:[/bold red] {e}")
        raise typer.Exit(code=1)


@file_app.command("entropy")
def file_entropy_command(
    file_path: Path = typer.Argument(
        ...,
        help="Path to binary file to compute Shannon entropy map",
        exists=True,
        readable=True,
    ),
    block_size: int = typer.Option(
        1024, "--block-size", "-b", help="Block size in bytes for chunk entropy"
    ),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw JSON entropy data"),
) -> None:
    """Compute and visualize Shannon entropy distribution to detect packing, encryption, or shellcode."""
    try:
        analyzer = BinaryStaticAnalyzer()
        res = analyzer.analyze(file_path)

        if json_output:
            typer.echo(
                json.dumps(
                    {
                        "file": str(file_path),
                        "entropy": res.overall_entropy,
                        "entropy_level": res.overall_entropy_level.value,
                        "size_bytes": res.size_bytes,
                    },
                    indent=2,
                )
            )
            return

        console.print()
        console.rule(f"[bold cyan]SHANNON ENTROPY PROFILE: {file_path.name}[/bold cyan]")
        score = res.overall_entropy
        color = "red" if score >= 7.2 else ("yellow" if score >= 6.0 else "green")
        bar_len = int((score / 8.0) * 40)
        bar = f"[{color}]{'█' * bar_len}{'░' * (40 - bar_len)}[/{color}]"

        panel = (
            f"Overall Entropy: [bold {color}]{score:.3f} / 8.000[/bold {color}]\n"
            f"Entropy Bar:     {bar}\n"
            f"Classification:  [bold]{res.overall_entropy_level.value}[/bold]\n"
            f"Assessment:      {'Likely packed, encrypted payload, or compressed shellcode' if score >= 7.2 else 'Standard plaintext / uncompressed binary structure'}"
        )
        console.print(Panel(panel, title="[bold]Entropy Analysis[/bold]"))
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Entropy error:[/bold red] {e}")
        raise typer.Exit(code=1)


@file_app.command("exif")
def file_exif_command(
    file_path: Path = typer.Argument(
        ...,
        help="Path to document, image, or media file to extract metadata",
        exists=True,
        readable=True,
    ),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw JSON metadata"),
) -> None:
    """Extract deep-dive metadata, EXIF, GPS, author info, and software traces."""
    try:
        extractor = MetadataExtractor()
        report = extractor.extract_from_file(file_path)

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
            return

        console.print()
        console.rule(f"[bold cyan]METADATA & EXIF EXTRACTION: {file_path.name}[/bold cyan]")

        tab = Table(show_header=True, header_style="bold blue", expand=True)
        tab.add_column("Metadata Field", style="cyan", width=25)
        tab.add_column("Extracted Value", style="white")

        tab.add_row("File Type", report.file_type)
        if report.exif:
            img = report.exif
            tab.add_row(
                "Image Dimensions",
                f"{img.image_width or 'N/A'} x {img.image_height or 'N/A'} ({img.color_space or 'RGB'})",
            )
            tab.add_row(
                "Camera Make / Model", f"{img.camera_make or 'N/A'} {img.camera_model or ''}"
            )
            tab.add_row("Software Used", img.software or "N/A")
            if img.gps:
                tab.add_row(
                    "GPS Coordinates", f"Lat {img.gps.latitude:.5f}, Lon {img.gps.longitude:.5f}"
                )
        if report.document:
            doc = report.document
            tab.add_row("Document Author", doc.creator or "N/A")
            tab.add_row("Document Application", doc.application or "N/A")
            tab.add_row("Created Date", str(doc.created or "N/A"))
            tab.add_row("Modified Date", str(doc.modified or "N/A"))
            tab.add_row("Page Count", str(doc.page_count or "N/A"))

        console.print(tab)
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Metadata extraction error:[/bold red] {e}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# 3. OSINT INTELLIGENCE SUB-APP (`eft osint ...`)
# ---------------------------------------------------------------------------


def _format_osint_report(report: DomainOSINTReport) -> None:
    """Render a DomainOSINTReport using Rich tables and panels."""
    score = report.reputation_score
    if score >= 75.0:
        badge = "[bold white on red] CRITICAL RISK [/bold white on red]"
        score_color = "red"
    elif score >= 50.0:
        badge = "[bold white on bright_red] HIGH RISK [/bold white on bright_red]"
        score_color = "bright_red"
    elif score >= 25.0:
        badge = "[bold black on yellow] SUSPICIOUS / MEDIUM RISK [/bold black on yellow]"
        score_color = "yellow"
    elif score >= 10.0:
        badge = "[bold black on cyan] LOW RISK [/bold black on cyan]"
        score_color = "cyan"
    else:
        badge = "[bold white on green] HEALTHY / LOW RISK [/bold white on green]"
        score_color = "green"

    console.print()
    console.rule(f"[bold cyan]OSINT INTELLIGENCE REPORT: {report.input_target}[/bold cyan]")
    console.print()

    target_type = "Email Address" if report.is_email_address else "Domain Name"

    panel_content = (
        f"Target: [bold]{report.input_target}[/bold] ({target_type})  |  "
        f"Domain: [bold cyan]{report.analyzed_domain}[/bold cyan]\n"
        f"Reputation Score: [bold {score_color}]{report.reputation_score:.1f} / 100.0[/bold {score_color}]  |  "
        f"Severity: {badge}  |  "
        f"Category: [bold magenta]{report.category.value}[/bold magenta]\n"
        f"Summary: {report.summary}"
    )
    console.print(Panel(panel_content, title="[bold]Executive Domain & Email Intelligence[/bold]"))

    id_table = Table(
        title="Domain Identity & Target Profile",
        show_header=True,
        header_style="bold blue",
        expand=True,
    )
    id_table.add_column("Attribute", style="cyan", width=25)
    id_table.add_column("Value / Details", style="white")

    id_table.add_row("Target Input", report.input_target)
    id_table.add_row("Target Type", target_type)
    if report.username:
        id_table.add_row("Username / Mailbox", report.username)
    id_table.add_row("Fully Qualified Domain (FQDN)", report.analyzed_domain)
    id_table.add_row("Registered Domain", report.registered_domain)
    id_table.add_row("Top-Level Domain (TLD)", f".{report.tld}")
    if report.is_punycode:
        id_table.add_row(
            "IDN / Punycode", f"[bold yellow]YES ({report.unicode_domain or 'N/A'})[/bold yellow]"
        )
    id_table.add_row("Category Classification", report.category.value)
    if report.disposable_service:
        id_table.add_row(
            "Disposable Provider",
            f"[bold red]{report.disposable_service} (Temporary Mailbox)[/bold red]",
        )
    if report.freemail_provider:
        id_table.add_row("Freemail Provider", f"[bold cyan]{report.freemail_provider}[/bold cyan]")
    id_table.add_row("Analysis Timestamp (UTC)", report.analyzed_at.isoformat())
    console.print(id_table)

    dns = report.dns_posture
    dns_table = Table(
        title="DNS Routing & Email Authentication Posture",
        show_header=True,
        header_style="bold green",
        expand=True,
    )
    dns_table.add_column("Security Mechanism", style="cyan", width=25)
    dns_table.add_column("Status / Configuration", style="white")

    if dns.has_mx and dns.mx_records:
        mx_formatted = [f"{m.host} (prio {m.preference})" for m in dns.mx_records]
        mx_str = f"[bold green]CONFIGURED[/bold green] ({len(dns.mx_records)} records: {', '.join(mx_formatted)})"
    else:
        mx_str = "[bold red]MISSING[/bold red] (Cannot receive inbound email)"
    dns_table.add_row("MX Mail Exchangers", mx_str)
    dns_table.add_row(
        "Host IPv4 (A)", ", ".join(dns.a_records) if dns.a_records else "[dim]None resolved[/dim]"
    )
    dns_table.add_row(
        "Nameservers (NS)",
        ", ".join(dns.ns_records) if dns.ns_records else "[dim]None resolved[/dim]",
    )

    spf = dns.spf
    if spf.raw_record or spf.qualifier != "missing":
        spf_status = f"[bold green]PRESENT[/bold green] (Strictness: [bold]{spf.strictness.value}[/bold], Qualifier: [yellow]{spf.qualifier}[/yellow])"
        if spf.raw_record:
            spf_status += f"\n[dim]{spf.raw_record}[/dim]"
    else:
        spf_status = "[bold red]MISSING[/bold red] (No SPF record published)"
    dns_table.add_row("SPF Record", spf_status)

    dmarc = dns.dmarc
    if dmarc.raw_record or dmarc.policy != "missing":
        dmarc_color = (
            "green"
            if dmarc.enforcement.value in ["REJECT", "QUARANTINE"]
            else ("yellow" if dmarc.enforcement.value == "NONE" else "red")
        )
        dmarc_status = f"[bold {dmarc_color}]PRESENT[/bold {dmarc_color}] (Policy: [bold]{dmarc.policy}[/bold], Enforcement: [bold]{dmarc.enforcement.value}[/bold], pct: {dmarc.percentage}%)"
        if dmarc.raw_record:
            dmarc_status += f"\n[dim]{dmarc.raw_record}[/dim]"
    else:
        dmarc_status = "[bold red]MISSING[/bold red] (No DMARC policy published)"
    dns_table.add_row("DMARC Policy", dmarc_status)
    console.print(dns_table)
    console.print()


def _handle_lookup(
    target: str,
    json_output: bool = False,
    dns_timeout: float = 3.0,
    offline: bool = False,
    output: Optional[Path] = None,
) -> None:
    try:
        analyzer = DomainOSINTAnalyzer()
        report = analyzer.analyze(target=target, dns_timeout=dns_timeout, offline=offline)

        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            if not json_output:
                console.print(
                    f"[bold green][OK][/bold green] OSINT report saved to: [cyan]{output}[/cyan]"
                )

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
        else:
            _format_osint_report(report)

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]OSINT Lookup Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@osint_app.command("lookup")
@app.command("lookup")
def osint_lookup_command(
    target: str = typer.Argument(
        ...,
        help="Email address (user@domain.com) or domain name (example.com) to inspect",
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output raw structured JSON report"
    ),
    dns_timeout: float = typer.Option(
        3.0, "--dns-timeout", "-t", help="DNS query timeout in seconds"
    ),
    offline: bool = typer.Option(False, "--offline", help="Run in offline air-gapped mode"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="File to save JSON report"),
) -> None:
    """Perform pre-triage OSINT intelligence inspection on an email address or domain name."""
    _handle_lookup(
        target=target,
        json_output=json_output,
        dns_timeout=dns_timeout,
        offline=offline,
        output=output,
    )


@osint_app.command("domain")
def osint_domain_command(
    domain: str = typer.Argument(..., help="Domain name to inspect (e.g. example.com)"),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output raw structured JSON report"
    ),
    dns_timeout: float = typer.Option(
        3.0, "--dns-timeout", "-t", help="DNS query timeout in seconds"
    ),
    offline: bool = typer.Option(False, "--offline", help="Run in offline air-gapped mode"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="File to save JSON report"),
) -> None:
    """Analyze domain authentication posture (SPF, DMARC, DKIM, BIMI) and typosquatting."""
    _handle_lookup(
        target=domain,
        json_output=json_output,
        dns_timeout=dns_timeout,
        offline=offline,
        output=output,
    )


@osint_app.command("ip")
def osint_ip_command(
    ip_address: str = typer.Argument(..., help="IPv4 or IPv6 address to geolocate and enrich"),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output raw JSON intelligence model"
    ),
) -> None:
    """Geolocate and enrich IP address with ASN, ISP, Tor, VPN, and cloud hyperscaler metadata."""
    try:
        net_service = NetworkIntelligenceService()
        intel = net_service.lookup_ip(ip_address)

        if not intel:
            err_console.print(f"[bold red]Invalid IP address format: {ip_address}[/bold red]")
            raise typer.Exit(code=1)

        if json_output:
            typer.echo(intel.model_dump_json(indent=2))
            return

        console.print()
        console.rule(f"[bold cyan]IP NETWORK INTELLIGENCE: {ip_address}[/bold cyan]")
        tab = Table(show_header=True, header_style="bold blue", expand=True)
        tab.add_column("Attribute", style="cyan", width=25)
        tab.add_column("Value / Forensic Details", style="white")

        tab.add_row("IP Address", intel.ip)
        tab.add_row(
            "Country / Region",
            f"{intel.country or 'Unknown'} ({intel.country_code or 'XX'}) / {intel.region or 'N/A'}",
        )
        tab.add_row(
            "City / Coordinates",
            f"{intel.city or 'N/A'} (Lat: {intel.latitude}, Lon: {intel.longitude})",
        )
        tab.add_row("ASN", f"AS{intel.asn}" if intel.asn else "N/A")
        tab.add_row("Organization / ISP", intel.as_org or intel.isp or "Unknown")
        tab.add_row(
            "Cloud Hyperscaler",
            f"[bold yellow]{intel.cloud_provider_name}[/bold yellow]"
            if intel.is_cloud_provider
            else "No",
        )
        tab.add_row(
            "Tor Exit Node",
            "[bold red]YES (TOR EXIT NODE)[/bold red]" if intel.is_tor_exit_node else "No",
        )
        tab.add_row(
            "VPN / Proxy Hosting",
            "[bold red]YES (COMMERCIAL VPN/PROXY)[/bold red]"
            if (intel.is_vpn or intel.is_proxy)
            else "No",
        )
        tab.add_row(
            "Private / RFC1918",
            "[bold cyan]YES (INTERNAL/PRIVATE)[/bold cyan]" if intel.is_private else "No",
        )

        console.print(tab)
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]IP OSINT Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("osint")
def root_osint_alias(
    target: str = typer.Argument(..., help="Email address or domain name to inspect"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw JSON report"),
    dns_timeout: float = typer.Option(
        3.0, "--dns-timeout", "-t", help="DNS query timeout in seconds"
    ),
    offline: bool = typer.Option(False, "--offline", help="Run in offline air-gapped mode"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="File to save JSON report"),
) -> None:
    """Alias for 'eft osint lookup': Inspect domain/email authentication posture and reputation."""
    _handle_lookup(
        target=target,
        json_output=json_output,
        dns_timeout=dns_timeout,
        offline=offline,
        output=output,
    )


# ---------------------------------------------------------------------------
# 4. NETWORK PCAP FORENSICS SUB-APP (`eft pcap ...`)
# ---------------------------------------------------------------------------


@pcap_app.command("analyze")
def pcap_analyze_command(
    pcap_path: Path = typer.Argument(
        ..., help="Path to .pcap or .pcapng network capture file", exists=True, readable=True
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output raw JSON PCAP analysis report"
    ),
) -> None:
    """Dissect PCAP streams, flows, packet timestamps, and protocol conversations."""
    try:
        analyzer = NetworkPCAPAnalyzer()
        report = analyzer.analyze(pcap_path)

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
            return

        console.print()
        console.rule(f"[bold cyan]PCAP NETWORK STREAM ANALYSIS: {pcap_path.name}[/bold cyan]")
        tab = Table(show_header=True, header_style="bold blue", expand=True)
        tab.add_column("Metric / Summary", style="cyan", width=25)
        tab.add_column("Value / Details", style="white")

        tab.add_row("Total Packets", str(report.total_packets))
        tab.add_row("Total Flows / Conversations", str(len(report.flows)))
        tab.add_row("HTTP Requests", str(report.http_requests_count))
        tab.add_row("DNS Queries Dissected", str(report.dns_queries_count))
        tab.add_row("TLS Handshakes (SNI)", str(report.tls_handshakes_count))
        tab.add_row(
            "Suspicious Network Anomalies",
            f"[bold red]{len(report.forensic_alerts)}[/bold red]"
            if report.forensic_alerts
            else "[green]0[/green]",
        )

        console.print(tab)
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]PCAP Analysis Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@pcap_app.command("dns")
def pcap_dns_command(
    pcap_path: Path = typer.Argument(
        ..., help="Path to .pcap capture file", exists=True, readable=True
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output raw JSON DNS threat report"
    ),
) -> None:
    """Detect DNS exfiltration, tunneling, fast-flux networks, DGA, and beaconing."""
    try:
        detector = DNSThreatAnalyzer()
        report = detector.analyze_pcap(pcap_path)

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
            return

        console.print()
        console.rule(f"[bold cyan]DNS THREAT & EXFILTRATION TRIAGE: {pcap_path.name}[/bold cyan]")
        score = report.threat_score
        color = "red" if score >= 75 else ("yellow" if score >= 40 else "green")

        panel = (
            f"DNS Threat Score: [bold {color}]{score:.1f} / 100.0[/bold {color}]\n"
            f"Tunneling Alerts: {len(report.tunneling_alerts)}  |  Fast-Flux Domains: {len(report.fast_flux_alerts)}\n"
            f"DGA Detections:   {len(report.dga_alerts)}  |  High-Entropy Subdomains: {len(report.high_entropy_subdomains)}"
        )
        console.print(Panel(panel, title="[bold]DNS Forensics Assessment[/bold]"))
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]DNS Threat Analysis Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@pcap_app.command("creds")
def pcap_creds_command(
    pcap_path: Path = typer.Argument(
        ..., help="Path to .pcap capture file", exists=True, readable=True
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output raw JSON credential leakage report"
    ),
) -> None:
    """Extract unencrypted credentials, API keys, HTTP Basic auth, and cleartext file transfers."""
    try:
        extractor = CredentialLeakAnalyzer()
        report = extractor.analyze_pcap(pcap_path)

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
            return

        console.print()
        console.rule(
            f"[bold cyan]CLEARTEXT CREDENTIAL & SECRET LEAKAGE: {pcap_path.name}[/bold cyan]"
        )
        tab = Table(show_header=True, header_style="bold red", expand=True)
        tab.add_column("Protocol / Type", style="cyan", width=20)
        tab.add_column("Target Host / URI", style="white")
        tab.add_column("Account / Secret", style="yellow")

        for c in report.credentials:
            tab.add_row(
                c.protocol.value,
                c.endpoint_url or f"{c.dst_ip}:{c.dst_port}",
                f"{c.username or 'N/A'}:{c.secret.masked_value}",
            )

        console.print(tab)
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Credential Extraction Error:[/bold red] {e}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# 5. EVENT & CLOUD LOG FORENSICS SUB-APP (`eft log ...`)
# ---------------------------------------------------------------------------


@log_app.command("evtx")
def log_evtx_command(
    evtx_path: Path = typer.Argument(
        ..., help="Path to Windows Security .evtx log file", exists=True, readable=True
    ),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw JSON log report"),
) -> None:
    """Triage Windows Security logs for logon anomalies, brute force, privilege escalation, and persistence."""
    try:
        analyzer = WindowsSecurityAnalyzer()
        report = analyzer.analyze_file(evtx_path)

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
            return

        console.print()
        console.rule(f"[bold cyan]WINDOWS SECURITY EVENT LOG TRIAGE: {evtx_path.name}[/bold cyan]")
        tab = Table(show_header=True, header_style="bold blue", expand=True)
        tab.add_column("Metric / Indicator", style="cyan", width=25)
        tab.add_column("Value / Details", style="white")

        tab.add_row("Total Security Events", str(report.total_events_parsed))
        tab.add_row("Logon Events (4624/4625)", str(len(report.logons)))
        tab.add_row("Admin Privileges Assigned (4672)", str(len(report.special_privileges)))
        tab.add_row("New Services Installed (7045/4697)", str(len(report.services_installed)))
        tab.add_row("Scheduled Tasks (4698/4702)", str(len(report.scheduled_tasks)))
        tab.add_row(
            "Security Anomaly Alerts",
            f"[bold red]{len(report.anomalies)}[/bold red]"
            if report.anomalies
            else "[green]0[/green]",
        )

        console.print(tab)
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]EVTX Security Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@log_app.command("sysmon")
def log_sysmon_command(
    evtx_path: Path = typer.Argument(
        ..., help="Path to Sysmon .evtx log file", exists=True, readable=True
    ),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw JSON Sysmon report"),
) -> None:
    """Correlate Sysmon process creation, parent-child relationships, network connections, and file drops."""
    try:
        analyzer = WindowsLogAnalyzer()
        report = analyzer.analyze_file(evtx_path)

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
            return

        console.print()
        console.rule(
            f"[bold cyan]SYSMON PROCESS & THREAT CORRELATION: {evtx_path.name}[/bold cyan]"
        )
        tab = Table(show_header=True, header_style="bold blue", expand=True)
        tab.add_column("Sysmon Telemetry", style="cyan", width=25)
        tab.add_column("Value / Details", style="white")

        tab.add_row("Total Records Parsed", str(report.total_records_parsed))
        tab.add_row("Sysmon Events", str(report.total_sysmon_events))
        tab.add_row("Security Events", str(report.total_security_events))
        tab.add_row("Process Trees", str(len(report.process_trees)))
        tab.add_row(
            "Process Tree Anomalies",
            f"[bold red]{len(report.anomalies)}[/bold red]"
            if report.anomalies
            else "[green]0[/green]",
        )

        console.print(tab)
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Sysmon Analysis Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@log_app.command("m365")
def log_m365_command(
    log_path: Path = typer.Argument(
        ...,
        help="Path to Microsoft 365 Unified Audit Log (.json, .csv)",
        exists=True,
        readable=True,
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output raw JSON M365 audit report"
    ),
) -> None:
    """Ingest M365 UAL logs for exfiltration inbox rules, mailbox delegation backdoors, and illicit OAuth grants."""
    try:
        analyzer = CloudAuditAnalyzer()
        report = analyzer.analyze_file(log_path)

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
            return

        console.print()
        console.rule(f"[bold cyan]MICROSOFT 365 AUDIT LOG TRIAGE: {log_path.name}[/bold cyan]")
        tab = Table(show_header=True, header_style="bold blue", expand=True)
        tab.add_column("Cloud Forensic Telemetry", style="cyan", width=25)
        tab.add_column("Value / Findings", style="white")

        tab.add_row("Total Records Parsed", str(report.total_records_parsed))
        tab.add_row("Inbox Rules Created/Modified", str(len(report.inbox_rules)))
        tab.add_row("Mailbox Permissions Granted", str(len(report.mailbox_delegations)))
        tab.add_row("OAuth Application Consents", str(len(report.oauth_consents)))
        tab.add_row("User Authentication Events", str(len(report.logins)))
        tab.add_row(
            "Threat Detections",
            f"[bold red]{len(report.anomalies)}[/bold red]"
            if report.anomalies
            else "[green]0[/green]",
        )

        console.print(tab)
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]M365 Audit Analysis Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@log_app.command("google")
def log_google_command(
    log_path: Path = typer.Argument(
        ...,
        help="Path to Google Workspace Admin audit log (.json, .csv)",
        exists=True,
        readable=True,
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output raw JSON Google Workspace report"
    ),
) -> None:
    """Ingest Google Workspace audit logs for user forwarding modifications, admin elevations, and account creations."""
    try:
        analyzer = CloudAuditAnalyzer()
        report = analyzer.analyze_file(log_path)

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
            return

        console.print()
        console.rule(f"[bold cyan]GOOGLE WORKSPACE AUDIT LOG TRIAGE: {log_path.name}[/bold cyan]")
        tab = Table(show_header=True, header_style="bold blue", expand=True)
        tab.add_column("Admin Telemetry", style="cyan", width=25)
        tab.add_column("Value / Findings", style="white")

        tab.add_row("Total Records Parsed", str(report.total_records_parsed))
        tab.add_row("Admin Audit Events", str(len(report.google_admin_events)))
        tab.add_row(
            "Threat Detections",
            f"[bold red]{len(report.anomalies)}[/bold red]"
            if report.anomalies
            else "[green]0[/green]",
        )

        console.print(tab)
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Google Workspace Audit Error:[/bold red] {e}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# 6. VOLATILE MEMORY FORENSICS SUB-APP (`eft mem ...`)
# ---------------------------------------------------------------------------


@mem_app.command("scan")
def mem_scan_command(
    memory_path: Path = typer.Argument(
        ..., help="Path to RAM dump (.raw, .dmp, .vmem, .bin, .lime)", exists=True, readable=True
    ),
    min_length: int = typer.Option(4, "--min-length", "-l", help="Minimum printable string length"),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output raw JSON combined memory report"
    ),
) -> None:
    """Comprehensive volatile memory triage: ingestion, string extraction, IoCs, and YARA signature scanning."""
    try:
        mem_analyzer = MemoryArtifactAnalyzer()
        ioc_matcher = MemoryIoCMatcher(memory_analyzer=mem_analyzer)
        yara_scanner = MemoryYARAScanner()

        extraction_report = mem_analyzer.analyze(
            memory_path, min_length=min_length, max_samples=100
        )
        pattern_report = ioc_matcher.scan_stream(memory_path, min_length=min_length)
        yara_report = yara_scanner.scan_stream(memory_path)

        if json_output:
            typer.echo(
                json.dumps(
                    {
                        "evidence_path": str(memory_path),
                        "hashes": extraction_report.evidence_hashes,
                        "metadata": extraction_report.metadata.model_dump(),
                        "statistics": extraction_report.statistics.model_dump(),
                        "patterns": pattern_report.model_dump(),
                        "yara_attribution": yara_report.model_dump(),
                    },
                    indent=2,
                    default=str,
                )
            )
            return

        console.print()
        console.rule(f"[bold cyan]VOLATILE MEMORY MASTER TRIAGE: {memory_path.name}[/bold cyan]")
        score = yara_report.composite_threat_score
        color = "red" if score >= 75 else ("yellow" if score >= 40 else "green")

        panel = (
            f"Image Format:    [bold cyan]{extraction_report.metadata.format.value}[/bold cyan]  |  Architecture: [bold]{extraction_report.metadata.architecture}[/bold]\n"
            f"Total Strings:   {extraction_report.statistics.total_strings} (ASCII: {extraction_report.statistics.ascii_count}, UTF-16: {extraction_report.statistics.utf16_count})\n"
            f"Pattern Matches: {pattern_report.total_patterns_matched} (High-Risk: {len(pattern_report.high_risk_findings)})\n"
            f"Threat Score:    [bold {color}]{score} / 100 ({yara_report.threat_level})[/bold {color}]\n"
            f"Attribution:     {yara_report.attribution_summary}"
        )
        console.print(Panel(panel, title="[bold]Memory Forensics Assessment[/bold]"))
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Memory Scan Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@mem_app.command("strings")
def mem_strings_command(
    memory_path: Path = typer.Argument(
        ..., help="Path to RAM dump file", exists=True, readable=True
    ),
    min_length: int = typer.Option(4, "--min-length", "-l", help="Minimum string length"),
    max_count: int = typer.Option(50, "--max-count", "-n", help="Maximum sample strings to print"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw JSON string report"),
) -> None:
    """Stream extracted ASCII & UTF-16LE strings with exact byte offsets."""
    try:
        analyzer = MemoryArtifactAnalyzer()
        report = analyzer.analyze(memory_path, min_length=min_length, max_samples=max_count)

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
            return

        console.print()
        console.rule(f"[bold cyan]EXTRACTED STRINGS SAMPLE: {memory_path.name}[/bold cyan]")
        tab = Table(show_header=True, header_style="bold blue", expand=True)
        tab.add_column("Byte Offset", style="cyan", width=15)
        tab.add_column("Encoding", style="yellow", width=10)
        tab.add_column("String Content", style="white")

        for item in report.strings_sample[:max_count]:
            tab.add_row(f"0x{item.offset:08X}", item.encoding.value, item.value[:80])

        console.print(tab)
        console.print(
            f"[dim]Showing {min(max_count, len(report.strings_sample))} of {report.total_extracted_count} extracted strings.[/dim]\n"
        )

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Memory Strings Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@mem_app.command("iocs")
def mem_iocs_command(
    memory_path: Path = typer.Argument(
        ..., help="Path to RAM dump file", exists=True, readable=True
    ),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw JSON IoC report"),
) -> None:
    """Scan RAM strings for IPv4/IPv6 addresses, URLs, crypto wallets, JWTs, private keys, and Base64 payloads."""
    try:
        matcher = MemoryIoCMatcher()
        report = matcher.scan_stream(memory_path)

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
            return

        console.print()
        console.rule(f"[bold cyan]IN-MEMORY IOC & PATTERN FINDINGS: {memory_path.name}[/bold cyan]")
        tab = Table(show_header=True, header_style="bold red", expand=True)
        tab.add_column("Type", style="cyan", width=18)
        tab.add_column("Matched IoC / Secret", style="yellow")
        tab.add_column("Offset", style="dim", width=12)
        tab.add_column("Risk", justify="right", width=8)

        for m in report.matches:
            tab.add_row(m.ioc_type.value, m.value[:60], f"0x{m.offset:08X}", str(m.risk_score))

        console.print(tab)
        console.print()

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Memory IoC Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@mem_app.command("yara")
def mem_yara_command(
    memory_path: Path = typer.Argument(
        ..., help="Path to RAM dump file", exists=True, readable=True
    ),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw JSON YARA report"),
) -> None:
    """Execute memory signature scans for Cobalt Strike, Mimikatz, Meterpreter, Lumma Stealer, and Ransomware."""
    try:
        scanner = MemoryYARAScanner()
        report = scanner.scan_stream(memory_path)

        if json_output:
            typer.echo(report.model_dump_json(indent=2))
            return

        console.print()
        console.rule(f"[bold cyan]VOLATILE MEMORY YARA SCAN: {memory_path.name}[/bold cyan]")
        tab = Table(show_header=True, header_style="bold red", expand=True)
        tab.add_column("Rule Name", style="bold", width=35)
        tab.add_column("Threat Family", style="magenta", width=22)
        tab.add_column("Severity", width=12)
        tab.add_column("Risk Score", justify="right", width=10)

        for y in report.yara_matches:
            tab.add_row(y.rule_name, y.threat_family.value, y.severity, str(y.risk_score))

        console.print(tab)
        console.print(f"[bold]Attribution Summary:[/bold] {report.attribution_summary}\n")

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Memory YARA Error:[/bold red] {e}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# 7. ROOT COMMANDS & VERIFICATION
# ---------------------------------------------------------------------------


@app.command("verify")
def verify_command(
    evidence_path: Path = typer.Argument(
        ...,
        help="Path to evidence file to verify for zero-byte mutation",
        exists=True,
        readable=True,
    ),
    manifest_file: Optional[Path] = typer.Option(
        None,
        "--manifest",
        "-m",
        help="Path to evidence_manifest.json or ledger JSON to verify against",
    ),
    expected_sha256: Optional[str] = typer.Option(
        None,
        "--sha256",
        help="Optional expected SHA-256 hash string to verify against directly",
    ),
) -> None:
    """Cryptographically verify evidence file integrity against acquisition hashes (ISO/IEC 27037)."""
    try:
        current_hashes = compute_file_hashes(evidence_path)
        current_sha256 = current_hashes["sha256"]

        table = Table(title="Evidence Integrity Verification", expand=True)
        table.add_column("Check", style="cyan")
        table.add_column("Hash Value", style="white")
        table.add_column("Result", style="bold")

        table.add_row("Current SHA-256", current_sha256, "[green]COMPUTED[/green]")
        table.add_row("Current SHA-1", current_hashes["sha1"], "[green]COMPUTED[/green]")
        table.add_row("Current MD5", current_hashes["md5"], "[green]COMPUTED[/green]")

        is_tampered = False

        if expected_sha256:
            target_hash = expected_sha256.strip().lower()
            if target_hash == current_sha256.lower():
                table.add_row(
                    "Expected SHA-256",
                    target_hash,
                    "[bold green][MATCH] (INTEGRITY VERIFIED)[/bold green]",
                )
            else:
                table.add_row(
                    "Expected SHA-256",
                    target_hash,
                    "[bold red][MISMATCH] (EVIDENCE TAMPERED)[/bold red]",
                )
                is_tampered = True

        if manifest_file:
            m_path = Path(manifest_file)
            if m_path.is_file():
                manifest_data = json.loads(m_path.read_text(encoding="utf-8", errors="replace"))
                pre_hash = manifest_data.get("pre_analysis_hashes", {}).get(
                    "sha256"
                ) or manifest_data.get("manifest", {}).get("pre_analysis_hashes", {}).get("sha256")
                if pre_hash:
                    if pre_hash.lower() == current_sha256.lower():
                        table.add_row(
                            "Manifest Pre-Analysis Hash",
                            pre_hash,
                            "[bold green][MATCH] (IMMUTABILITY VERIFIED)[/bold green]",
                        )
                    else:
                        table.add_row(
                            "Manifest Pre-Analysis Hash",
                            pre_hash,
                            "[bold red][MISMATCH] (TAMPERING DETECTED)[/bold red]",
                        )
                        is_tampered = True

        console.print(table)

        if is_tampered:
            err_console.print(
                "[bold red]CRITICAL: Evidence hash mismatch! Potential tampering detected.[/bold red]"
            )
            raise typer.Exit(code=2)
        else:
            console.print(
                "[bold green][OK] Cryptographic evidence integrity verified. Zero mutation detected.[/bold green]"
            )

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Verification error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("serve")
def serve_command(
    host: str = typer.Option("127.0.0.1", "--host", "-H", help="Host IP to bind web server"),
    port: int = typer.Option(8000, "--port", "-p", help="Port number for web server"),
    reload: bool = typer.Option(False, "--reload", help="Enable hot reload for development"),
    open_browser: bool = typer.Option(
        False, "--open", help="Automatically open browser upon server start"
    ),
) -> None:
    """Launch the air-gapped forensic web analysis server and interactive dashboard."""
    try:
        import uvicorn

        from eft.server.app import create_app

        console.print()
        console.rule("[bold cyan]EMAIL FORENSIC TOOL (EFT) — AIR-GAPPED WEB SERVER[/bold cyan]")
        console.print(
            f"[OK] [bold green]Server running at:[/bold green] [cyan]http://{host}:{port}[/cyan]"
        )
        console.print("[dim]Press Ctrl+C to stop the server.[/dim]\n")

        if open_browser:
            import threading
            import time

            def _open_tab() -> None:
                time.sleep(1.0)
                webbrowser.open(f"http://{host}:{port}")

            threading.Thread(target=_open_tab, daemon=True).start()

        app_instance = create_app()
        uvicorn.run(app_instance, host=host, port=port, reload=reload)

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Server error:[/bold red] {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
