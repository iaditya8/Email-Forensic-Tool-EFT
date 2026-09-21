"""Unified Command-Line Interface (CLI) Suite for Email Forensic Tool (EFT)."""

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
from eft.analysis.domain_osint import DomainOSINTAnalyzer
from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.analysis.obfuscation_detector import ContentObfuscationDetector
from eft.analysis.relay_analyzer import RelayAnalyzer
from eft.analysis.threat_scorer import ThreatScorer
from eft.analysis.url_analyzer import URLAnalyzer
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

app = typer.Typer(
    name="eft",
    help="Email Forensic Tool (EFT) — Enterprise DFIR & Authentication Analysis Suite",
    no_args_is_help=True,
    add_completion=False,
)

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
    """Enterprise-Grade Digital Forensics & Incident Response (DFIR) Email Analysis Engine."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)


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
    # 1. Header Decomposition
    decomp = HeaderDecomposer.decompose(email.ordered_headers)
    email.header_decomposition = decomp

    # 2. Attachment Extraction
    if save_attachments and output_dir:
        clean_mid = re.sub(r'[<>:"/\\|?*]', "_", email.message_id or "msg")
        att_dir = output_dir / f"attachments_{clean_mid}"
        extracted = AttachmentExtractor.extract_from_email(
            email, output_dir=att_dir, save_to_disk=True
        )
    else:
        extracted = AttachmentExtractor.extract_from_email(email, save_to_disk=False)
    email.extracted_attachments = extracted

    # 3. Authentication Verification
    auth_report = AuthenticationVerifier.verify_email(email)
    email.authentication_report = auth_report

    # 4. Relay Hop Reconstruction & Network Intelligence
    transit_route = RelayAnalyzer.reconstruct_route(decomp.received_headers)
    svc = net_service or NetworkIntelligenceService()
    email.transit_route = svc.enrich_route(transit_route)

    # 5. URL Analysis
    email.url_report = URLAnalyzer().extract_urls(email)

    # 6. BEC & Spoofing Detection
    email.bec_report = BECDetector().detect(
        email,
        protected_domains=protected_domains,
        protected_executives=protected_executives,
    )

    # 7. Obfuscation & Zero-Width Detector
    email.obfuscation_report = ContentObfuscationDetector().detect(email)

    # 8. Attachment Threat Scanning & YARA
    scanner = AttachmentThreatScanner(custom_yara_rules=custom_yara_rules)
    email.attachment_threat_report = scanner.scan_email(email, known_bad_hashes=threat_hashes)

    # 9. Timeline Synthesis
    email.timeline_report = TimelineGenerator.generate_timeline(email)

    return email


@app.command("scan")
def scan_command(
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
    """Run comprehensive DFIR forensic inspection, multi-vector threat scoring, and triage."""
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

        # Load optional threat intel
        threat_hashes: set[str] = set()
        if ioc_file and ioc_file.is_file():
            for line in ioc_file.read_text(encoding="utf-8").splitlines():
                h = line.strip()
                if h and not h.startswith("#"):
                    threat_hashes.add(h.lower())

        # Load optional protected domain/VIP config
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

        # Verify custody integrity
        is_valid, _ = ChainOfCustodyManager.verify_integrity(
            ledger, current_file_path=evidence_path
        )
        if not is_valid:
            err_console.print("[bold red]CRITICAL: Evidence hash mismatch detected![/bold red]")
            raise typer.Exit(code=2)

        # Output JSON format if requested
        if json_output:
            if len(analyzed_emails) == 1:
                typer.echo(ForensicReportExporter.export_json(analyzed_emails[0]))
            else:
                dump_list = [
                    json.loads(ForensicReportExporter.export_json(m)) for m in analyzed_emails
                ]
                typer.echo(json.dumps(dump_list, indent=2))
            return

        # Terminal Rich Dashboard Output
        _render_scan_terminal_dashboard(manifest, analyzed_emails, risk_reports)

    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        err_console.print(f"[bold red]Forensic analysis error:[/bold red] {e}")
        raise typer.Exit(code=1)


def _render_scan_terminal_dashboard(
    manifest: Any,
    emails: List[CanonicalEmail],
    reports: List[CompositeRiskReport],
) -> None:
    """Render high-fidelity Rich terminal dashboard for forensic triage."""
    console.print()
    console.rule("[bold cyan]EMAIL FORENSIC TOOL (EFT) — DIGITAL EVIDENCE REPORT[/bold cyan]")
    console.print()

    # Evidence Provenance Box
    prov_table = Table(show_header=True, header_style="bold magenta", expand=True)
    prov_table.add_column("Property", style="cyan", width=24)
    prov_table.add_column("Evidence Value", style="white")

    prov_table.add_row("Evidence Path", manifest.source_file_path)
    prov_table.add_row("Evidence Size", f"{manifest.source_file_size_bytes:,} bytes")
    prov_table.add_row("Case / Evidence ID", f"{manifest.case_id} / {manifest.evidence_id}")
    prov_table.add_row(
        "Examiner / Agency", f"{manifest.examiner_name} ({manifest.examiner_agency})"
    )
    prov_table.add_row("SHA-256 Digest", manifest.pre_analysis_hashes.get("sha256", "N/A"))
    prov_table.add_row("MD5 Digest", manifest.pre_analysis_hashes.get("md5", "N/A"))
    prov_table.add_row("Messages Parsed", f"{len(emails)} message(s)")
    prov_table.add_row("Chain of Custody", "[MATCH] Verified (Zero Byte Mutation)")

    console.print(
        Panel(prov_table, title="[bold green]Evidence Ingestion & Custody Manifest[/bold green]")
    )
    console.print()

    for idx, (email, report) in enumerate(zip(emails, reports), start=1):
        # Color coding by severity
        sev = report.risk_level
        if sev == RiskSeverity.CRITICAL:
            badge = "[bold white on red] CRITICAL THREAT [/bold white on red]"
            score_color = "red"
        elif sev == RiskSeverity.MALICIOUS_HIGH:
            badge = "[bold white on dark_orange] HIGH RISK [/bold white on dark_orange]"
            score_color = "dark_orange"
        elif sev == RiskSeverity.SUSPICIOUS_MEDIUM:
            badge = "[bold black on yellow] SUSPICIOUS [/bold black on yellow]"
            score_color = "yellow"
        elif sev == RiskSeverity.SUSPICIOUS_LOW:
            badge = "[bold black on cyan] LOW SUSPICION [/bold black on cyan]"
            score_color = "cyan"
        else:
            badge = "[bold white on green] CLEAN / BENIGN [/bold white on green]"
            score_color = "green"

        prefix = f"Message #{idx}: " if len(emails) > 1 else ""
        console.rule(f"[bold]{prefix}{email.subject or '(No Subject)'}[/bold]")

        # Executive Threat Score Dial
        score_panel = (
            f"Overall Threat Score: [bold {score_color}]{report.overall_score:.1f} / 100.0[/bold {score_color}]  |  "
            f"Severity Tier: {badge}\n"
            f"Recommended Action: [bold]{report.recommended_action}[/bold]\n"
            f"Summary: {report.summary}"
        )
        console.print(Panel(score_panel, title="[bold]Forensic Threat Assessment[/bold]"))

        # Details Table
        det_table = Table(show_header=True, header_style="bold blue", expand=True)
        det_table.add_column("Vector / Category", style="cyan", width=28)
        det_table.add_column("Status / Findings", style="white")

        # Sender & Message
        det_table.add_row("From", email.from_address or "N/A")
        det_table.add_row("To", ", ".join(email.to_addresses) if email.to_addresses else "N/A")
        if email.reply_to:
            det_table.add_row("Reply-To", email.reply_to)
        det_table.add_row("Date", email.date or "N/A")

        # Authentication
        auth = email.authentication_report
        if auth:
            spf_s = f"SPF: {auth.spf.status if auth.spf else 'N/A'}"
            dkim_s = f"DKIM: {', '.join(d.status for d in auth.dkim_signatures) if auth.dkim_signatures else 'N/A'}"
            dmarc_s = f"DMARC: {auth.dmarc.status if auth.dmarc else 'N/A'}"
            det_table.add_row(
                "Authentication", f"[{auth.overall_verdict}] {spf_s} | {dkim_s} | {dmarc_s}"
            )

        # Transit route
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

        # URLs
        urls = email.url_report
        if urls:
            det_table.add_row(
                "Hyperlinks & URLs",
                f"{urls.total_urls_found} URLs ({urls.homographs_count} homoglyphs, {urls.ip_urls_count} IP hosts, {urls.anchor_mismatches_count} anchor mismatches)",
            )

        # BEC
        bec = email.bec_report
        if bec:
            bec_status = (
                "[bold red]SUSPECTED[/bold red]" if bec.is_bec_suspected else "[green]CLEAN[/green]"
            )
            det_table.add_row(
                "BEC / Executive Spoofing",
                f"{bec_status} (Score: {bec.threat_score:.1f}, {len(bec.indicators)} indicators)",
            )

        # Obfuscation
        obf = email.obfuscation_report
        if obf:
            det_table.add_row(
                "Content Obfuscation",
                f"{obf.hidden_text_char_count} hidden chars (Zero-Width: {obf.has_zero_width_chars}, Blobs: {len(obf.decoded_blobs)})",
            )

        # Attachments
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

        # Top Threat Factors
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


@app.command("report")
def report_command(
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


@app.command("inspect")
def inspect_command(
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


@app.command("map")
def map_command(
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
        from eft.core.integrity import compute_file_hashes

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

    # Executive Score Dial Panel
    panel_content = (
        f"Target: [bold]{report.input_target}[/bold] ({target_type})  |  "
        f"Domain: [bold cyan]{report.analyzed_domain}[/bold cyan]\n"
        f"Reputation Score: [bold {score_color}]{report.reputation_score:.1f} / 100.0[/bold {score_color}]  |  "
        f"Severity: {badge}  |  "
        f"Category: [bold magenta]{report.category.value}[/bold magenta]\n"
        f"Summary: {report.summary}"
    )
    console.print(Panel(panel_content, title="[bold]Executive Domain & Email Intelligence[/bold]"))

    # Target Profile & Domain Identity Table
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

    # DNS Authentication Posture Table
    dns = report.dns_posture
    dns_table = Table(
        title="DNS Routing & Email Authentication Posture",
        show_header=True,
        header_style="bold green",
        expand=True,
    )
    dns_table.add_column("Security Mechanism", style="cyan", width=25)
    dns_table.add_column("Status / Configuration", style="white")

    # MX
    if dns.has_mx and dns.mx_records:
        mx_formatted = [f"{m.host} (prio {m.preference})" for m in dns.mx_records]
        mx_str = f"[bold green]CONFIGURED[/bold green] ({len(dns.mx_records)} records: {', '.join(mx_formatted)})"
    else:
        mx_str = "[bold red]MISSING[/bold red] (Cannot receive inbound email)"
    dns_table.add_row("MX Mail Exchangers", mx_str)

    # A / NS
    dns_table.add_row(
        "Host IPv4 (A)", ", ".join(dns.a_records) if dns.a_records else "[dim]None resolved[/dim]"
    )
    dns_table.add_row(
        "Nameservers (NS)",
        ", ".join(dns.ns_records) if dns.ns_records else "[dim]None resolved[/dim]",
    )

    # SPF
    spf = dns.spf
    if spf.raw_record or spf.qualifier != "missing":
        spf_status = f"[bold green]PRESENT[/bold green] (Strictness: [bold]{spf.strictness.value}[/bold], Qualifier: [yellow]{spf.qualifier}[/yellow])"
        if spf.raw_record:
            spf_status += f"\n[dim]{spf.raw_record}[/dim]"
        if spf.warnings:
            spf_status += f"\n[bold yellow]Warnings:[/bold yellow] {'; '.join(spf.warnings)}"
    else:
        spf_status = "[bold red]MISSING[/bold red] (No SPF record published)"
    dns_table.add_row("SPF Record", spf_status)

    # DMARC
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
        if dmarc.rua_uris:
            dmarc_status += f"\n[dim]Reporting (RUA): {', '.join(dmarc.rua_uris)}[/dim]"
        if dmarc.warnings:
            dmarc_status += f"\n[bold yellow]Warnings:[/bold yellow] {'; '.join(dmarc.warnings)}"
    else:
        dmarc_status = "[bold red]MISSING[/bold red] (No DMARC policy published)"
    dns_table.add_row("DMARC Policy", dmarc_status)

    # DKIM Discovery
    dkim_probed = dns.discovered_dkim
    found_selectors = [d for d in dkim_probed if d.is_valid]
    if found_selectors:
        sel_details = [
            f"[bold green]{d.selector}[/bold green] ({d.key_type})" for d in found_selectors
        ]
        dkim_status = f"[bold green]{len(found_selectors)} Selectors Discovered[/bold green]: {', '.join(sel_details)}"
    else:
        dkim_status = "[dim]0 common selectors discovered[/dim]"
    dns_table.add_row("DKIM Probing", dkim_status)

    # BIMI
    bimi = dns.bimi
    if bimi.logo_url or bimi.raw_record:
        bimi_status = f"[bold green]PRESENT[/bold green] (Logo: {bimi.logo_url or 'N/A'}, VMC: {'YES' if bimi.has_vmc else 'NO'})"
    else:
        bimi_status = "[dim]Not configured[/dim]"
    dns_table.add_row("BIMI Brand Identity", bimi_status)

    console.print(dns_table)

    # Brand Lookalike & Typosquatting Panel
    if report.brand_risk and (
        report.brand_risk.has_homoglyphs
        or report.brand_risk.is_cousin_domain
        or report.brand_risk.similarity_score >= 0.75
    ):
        br = report.brand_risk
        hg_str = f" | Homoglyphs: {', '.join(br.homoglyphs_detected)}" if br.has_homoglyphs else ""
        brand_text = (
            f"Target Domain: [bold cyan]{report.analyzed_domain}[/bold cyan]  -->  "
            f"Targeted Protected Brand: [bold yellow]{br.matched_brand_domain}[/bold yellow]\n"
            f"Levenshtein Distance: [bold]{br.levenshtein_distance}[/bold]  |  "
            f"Similarity: [bold]{br.similarity_score * 100:.1f}%[/bold]  |  "
            f"Indicator: [bold red]{br.risk_indicator}[/bold red]{hg_str}"
        )
        console.print(
            Panel(
                brand_text,
                title="[bold red][!] Brand Impersonation & Typosquatting Alert[/bold red]",
                border_style="red",
            )
        )

    # Threat Factors Table
    if report.risk_factors:
        rf_table = Table(
            title="Contributing Threat & Anomaly Factors",
            show_header=True,
            header_style="bold red",
            expand=True,
        )
        rf_table.add_column("Severity", width=12)
        rf_table.add_column("Threat Factor / Anomaly", style="bold")
        rf_table.add_column("Points", justify="right", width=10)
        rf_table.add_column("Evidence Reference", style="dim")
        for f in report.risk_factors:
            sev_str = f.severity.value if hasattr(f.severity, "value") else f.severity
            rf_table.add_row(
                sev_str,
                f.name,
                f"+{f.score_contribution:.1f}",
                f.evidence_reference or "",
            )
        console.print(rf_table)

    # Remediation Advice Panel
    if report.remediation_advice:
        advice_text = "\n".join(
            f"[bold cyan]*[/bold cyan] {advice}" for advice in report.remediation_advice
        )
        console.print(
            Panel(
                advice_text,
                title="[bold]Forensic Remediation & Hardening Recommendations[/bold]",
                border_style="cyan",
            )
        )

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


@app.command("lookup")
def lookup_command(
    target: str = typer.Argument(
        ...,
        help="Email address (user@domain.com), domain name (example.com), or URL to inspect",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output raw structured JSON intelligence report",
    ),
    dns_timeout: float = typer.Option(
        3.0,
        "--dns-timeout",
        "-t",
        help="Timeout in seconds for DNS queries",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Run in offline air-gapped mode without performing network DNS queries",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional destination file path to save JSON report",
    ),
) -> None:
    """Perform pre-triage OSINT intelligence inspection on an email address or domain name."""
    _handle_lookup(
        target=target,
        json_output=json_output,
        dns_timeout=dns_timeout,
        offline=offline,
        output=output,
    )


@app.command("osint")
def osint_command(
    target: str = typer.Argument(
        ...,
        help="Email address (user@domain.com), domain name (example.com), or URL to inspect",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output raw structured JSON intelligence report",
    ),
    dns_timeout: float = typer.Option(
        3.0,
        "--dns-timeout",
        "-t",
        help="Timeout in seconds for DNS queries",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Run in offline air-gapped mode without performing network DNS queries",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional destination file path to save JSON report",
    ),
) -> None:
    """Alias for 'lookup': Inspect domain/email authentication posture, homoglyphs, and reputation."""
    _handle_lookup(
        target=target,
        json_output=json_output,
        dns_timeout=dns_timeout,
        offline=offline,
        output=output,
    )


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
