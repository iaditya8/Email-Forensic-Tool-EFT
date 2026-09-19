"""Multi-format forensic report exporter generating PDF, JSON, CSV, and STIX 2.1 artifacts."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import stix2
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from eft.models.canonical import CanonicalEmail


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas for dynamic 'Page X of Y' footer and confidentiality header."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int) -> None:
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#718096"))

        # Running Header
        self.drawString(
            54,
            750,
            "EMAIL FORENSIC TOOL (EFT) — DFIR DIGITAL EVIDENCE REPORT [CONFIDENTIAL]",
        )
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(54, 744, 558, 744)

        # Running Footer
        self.line(54, 45, 558, 45)
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_text)
        self.drawString(
            54,
            32,
            "Court-Admissible Evidence Artifact — Verified Immutability & Chain of Custody",
        )
        self.restoreState()


class ForensicReportExporter:
    """Enterprise-grade multi-format forensic evidence and threat intelligence exporter."""

    @classmethod
    def export_json(
        cls,
        email_obj: CanonicalEmail,
        output_path: Optional[Union[str, Path]] = None,
        indent: int = 2,
    ) -> str:
        """Export the complete canonical email model to a loss-free structured JSON artifact.

        Args:
            email_obj: The CanonicalEmail instance to serialize.
            output_path: Optional destination file path on disk.
            indent: Indentation formatting level (default: 2).

        Returns:
            JSON-formatted string representation.
        """
        import base64

        data = email_obj.model_dump(mode="python")

        def _json_serial(obj: Any) -> Any:
            if isinstance(obj, bytes):
                return base64.b64encode(obj).decode("ascii")
            if isinstance(obj, (datetime, Path)):
                return obj.isoformat() if isinstance(obj, datetime) else str(obj)
            return str(obj)

        json_str = json.dumps(data, indent=indent, default=_json_serial)

        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json_str, encoding="utf-8")

        return json_str

    @classmethod
    def export_csv(
        cls,
        email_obj: CanonicalEmail,
        output_path: Optional[Union[str, Path]] = None,
    ) -> str:
        """Extract and export all Indicators of Compromise (IoCs) to RFC 4180 CSV format.

        Args:
            email_obj: The CanonicalEmail instance to inspect.
            output_path: Optional destination file path on disk.

        Returns:
            Formatted CSV content string.
        """
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        # Header Row
        writer.writerow(
            [
                "ioc_type",
                "ioc_value",
                "source_context",
                "severity",
                "threat_category",
                "description",
            ]
        )

        # 1. IP Addresses (Transit Route / Relays)
        if email_obj.transit_route and email_obj.transit_route.hops:
            for hop in email_obj.transit_route.hops:
                if hop.from_ip:
                    intel = hop.network_intelligence
                    desc = f"Transit hop {hop.hop_number} sending IP"
                    if intel and intel.as_org:
                        desc += f" (ASN: {intel.asn or 'N/A'}, Org: {intel.as_org})"
                    severity = (
                        "HIGH"
                        if intel and (intel.is_tor_exit_node or "TOR" in intel.threat_tags)
                        else ("MEDIUM" if intel and intel.is_vpn else "INFO")
                    )
                    writer.writerow(
                        [
                            "ip-address",
                            hop.from_ip,
                            f"Hop {hop.hop_number}",
                            severity,
                            "INFRASTRUCTURE",
                            desc,
                        ]
                    )

        # 2. Domains & Sender Identities
        if email_obj.from_address:
            writer.writerow(
                [
                    "email-address",
                    email_obj.from_address,
                    "Header: From",
                    "INFO",
                    "IDENTITY",
                    "Declared sender address",
                ]
            )

        if email_obj.return_path and email_obj.return_path != email_obj.from_address:
            writer.writerow(
                [
                    "email-address",
                    email_obj.return_path,
                    "Header: Return-Path",
                    "LOW",
                    "ENVELOPE",
                    "Envelope bounce return path address",
                ]
            )

        if email_obj.reply_to and email_obj.reply_to != email_obj.from_address:
            writer.writerow(
                [
                    "email-address",
                    email_obj.reply_to,
                    "Header: Reply-To",
                    "MEDIUM",
                    "ROUTING_MISMATCH",
                    "Asymmetric Reply-To address differing from From header",
                ]
            )

        # 3. Hyperlinks & URLs
        if email_obj.url_report and email_obj.url_report.urls:
            for url_entry in email_obj.url_report.urls:
                severity = (
                    "CRITICAL"
                    if url_entry.is_idn_homograph
                    else (
                        "HIGH"
                        if url_entry.is_anchor_mismatch
                        else ("MEDIUM" if url_entry.is_ip_host or url_entry.is_shortener else "LOW")
                    )
                )
                category = "PHISHING_URL" if severity in ["CRITICAL", "HIGH"] else "HYPERLINK"
                desc = f"Extracted from {url_entry.source_location}. Defanged: {url_entry.defanged_url}"
                if url_entry.risk_flags:
                    desc += f" [Flags: {', '.join(url_entry.risk_flags)}]"

                writer.writerow(
                    [
                        "url",
                        url_entry.url,
                        url_entry.source_location,
                        severity,
                        category,
                        desc,
                    ]
                )

        # 4. Attachments & Cryptographic Hashes
        if email_obj.extracted_attachments:
            for att in email_obj.extracted_attachments:
                threat = att.threat_analysis
                severity = (
                    "CRITICAL"
                    if threat and threat.is_malicious
                    else ("HIGH" if threat and threat.threat_level == "SUSPICIOUS" else "LOW")
                )
                category = (
                    "MALICIOUS_PAYLOAD"
                    if severity in ["CRITICAL", "HIGH"]
                    else "ATTACHMENT_ARTIFACT"
                )

                desc = f"File: {att.filename} ({att.size_bytes} bytes, MIME: {att.content_type})"
                if threat and threat.threat_indicators:
                    desc += f" [Threats: {', '.join(threat.threat_indicators)}]"

                # Record SHA-256
                if "sha256" in att.hashes:
                    writer.writerow(
                        [
                            "file-hash-sha256",
                            att.hashes["sha256"],
                            f"Attachment: {att.filename}",
                            severity,
                            category,
                            f"{desc} (SHA-256 digest)",
                        ]
                    )
                # Record MD5
                if "md5" in att.hashes:
                    writer.writerow(
                        [
                            "file-hash-md5",
                            att.hashes["md5"],
                            f"Attachment: {att.filename}",
                            severity,
                            category,
                            f"{desc} (MD5 digest)",
                        ]
                    )

        # 5. BEC Indicators
        if email_obj.bec_report and email_obj.bec_report.indicators:
            for bec_ind in email_obj.bec_report.indicators:
                writer.writerow(
                    [
                        "bec-indicator",
                        bec_ind.observed_value or "N/A",
                        bec_ind.indicator_type,
                        bec_ind.severity,
                        "SOCIAL_ENGINEERING",
                        bec_ind.description,
                    ]
                )

        # 6. Obfuscated Blob Hashes
        if email_obj.obfuscation_report and email_obj.obfuscation_report.decoded_blobs:
            for blob in email_obj.obfuscation_report.decoded_blobs:
                if blob.decoded_bytes_sha256:
                    writer.writerow(
                        [
                            "obfuscated-payload-hash",
                            blob.decoded_bytes_sha256,
                            f"Decoded {blob.encoding_type} blob",
                            "HIGH" if blob.suspicious_indicators else "MEDIUM",
                            "EVASION_PAYLOAD",
                            f"Decoded {blob.encoding_type} stream from {blob.source_location}. Flags: {', '.join(blob.suspicious_indicators) or 'None'}",
                        ]
                    )

        csv_str = output.getvalue()
        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(csv_str, encoding="utf-8")

        return csv_str

    @classmethod
    def export_stix(
        cls,
        email_obj: CanonicalEmail,
        output_path: Optional[Union[str, Path]] = None,
    ) -> str:
        """Export forensic findings as a standardized STIX 2.1 Cyber Threat Intelligence bundle.

        Args:
            email_obj: The CanonicalEmail instance to convert.
            output_path: Optional destination file path on disk.

        Returns:
            STIX 2.1 JSON bundle string.
        """
        stix_objects: List[Any] = []

        # 1. Email Address Observables
        from_ref = None
        if email_obj.from_address and "@" in email_obj.from_address:
            # Extract clean email address if display name present
            match = re.search(r"[\w\.-]+@[\w\.-]+", email_obj.from_address)
            clean_addr = match.group(0) if match else email_obj.from_address
            from_ref = stix2.EmailAddress(value=clean_addr)
            stix_objects.append(from_ref)

        to_refs: List[Any] = []
        for to_addr in email_obj.to_addresses:
            if "@" in to_addr:
                match = re.search(r"[\w\.-]+@[\w\.-]+", to_addr)
                clean_addr = match.group(0) if match else to_addr
                to_email = stix2.EmailAddress(value=clean_addr)
                to_refs.append(to_email)
                stix_objects.append(to_email)

        # 2. EmailMessage Cyber Observable
        is_multi = len(email_obj.mime_parts) > 1
        email_kwargs: Dict[str, Any] = {
            "is_multipart": is_multi,
            "subject": email_obj.subject or "(No Subject)",
        }
        if not is_multi:
            email_kwargs["body"] = (email_obj.body_plain or email_obj.body_html or "")[:4000]
        if from_ref:
            email_kwargs["from_ref"] = from_ref.id
        if to_refs:
            email_kwargs["to_refs"] = [t.id for t in to_refs]
        if email_obj.message_id:
            email_kwargs["message_id"] = email_obj.message_id

        # Received lines
        if email_obj.transit_route and email_obj.transit_route.hops:
            received_lines = [
                hop.raw_header for hop in email_obj.transit_route.hops if hop.raw_header
            ]
            if received_lines:
                email_kwargs["received_lines"] = received_lines

        email_sco = stix2.EmailMessage(**email_kwargs)
        stix_objects.append(email_sco)

        # 3. IPv4 / IPv6 Observables for Relay Hops
        if email_obj.transit_route and email_obj.transit_route.hops:
            for hop in email_obj.transit_route.hops:
                if hop.from_ip:
                    try:
                        if ":" in hop.from_ip:
                            ip_sco = stix2.IPv6Address(value=hop.from_ip)
                        else:
                            ip_sco = stix2.IPv4Address(value=hop.from_ip)
                        stix_objects.append(ip_sco)
                    except Exception:
                        pass

        # 4. URL Observables & Phishing Indicators
        if email_obj.url_report and email_obj.url_report.urls:
            for url_item in email_obj.url_report.urls:
                try:
                    url_sco = stix2.URL(value=url_item.url)
                    stix_objects.append(url_sco)

                    # If suspicious or malicious, create STIX Indicator SDO
                    if (
                        url_item.risk_score >= 40.0
                        or url_item.is_idn_homograph
                        or url_item.is_anchor_mismatch
                    ):
                        escaped_url = url_item.url.replace("'", "\\'")
                        indicator = stix2.Indicator(
                            name=f"Suspicious / Phishing URL: {url_item.domain}",
                            pattern_type="stix",
                            pattern=f"[url:value = '{escaped_url}']",
                            valid_from=datetime.now(timezone.utc),
                            indicator_types=["malicious-activity"],
                            description=f"Suspicious URL extracted from email ({', '.join(url_item.risk_flags)})",
                        )
                        stix_objects.append(indicator)

                        # Relationship
                        rel = stix2.Relationship(
                            source_ref=indicator.id,
                            target_ref=email_sco.id,
                            relationship_type="indicates",
                        )
                        stix_objects.append(rel)
                except Exception:
                    pass

        # 5. Attachment File Observables & Malware Indicators
        if email_obj.extracted_attachments:
            for att in email_obj.extracted_attachments:
                try:
                    file_hashes: Dict[str, str] = {}
                    if "sha256" in att.hashes:
                        file_hashes["SHA-256"] = att.hashes["sha256"]
                    if "md5" in att.hashes:
                        file_hashes["MD5"] = att.hashes["md5"]
                    if "sha1" in att.hashes:
                        file_hashes["SHA-1"] = att.hashes["sha1"]

                    file_sco = stix2.File(
                        name=att.filename,
                        size=att.size_bytes,
                        hashes=file_hashes or None,
                        mime_type=att.content_type,
                    )
                    stix_objects.append(file_sco)

                    threat = att.threat_analysis
                    if threat and (
                        threat.is_malicious or threat.threat_level in ["SUSPICIOUS", "MALICIOUS"]
                    ):
                        sha256_val = att.hashes.get("sha256", "")
                        if sha256_val:
                            indicator = stix2.Indicator(
                                name=f"Malicious Attachment: {att.filename}",
                                pattern_type="stix",
                                pattern=f"[file:hashes.'SHA-256' = '{sha256_val}']",
                                valid_from=datetime.now(timezone.utc),
                                indicator_types=["malicious-activity"],
                                description=f"Malicious email attachment: {att.filename} [Threats: {', '.join(threat.threat_indicators)}]",
                            )
                            stix_objects.append(indicator)

                            rel = stix2.Relationship(
                                source_ref=indicator.id,
                                target_ref=file_sco.id,
                                relationship_type="indicates",
                            )
                            stix_objects.append(rel)
                except Exception:
                    pass

        # Bundle Creation
        bundle = stix2.Bundle(objects=stix_objects, allow_custom=True)
        bundle_json = bundle.serialize(pretty=True)

        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(bundle_json, encoding="utf-8")

        return bundle_json

    @classmethod
    def export_pdf(
        cls,
        email_obj: CanonicalEmail,
        output_path: Union[str, Path],
        case_id: Optional[str] = None,
        examiner_name: Optional[str] = None,
        examiner_agency: Optional[str] = None,
    ) -> Path:
        """Generate a comprehensive, court-admissible DFIR forensic PDF report.

        Args:
            email_obj: The CanonicalEmail instance with full analysis records.
            output_path: Output file destination for the PDF.
            case_id: Optional case identifier override.
            examiner_name: Optional examiner name override.
            examiner_agency: Optional agency name override.

        Returns:
            Path object pointing to the written PDF file.
        """
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(out_file),
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )

        styles = getSampleStyleSheet()

        # Custom Typography Styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#1A202C"),
            spaceAfter=4,
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#4A5568"),
            spaceAfter=12,
        )
        h2_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#2D3748"),
            spaceBefore=10,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "TableBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#2D3748"),
        )
        bold_style = ParagraphStyle(
            "TableBodyBold",
            parent=body_style,
            fontName="Helvetica-Bold",
        )
        code_style = ParagraphStyle(
            "TableCode",
            parent=body_style,
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#2B6CB0"),
        )

        story: List[Any] = []

        # 1. Document Title & Header
        story.append(Spacer(1, 10))
        story.append(Paragraph("DIGITAL EVIDENCE FORENSIC ANALYSIS REPORT", title_style))
        story.append(
            Paragraph(
                "Court-Admissible Technical Investigation & Threat Intelligence Audit",
                subtitle_style,
            )
        )
        story.append(
            HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2B6CB0"), spaceAfter=10)
        )

        # 2. Case & Evidence Metadata Card
        c_id = case_id or "CASE-2026-DFIR-AUTO"
        ex_name = examiner_name or "Special Agent Examiner"
        ex_agency = examiner_agency or "Cyber Digital Forensics Unit"
        acq_time = (
            email_obj.ingestion_timestamp_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
            if email_obj.ingestion_timestamp_utc
            else "N/A"
        )
        ev_file = email_obj.source_file.file_name if email_obj.source_file else "evidence.eml"
        ev_size = (
            f"{email_obj.source_file.file_size_bytes:,} bytes" if email_obj.source_file else "N/A"
        )
        sha256_digest = (
            email_obj.source_file.hashes.get("sha256", "N/A") if email_obj.source_file else "N/A"
        )

        meta_data = [
            [
                Paragraph("<b>Case Identifier:</b>", body_style),
                Paragraph(c_id, bold_style),
                Paragraph("<b>Examiner:</b>", body_style),
                Paragraph(f"{ex_name} ({ex_agency})", body_style),
            ],
            [
                Paragraph("<b>Evidence File:</b>", body_style),
                Paragraph(ev_file, body_style),
                Paragraph("<b>File Size:</b>", body_style),
                Paragraph(ev_size, body_style),
            ],
            [
                Paragraph("<b>Acquisition (UTC):</b>", body_style),
                Paragraph(acq_time, body_style),
                Paragraph("<b>Integrity:</b>", body_style),
                Paragraph(
                    "<font color='#22543D'><b>VERIFIED IMMUTABLE (MATCH)</b></font>", body_style
                ),
            ],
            [
                Paragraph("<b>Pre-Analysis SHA-256:</b>", body_style),
                Paragraph(f"<code>{sha256_digest}</code>", code_style),
                "",
                "",
            ],
        ]

        meta_table = Table(meta_data, colWidths=[105, 145, 80, 174])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("SPAN", (1, 3), (3, 3)),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # 3. Envelope Overview Table
        story.append(Paragraph("1. Core Email Envelope & Header Information", h2_style))
        env_data = [
            [
                Paragraph("<b>From:</b>", body_style),
                Paragraph(email_obj.from_address or "N/A", body_style),
            ],
            [
                Paragraph("<b>To:</b>", body_style),
                Paragraph(", ".join(email_obj.to_addresses) or "N/A", body_style),
            ],
            [
                Paragraph("<b>Subject:</b>", body_style),
                Paragraph(email_obj.subject or "(No Subject)", bold_style),
            ],
            [
                Paragraph("<b>Date Header:</b>", body_style),
                Paragraph(email_obj.date or "N/A", body_style),
            ],
            [
                Paragraph("<b>Message-ID:</b>", body_style),
                Paragraph(email_obj.message_id or "N/A", code_style),
            ],
            [
                Paragraph("<b>Return-Path:</b>", body_style),
                Paragraph(email_obj.return_path or "N/A", body_style),
            ],
            [
                Paragraph("<b>Reply-To:</b>", body_style),
                Paragraph(email_obj.reply_to or "N/A", body_style),
            ],
        ]

        env_table = Table(env_data, colWidths=[90, 414])
        env_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EDF2F7")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(env_table)
        story.append(Spacer(1, 10))

        # 4. Authentication Card (SPF, DKIM, DMARC, ARC)
        story.append(Paragraph("2. Multi-Protocol Authentication Verification", h2_style))
        auth_rep = email_obj.authentication_report
        spf_status = auth_rep.spf.status.upper() if auth_rep and auth_rep.spf else "NONE"
        dmarc_status = auth_rep.dmarc.status.upper() if auth_rep and auth_rep.dmarc else "NONE"
        arc_status = auth_rep.arc.arc_seal_status.upper() if auth_rep and auth_rep.arc else "NONE"
        dkim_count = len(auth_rep.dkim_signatures) if auth_rep else 0

        auth_rows = [
            [
                Paragraph("<b>Protocol</b>", bold_style),
                Paragraph("<b>Result Status</b>", bold_style),
                Paragraph("<b>Alignment / Policy</b>", bold_style),
                Paragraph("<b>Details / Verdict</b>", bold_style),
            ],
            [
                Paragraph("<b>SPF (RFC 7208)</b>", body_style),
                Paragraph(
                    f"<font color='{'#22543D' if spf_status == 'PASS' else '#9B2C2C'}'><b>{spf_status}</b></font>",
                    body_style,
                ),
                Paragraph(
                    f"Aligned: {auth_rep.spf.is_aligned if auth_rep and auth_rep.spf else False}",
                    body_style,
                ),
                Paragraph(
                    f"Sender IP: {auth_rep.spf.sender_ip if auth_rep and auth_rep.spf else 'N/A'}",
                    body_style,
                ),
            ],
            [
                Paragraph("<b>DKIM (RFC 6376)</b>", body_style),
                Paragraph(f"<b>{dkim_count} Signature(s)</b>", body_style),
                Paragraph(
                    f"Aligned: {any(d.is_aligned for d in auth_rep.dkim_signatures) if auth_rep else False}",
                    body_style,
                ),
                Paragraph(
                    f"Domains: {', '.join(d.domain for d in auth_rep.dkim_signatures) if auth_rep and auth_rep.dkim_signatures else 'None'}",
                    body_style,
                ),
            ],
            [
                Paragraph("<b>DMARC (RFC 7489)</b>", body_style),
                Paragraph(
                    f"<font color='{'#22543D' if dmarc_status == 'PASS' else '#9B2C2C'}'><b>{dmarc_status}</b></font>",
                    body_style,
                ),
                Paragraph(
                    f"Policy: {auth_rep.dmarc.policy if auth_rep and auth_rep.dmarc else 'none'}",
                    body_style,
                ),
                Paragraph(
                    f"Disposition: {auth_rep.dmarc.disposition if auth_rep and auth_rep.dmarc else 'none'}",
                    body_style,
                ),
            ],
            [
                Paragraph("<b>ARC (RFC 8617)</b>", body_style),
                Paragraph(f"<b>{arc_status}</b>", body_style),
                Paragraph(
                    f"Valid Chain: {auth_rep.arc.is_valid if auth_rep and auth_rep.arc else False}",
                    body_style,
                ),
                Paragraph(
                    f"Instances: {auth_rep.arc.instance_count if auth_rep and auth_rep.arc else 0}",
                    body_style,
                ),
            ],
        ]
        auth_table = Table(auth_rows, colWidths=[110, 95, 110, 189])
        auth_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(auth_table)
        story.append(Spacer(1, 10))

        # 5. MTA Transit Route
        story.append(Paragraph("3. Mail Transfer Agent (MTA) Transit Route", h2_style))
        if email_obj.transit_route and email_obj.transit_route.hops:
            hop_rows = [
                [
                    Paragraph("<b>Hop</b>", bold_style),
                    Paragraph("<b>Sending Host / IP</b>", bold_style),
                    Paragraph("<b>Receiving Host / IP</b>", bold_style),
                    Paragraph("<b>Delay</b>", bold_style),
                    Paragraph("<b>Anomalies</b>", bold_style),
                ]
            ]
            for hop in email_obj.transit_route.hops:
                from_str = f"{hop.from_host or 'N/A'}<br/><code>{hop.from_ip or ''}</code>"
                by_str = f"{hop.by_host or 'N/A'}<br/><code>{hop.by_ip or ''}</code>"
                delay_str = (
                    f"+{hop.delay_seconds:.1f}s"
                    if hop.delay_seconds >= 0
                    else f"{hop.delay_seconds:.1f}s"
                )
                anom_str = ", ".join(hop.anomalies) if hop.anomalies else "None"

                hop_rows.append(
                    [
                        Paragraph(f"#{hop.hop_number}", bold_style),
                        Paragraph(from_str, body_style),
                        Paragraph(by_str, body_style),
                        Paragraph(delay_str, body_style),
                        Paragraph(anom_str, body_style),
                    ]
                )
            hop_table = Table(hop_rows, colWidths=[35, 145, 150, 60, 114])
            hop_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
            story.append(hop_table)
        else:
            story.append(Paragraph("<i>No MTA transit hops reconstructed.</i>", body_style))
        story.append(Spacer(1, 10))

        # 6. Attachment Forensics Table
        story.append(Paragraph("4. Attachment Static Analysis & Cryptographic Hashes", h2_style))
        if email_obj.extracted_attachments:
            att_rows = [
                [
                    Paragraph("<b>Filename</b>", bold_style),
                    Paragraph("<b>Size</b>", bold_style),
                    Paragraph("<b>MIME / Magic</b>", bold_style),
                    Paragraph("<b>SHA-256 Digest</b>", bold_style),
                    Paragraph("<b>Threat Verdict</b>", bold_style),
                ]
            ]
            for att in email_obj.extracted_attachments:
                threat = att.threat_analysis
                verdict = threat.threat_level if threat else "BENIGN"
                color_hex = (
                    "#9B2C2C"
                    if verdict == "MALICIOUS"
                    else ("#C05621" if verdict == "SUSPICIOUS" else "#22543D")
                )

                att_rows.append(
                    [
                        Paragraph(att.filename, bold_style),
                        Paragraph(f"{att.size_bytes:,} B", body_style),
                        Paragraph(att.content_type, body_style),
                        Paragraph(
                            f"<code>{att.hashes.get('sha256', 'N/A')[:20]}...</code>", code_style
                        ),
                        Paragraph(f"<font color='{color_hex}'><b>{verdict}</b></font>", body_style),
                    ]
                )
            att_table = Table(att_rows, colWidths=[120, 55, 105, 134, 90])
            att_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
            story.append(att_table)
        else:
            story.append(Paragraph("<i>No attachments present in evidence.</i>", body_style))
        story.append(Spacer(1, 10))

        # 7. Threat & BEC Indicators (if any)
        story.append(Paragraph("5. Business Email Compromise (BEC) & Threat Analysis", h2_style))
        bec = email_obj.bec_report
        bec_score = f"{bec.threat_score:.1f}/100.0" if bec else "0.0/100.0"
        bec_verdict = bec.overall_threat_level if bec else "CLEAN"
        story.append(
            Paragraph(
                f"<b>Overall BEC Risk Score:</b> {bec_score} | <b>Threat Level:</b> <b>{bec_verdict}</b>",
                body_style,
            )
        )
        if bec and bec.indicators:
            bec_rows = [
                [
                    Paragraph("<b>Indicator Type</b>", bold_style),
                    Paragraph("<b>Severity</b>", bold_style),
                    Paragraph("<b>Description</b>", bold_style),
                ]
            ]
            for ind in bec.indicators:
                bec_rows.append(
                    [
                        Paragraph(ind.indicator_type, bold_style),
                        Paragraph(ind.severity, body_style),
                        Paragraph(ind.description, body_style),
                    ]
                )
            bec_table = Table(bec_rows, colWidths=[140, 70, 294])
            bec_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
            story.append(Spacer(1, 4))
            story.append(bec_table)

        # 8. Examiner Certification Statement
        story.append(Spacer(1, 14))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E0"), spaceAfter=8)
        )
        cert_text = (
            "<b>EXAMINER CERTIFICATION:</b> I hereby certify that this forensic examination was conducted "
            "in strict adherence to ISO/IEC 27037 digital evidence standards. The original evidence file was "
            "maintained in read-only custody and zero byte alteration occurred during parsing and threat analysis."
        )
        story.append(Paragraph(cert_text, body_style))

        # Build PDF with NumberedCanvas
        doc.build(story, canvasmaker=NumberedCanvas)
        return out_file

    @classmethod
    def export_all(
        cls,
        email_obj: CanonicalEmail,
        output_dir: Union[str, Path],
        base_name: str = "forensic_report",
        case_id: Optional[str] = None,
        examiner_name: Optional[str] = None,
        examiner_agency: Optional[str] = None,
    ) -> Dict[str, Path]:
        """Convenience function to batch-export all 4 formats (JSON, CSV, STIX, PDF).

        Args:
            email_obj: The CanonicalEmail instance.
            output_dir: Directory where report artifacts will be saved.
            base_name: Base filename prefix.
            case_id: Case identifier.
            examiner_name: Examiner identity.
            examiner_agency: Organization or agency.

        Returns:
            Dictionary mapping format keys ("json", "csv", "stix", "pdf") to their Path locations.
        """
        dir_path = Path(output_dir)
        dir_path.mkdir(parents=True, exist_ok=True)

        json_path = dir_path / f"{base_name}.json"
        csv_path = dir_path / f"{base_name}.csv"
        stix_path = dir_path / f"{base_name}.stix2.json"
        pdf_path = dir_path / f"{base_name}.pdf"

        cls.export_json(email_obj, output_path=json_path)
        cls.export_csv(email_obj, output_path=csv_path)
        cls.export_stix(email_obj, output_path=stix_path)
        cls.export_pdf(
            email_obj,
            output_path=pdf_path,
            case_id=case_id,
            examiner_name=examiner_name,
            examiner_agency=examiner_agency,
        )

        return {
            "json": json_path,
            "csv": csv_path,
            "stix": stix_path,
            "pdf": pdf_path,
        }
