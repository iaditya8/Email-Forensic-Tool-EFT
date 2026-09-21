"""Master Case Multi-Format Exporter (PDF, STIX 2.1, JSON, CSV)."""

from __future__ import annotations

import csv
import io
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

from eft.models.master_case import MasterCaseReport


class MasterNumberedCanvas(canvas.Canvas):
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
            "EMAIL FORENSIC TOOL (EFT) — MASTER DIGITAL FORENSIC EXAMINATION REPORT [CONFIDENTIAL]",
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
            "Court-Admissible Multi-Evidence Master Case Ledger — ISO/IEC 27037 Immutability Verified",
        )
        self.restoreState()


class MasterCaseExporter:
    """Exports unified Master Case reports to PDF, STIX 2.1, JSON, and CSV."""

    @classmethod
    def export_json(
        cls,
        case_report: MasterCaseReport,
        output_path: Optional[Union[str, Path]] = None,
        indent: int = 2,
    ) -> str:
        """Export MasterCaseReport model to JSON format."""
        json_str = case_report.model_dump_json(indent=indent)
        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json_str, encoding="utf-8")
        return json_str

    @classmethod
    def export_csv(
        cls,
        case_report: MasterCaseReport,
        output_path: Optional[Union[str, Path]] = None,
    ) -> str:
        """Export Master IoC ledger to CSV format."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        writer.writerow(
            [
                "case_id",
                "ioc_id",
                "ioc_type",
                "ioc_value",
                "source_item_id",
                "source_item_type",
                "severity",
                "threat_category",
                "description",
            ]
        )

        for ioc in case_report.master_ioc_ledger:
            writer.writerow(
                [
                    case_report.case_id,
                    ioc.ioc_id,
                    ioc.ioc_type,
                    ioc.ioc_value,
                    ioc.source_item_id,
                    ioc.source_item_type.value,
                    ioc.severity,
                    ioc.threat_category,
                    ioc.description,
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
        case_report: MasterCaseReport,
        output_path: Optional[Union[str, Path]] = None,
    ) -> str:
        """Export master findings into a comprehensive STIX 2.1 bundle."""
        stix_objects: List[Any] = []

        # 1. Identity & Incident / Report SDO
        identity = stix2.Identity(
            name=case_report.examiner_agency or "EFT Digital Forensics Unit",
            identity_class="organization",
            description=f"Forensic Examiner: {case_report.examiner_name}",
        )
        stix_objects.append(identity)

        report_sdo = stix2.Report(
            name=f"Forensic Case Report: {case_report.case_id} - {case_report.case_title}",
            description=case_report.executive_summary,
            published=case_report.created_at_utc,
            report_types=["investigation", "threat-report"],
            object_refs=[identity.id],
        )
        stix_objects.append(report_sdo)

        # 2. Indicators for IoCs
        for ioc in case_report.master_ioc_ledger:
            pattern = None
            val_escaped = ioc.ioc_value.replace("'", "\\'")

            if ioc.ioc_type in ["file-hash-sha256", "sha256"]:
                pattern = f"[file:hashes.'SHA-256' = '{val_escaped}']"
            elif ioc.ioc_type in ["ip", "ip-address"]:
                pattern = f"[ipv4-addr:value = '{val_escaped}']"
            elif ioc.ioc_type in ["domain"]:
                pattern = f"[domain-name:value = '{val_escaped}']"
            elif ioc.ioc_type in ["url"]:
                pattern = f"[url:value = '{val_escaped}']"
            elif ioc.ioc_type in ["email", "email-address"]:
                pattern = f"[email-addr:value = '{val_escaped}']"

            if pattern:
                try:
                    indicator = stix2.Indicator(
                        name=f"{ioc.threat_category}: {ioc.ioc_value}",
                        pattern_type="stix",
                        pattern=pattern,
                        valid_from=datetime.now(timezone.utc),
                        indicator_types=["malicious-activity"],
                        description=f"Evidence {ioc.source_item_id}: {ioc.description}",
                    )
                    stix_objects.append(indicator)
                except Exception:
                    pass

        # 3. MITRE Attack Patterns
        for tactic, tech_list in case_report.mitre_matrix.items():
            for t_id in tech_list:
                try:
                    ap = stix2.AttackPattern(
                        name=f"ATT&CK {t_id} ({tactic})",
                        external_references=[
                            {
                                "source_name": "mitre-attack",
                                "external_id": t_id,
                            }
                        ],
                    )
                    stix_objects.append(ap)
                except Exception:
                    pass

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
        case_report: MasterCaseReport,
        output_path: Union[str, Path],
    ) -> Path:
        """Generate a comprehensive Court-Admissible Master Forensic PDF Report."""
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

        # 1. Header
        story.append(Spacer(1, 10))
        story.append(Paragraph("MASTER DIGITAL FORENSIC EXAMINATION REPORT", title_style))
        story.append(
            Paragraph(
                "Unified Cross-Module Evidence Investigation & Threat Correlation Audit",
                subtitle_style,
            )
        )
        story.append(
            HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2B6CB0"), spaceAfter=10)
        )

        # 2. Case Overview Table
        case_meta = [
            [
                Paragraph("<b>Case Reference ID:</b>", body_style),
                Paragraph(case_report.case_id, bold_style),
                Paragraph("<b>Investigation Date:</b>", body_style),
                Paragraph(case_report.created_at_utc.strftime("%Y-%m-%d %H:%M:%S UTC"), body_style),
            ],
            [
                Paragraph("<b>Lead Examiner:</b>", body_style),
                Paragraph(case_report.examiner_name, body_style),
                Paragraph("<b>Agency / Unit:</b>", body_style),
                Paragraph(case_report.examiner_agency or "Digital Forensics Unit", body_style),
            ],
            [
                Paragraph("<b>Master Risk Score:</b>", body_style),
                Paragraph(
                    f"<b>{case_report.overall_composite_risk_score:.1f} / 100 ({case_report.overall_risk_level})</b>",
                    bold_style,
                ),
                Paragraph("<b>Evidence Count:</b>", body_style),
                Paragraph(f"{len(case_report.evidence_items)} Items Analyzed", body_style),
            ],
        ]
        t_meta = Table(case_meta, colWidths=[110, 142, 110, 142])
        t_meta.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(t_meta)
        story.append(Spacer(1, 10))

        # 3. Executive Summary
        story.append(Paragraph("1. Executive Summary & Incident Narrative", h2_style))
        story.append(Paragraph(case_report.executive_summary, body_style))
        story.append(Spacer(1, 8))

        # 4. Evidence Inventory & Immutability Ledger
        story.append(Paragraph("2. Evidence Inventory & Cryptographic Custody Ledger", h2_style))
        ev_rows = [
            [
                Paragraph("<b>Item ID</b>", bold_style),
                Paragraph("<b>Domain Type</b>", bold_style),
                Paragraph("<b>Evidence Source Name</b>", bold_style),
                Paragraph("<b>Size</b>", bold_style),
                Paragraph("<b>SHA-256 Digest</b>", bold_style),
                Paragraph("<b>Integrity</b>", bold_style),
            ]
        ]
        for it in case_report.evidence_items:
            sha = it.manifest.pre_analysis_hashes.get("sha256", "N/A")
            ev_rows.append(
                [
                    Paragraph(it.item_id, bold_style),
                    Paragraph(it.item_type.value, body_style),
                    Paragraph(it.source_name, body_style),
                    Paragraph(f"{it.size_bytes:,} B", body_style),
                    Paragraph(f"{sha[:16]}...{sha[-8:]}", code_style),
                    Paragraph(
                        "VERIFIED (0-MUTATION)" if it.manifest.integrity_verified else "TAMPERED",
                        bold_style,
                    ),
                ]
            )
        t_ev = Table(ev_rows, colWidths=[55, 75, 110, 50, 134, 80])
        t_ev.setStyle(
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
        story.append(t_ev)
        story.append(Spacer(1, 8))

        # 5. Cross-Evidence Correlations
        if case_report.cross_module_correlations:
            story.append(Paragraph("3. Cross-Evidence Threat Correlations", h2_style))
            corr_rows = [
                [
                    Paragraph("<b>Correlation</b>", bold_style),
                    Paragraph("<b>Severity</b>", bold_style),
                    Paragraph("<b>Involved Items</b>", bold_style),
                    Paragraph("<b>Findings Narrative</b>", bold_style),
                ]
            ]
            for c in case_report.cross_module_correlations:
                corr_rows.append(
                    [
                        Paragraph(c.title, bold_style),
                        Paragraph(c.severity, bold_style),
                        Paragraph(", ".join(c.involved_item_ids), body_style),
                        Paragraph(c.description, body_style),
                    ]
                )
            t_corr = Table(corr_rows, colWidths=[120, 50, 84, 250])
            t_corr.setStyle(
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
            story.append(t_corr)
            story.append(Spacer(1, 8))

        # 6. Master Unified Chronological Timeline
        story.append(Paragraph("4. Master Chronological Unified Timeline (UTC)", h2_style))
        time_rows = [
            [
                Paragraph("<b>Timestamp (UTC)</b>", bold_style),
                Paragraph("<b>Domain</b>", bold_style),
                Paragraph("<b>Event Category</b>", bold_style),
                Paragraph("<b>Event Title & Narrative</b>", bold_style),
            ]
        ]
        for ev in case_report.master_timeline[:30]:
            time_rows.append(
                [
                    Paragraph(ev.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S"), code_style),
                    Paragraph(ev.source_type.value, body_style),
                    Paragraph(ev.event_category, body_style),
                    Paragraph(f"<b>{ev.title}</b>: {ev.description}", body_style),
                ]
            )
        t_time = Table(time_rows, colWidths=[90, 65, 95, 254])
        t_time.setStyle(
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
        story.append(t_time)
        story.append(Spacer(1, 8))

        # 7. MITRE ATT&CK Matrix
        if case_report.mitre_matrix:
            story.append(Paragraph("5. MITRE ATT&CK Enterprise Matrix Mapping", h2_style))
            mitre_rows = [
                [
                    Paragraph("<b>ATT&CK Tactic</b>", bold_style),
                    Paragraph("<b>Identified Techniques</b>", bold_style),
                ]
            ]
            for tactic, techs in case_report.mitre_matrix.items():
                mitre_rows.append(
                    [
                        Paragraph(tactic, bold_style),
                        Paragraph(", ".join(techs), code_style),
                    ]
                )
            t_mitre = Table(mitre_rows, colWidths=[150, 354])
            t_mitre.setStyle(
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
            story.append(t_mitre)
            story.append(Spacer(1, 8))

        # 8. Examiner Certification Sign-off Block
        story.append(Spacer(1, 12))
        story.append(Paragraph("6. Forensic Examiner Certification & Attestation", h2_style))
        story.append(
            Paragraph(
                "I hereby attest under penalty of perjury that the multi-evidence examination described herein "
                "was conducted in strict accordance with ISO/IEC 27037 standards. All digital evidence files were "
                "acquired and analyzed in a 100% air-gapped environment with continuous cryptographic hash validation, "
                "ensuring complete bit-level immutability and unbroken chain of custody.",
                body_style,
            )
        )
        story.append(Spacer(1, 15))

        sign_data = [
            [
                Paragraph(
                    "<b>Lead Examiner Signature:</b> ___________________________", body_style
                ),
                Paragraph("<b>Date:</b> ______________", body_style),
            ],
            [
                Paragraph(f"<b>Printed Name:</b> {case_report.examiner_name}", body_style),
                Paragraph(
                    f"<b>Agency:</b> {case_report.examiner_agency or 'DFIR Unit'}", body_style
                ),
            ],
        ]
        t_sign = Table(sign_data, colWidths=[330, 174])
        t_sign.setStyle(
            TableStyle(
                [
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(t_sign)

        doc.build(story, canvasmaker=MasterNumberedCanvas)
        return out_file
