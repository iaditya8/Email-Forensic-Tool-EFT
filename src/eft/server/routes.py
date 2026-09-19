"""FastAPI route handlers for EFT Air-Gapped Web Server."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, Response, UploadFile
from fastapi.responses import HTMLResponse

from eft.analysis.attachment_scanner import AttachmentThreatScanner
from eft.analysis.auth_verifier import AuthenticationVerifier
from eft.analysis.bec_detector import BECDetector
from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.analysis.obfuscation_detector import ContentObfuscationDetector
from eft.analysis.relay_analyzer import RelayAnalyzer
from eft.analysis.threat_scorer import ThreatScorer
from eft.analysis.url_analyzer import URLAnalyzer
from eft.core.integrity import compute_file_hashes
from eft.ingestion.attachment_extractor import AttachmentExtractor
from eft.ingestion.engine import EmailIngester
from eft.ingestion.header_decomposer import HeaderDecomposer
from eft.models.canonical import CanonicalEmail
from eft.reporting.custody import ChainOfCustodyManager
from eft.reporting.exporter import ForensicReportExporter
from eft.reporting.timeline import TimelineGenerator
from eft.ui.inspector import EmailInspector
from eft.ui.map_visualizer import TransitMapVisualizer

router = APIRouter()

TEMPLATES_DIR = Path(__file__).parent / "templates"
CORPUS_DIR = Path(__file__).parent.parent.parent.parent / "tests" / "fixtures" / "corpus"


def _run_full_analysis(
    email: CanonicalEmail,
    threat_hashes: Optional[set[str]] = None,
    protected_domains: Optional[List[str]] = None,
    protected_executives: Optional[List[Dict[str, str]]] = None,
) -> CanonicalEmail:
    """Execute complete DFIR analysis pipeline on a CanonicalEmail object."""
    decomp = HeaderDecomposer.decompose(email.ordered_headers)
    email.header_decomposition = decomp

    # 1. Attachment Extraction
    email.extracted_attachments = AttachmentExtractor.extract_from_email(email, save_to_disk=False)

    # 2. Auth Verifier
    email.authentication_report = AuthenticationVerifier.verify_email(email)

    # 3. Relay Analyzer & GeoIP
    transit_route = RelayAnalyzer.reconstruct_route(decomp.received_headers)
    net_service = NetworkIntelligenceService()
    email.transit_route = net_service.enrich_route(transit_route)

    # 4. URL Analyzer
    email.url_report = URLAnalyzer().extract_urls(email)

    # 5. BEC & Impersonation
    email.bec_report = BECDetector().detect(
        email,
        protected_domains=protected_domains,
        protected_executives=protected_executives,
    )

    # 6. Obfuscation Detector
    email.obfuscation_report = ContentObfuscationDetector().detect(email)

    # 7. Attachment Threat Scanner
    scanner = AttachmentThreatScanner()
    email.attachment_threat_report = scanner.scan_email(
        email, known_bad_hashes=threat_hashes or set()
    )

    # 8. Timeline Synthesis
    email.timeline_report = TimelineGenerator.generate_timeline(email)

    return email


@router.get("/", response_class=HTMLResponse)
def get_dashboard() -> HTMLResponse:
    """Serve the single-page air-gapped forensic dashboard."""
    index_file = TEMPLATES_DIR / "index.html"
    if not index_file.is_file():
        raise HTTPException(status_code=404, detail="Dashboard template not found")
    return HTMLResponse(content=index_file.read_text(encoding="utf-8", errors="replace"))


@router.get("/health")
def health_check() -> Dict[str, Any]:
    """Forensic engine healthcheck and air-gapped readiness probe."""
    return {
        "status": "ok",
        "service": "Email Forensic Tool (EFT)",
        "version": "1.0.0",
        "air_gapped": True,
        "iso_27037_compliant": True,
    }


@router.get("/api/samples")
def list_samples() -> List[Dict[str, str]]:
    """List available forensic corpus samples."""
    samples = []
    c_dir = CORPUS_DIR if CORPUS_DIR.is_dir() else Path("tests/fixtures/corpus")
    if c_dir.is_dir():
        for p in sorted(c_dir.glob("*")):
            if p.suffix.lower() in [".eml", ".msg", ".mbox"]:
                samples.append({"filename": p.name, "path": p.name})
    return samples


@router.get("/api/sample/{sample_name}")
def analyze_sample(sample_name: str) -> Dict[str, Any]:
    """Directly analyze a sample from the built-in forensic corpus."""
    target_file = CORPUS_DIR / sample_name
    if not target_file.is_file():
        # Search fallback relative to repo root
        target_file = Path("tests/fixtures/corpus") / sample_name
        if not target_file.is_file():
            raise HTTPException(status_code=404, detail=f"Sample '{sample_name}' not found")

    hashes = compute_file_hashes(target_file)
    ingester = EmailIngester()
    result = ingester.ingest_file(target_file)

    if not result.success or not result.messages:
        raise HTTPException(status_code=400, detail=f"Failed to ingest sample: {result.errors}")

    email = _run_full_analysis(result.messages[0])
    risk = ThreatScorer.calculate_composite_risk(email)

    return {
        "success": True,
        "sample_name": sample_name,
        "sha256": hashes["sha256"],
        "hashes": hashes,
        "email": json.loads(ForensicReportExporter.export_json(email)),
        "risk_report": json.loads(risk.model_dump_json()),
    }


@router.post("/api/analyze")
async def analyze_uploaded_file(
    file: UploadFile = File(...),
    case_id: str = Form("CASE-2026-AUTO"),
    examiner: str = Form("Forensic Examiner"),
) -> Dict[str, Any]:
    """Ingest uploaded evidence file (.eml, .msg, .mbox) and run forensic pipeline."""
    suffix = Path(file.filename or "evidence.eml").suffix.lower()
    if suffix not in [".eml", ".msg", ".mbox"]:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{suffix}'. Supported formats: .eml, .msg, .mbox",
        )

    content = await file.read()

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        hashes = compute_file_hashes(tmp_path)
        manifest = ChainOfCustodyManager.create_manifest(
            file_path=tmp_path,
            case_id=case_id,
            evidence_id=f"EVID-{tmp_path.stem}",
            examiner_name=examiner,
        )

        ingester = EmailIngester()
        result = ingester.ingest_file(tmp_path)

        if not result.success or not result.messages:
            raise HTTPException(status_code=400, detail=f"Ingestion failed: {result.errors}")

        email = _run_full_analysis(result.messages[0])
        risk = ThreatScorer.calculate_composite_risk(email)

        return {
            "success": True,
            "filename": file.filename,
            "sha256": hashes["sha256"],
            "hashes": hashes,
            "manifest": json.loads(manifest.model_dump_json()),
            "email": json.loads(ForensicReportExporter.export_json(email)),
            "risk_report": json.loads(risk.model_dump_json()),
        }
    finally:
        if tmp_path.is_file():
            tmp_path.unlink(missing_ok=True)


@router.post("/api/export/{format_type}")
async def export_report_endpoint(
    format_type: str,
    payload: Dict[str, Any],
) -> Response:
    """Generate on-the-fly downloadable forensic evidence reports (PDF, JSON, CSV, STIX)."""
    raw_email_data = payload.get("email") or payload
    email = CanonicalEmail.model_validate(raw_email_data)

    fmt = format_type.lower().strip()
    if fmt == "json":
        json_str = ForensicReportExporter.export_json(email)
        return Response(content=json_str, media_type="application/json")

    elif fmt == "csv":
        csv_str = ForensicReportExporter.export_csv(email)
        return Response(content=csv_str, media_type="text/csv")

    elif fmt == "stix":
        stix_str = ForensicReportExporter.export_stix(email)
        return Response(content=stix_str, media_type="application/json")

    elif fmt == "pdf":
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf:
            tmp_p = Path(tmp_pdf.name)

        try:
            ForensicReportExporter.export_pdf(
                email,
                output_path=tmp_p,
                case_id=payload.get("case_id", "CASE-2026"),
                examiner_name=payload.get("examiner", "Forensic Examiner"),
            )
            pdf_bytes = tmp_p.read_bytes()
            return Response(content=pdf_bytes, media_type="application/pdf")
        finally:
            tmp_p.unlink(missing_ok=True)

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format '{format_type}'. Supported formats: pdf, json, csv, stix",
        )


@router.post("/api/inspect", response_class=HTMLResponse)
def render_inspector_endpoint(payload: Dict[str, Any]) -> HTMLResponse:
    """Render standalone air-gapped dual-pane HTML email & header inspector."""
    raw_email_data = payload.get("email") or payload
    email = CanonicalEmail.model_validate(raw_email_data)
    html_content = EmailInspector.generate_inspector_html(email)
    return HTMLResponse(content=html_content)


@router.post("/api/map", response_class=Response)
def render_transit_map_endpoint(payload: Dict[str, Any]) -> Response:
    """Render interactive SVG geodesic world transit map."""
    raw_email_data = payload.get("email") or payload
    email = CanonicalEmail.model_validate(raw_email_data)
    if not email.transit_route:
        return Response(
            content="<svg width='100%' height='60'><text x='20' y='35' fill='#94a3b8'>No transit hops</text></svg>",
            media_type="image/svg+xml",
        )

    svg_map = TransitMapVisualizer.generate_svg_map(email.transit_route)
    return Response(content=svg_map, media_type="image/svg+xml")


@router.post("/api/verify")
def verify_evidence_endpoint(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Cryptographically verify evidence file hash against expected value or manifest."""
    current_sha = payload.get("current_sha256")
    expected_sha = payload.get("expected_sha256")

    if not current_sha or not expected_sha:
        raise HTTPException(
            status_code=400,
            detail="Both 'current_sha256' and 'expected_sha256' are required.",
        )

    match = current_sha.strip().lower() == expected_sha.strip().lower()
    return {
        "verified": match,
        "current_sha256": current_sha,
        "expected_sha256": expected_sha,
        "status": "IMMUTABILITY VERIFIED" if match else "TAMPERING DETECTED",
    }
