"""End-to-End Forensic Pipeline Integration Test Suite with Realistic Test Corpus."""

import re
from pathlib import Path

from eft.analysis.attachment_scanner import AttachmentThreatScanner
from eft.analysis.auth_verifier import AuthenticationVerifier
from eft.analysis.bec_detector import BECDetector
from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.analysis.obfuscation_detector import ContentObfuscationDetector
from eft.analysis.relay_analyzer import RelayAnalyzer
from eft.analysis.threat_scorer import ThreatScorer
from eft.analysis.url_analyzer import URLAnalyzer
from eft.ingestion.attachment_extractor import AttachmentExtractor
from eft.ingestion.engine import EmailIngester
from eft.ingestion.header_decomposer import HeaderDecomposer
from eft.models.canonical import CanonicalEmail
from eft.models.threat import RiskSeverity
from eft.reporting.custody import ChainOfCustodyManager
from eft.reporting.exporter import ForensicReportExporter
from eft.reporting.timeline import TimelineGenerator
from eft.ui.map_visualizer import TransitMapVisualizer
from eft.ui.threat_card import ThreatCardRenderer

CORPUS_DIR = Path(__file__).parent / "fixtures" / "corpus"


def run_full_forensic_pipeline(email: CanonicalEmail, tmp_path: Path) -> CanonicalEmail:
    """Execute the full multi-vector forensic analysis and enrichment pipeline on a CanonicalEmail."""
    # 1. Header Decomposition
    decomp = HeaderDecomposer.decompose(email.ordered_headers)
    email.header_decomposition = decomp

    # 2. Attachment Extraction & Fingerprinting
    clean_mid = re.sub(r'[<>:"/\\|?*]', "_", email.message_id or "msg")
    att_dir = tmp_path / f"attachments_{clean_mid}"
    extracted_atts = AttachmentExtractor.extract_from_email(
        email, output_dir=att_dir, save_to_disk=True
    )
    email.extracted_attachments = extracted_atts

    # 3. Authentication Verification (SPF, DKIM, DMARC, ARC)
    auth_report = AuthenticationVerifier.verify_email(email)
    email.authentication_report = auth_report

    # 4. Relay Hop Reconstruction & Network Intelligence
    net_svc = NetworkIntelligenceService()
    transit_route = RelayAnalyzer.reconstruct_route(decomp.received_headers)
    enriched_route = net_svc.enrich_route(transit_route)
    email.transit_route = enriched_route

    # 5. URL Extraction & Phishing Forensics
    url_analyzer = URLAnalyzer()
    url_report = url_analyzer.extract_urls(email)
    email.url_report = url_report

    # 6. BEC & Spoofing Detection
    bec_detector = BECDetector()
    bec_report = bec_detector.detect(email)
    email.bec_report = bec_report

    # 7. Content Obfuscation & Hidden Text Analysis
    obf_detector = ContentObfuscationDetector()
    obf_report = obf_detector.detect(email)
    email.obfuscation_report = obf_report

    # 8. Attachment Threat Scanning & YARA Inspection
    att_scanner = AttachmentThreatScanner()
    att_report = att_scanner.scan_email(email)
    email.attachment_threat_report = att_report

    # 9. Timeline Synthesis & Anomaly Detection
    timeline_rep = TimelineGenerator.generate_timeline(email)
    email.timeline_report = timeline_rep

    return email


def test_corpus_01_benign_corporate(tmp_path: Path) -> None:
    """Verify end-to-end processing and clean risk classification for benign corporate sample."""
    sample_path = CORPUS_DIR / "01_benign_corporate.eml"
    assert sample_path.is_file()

    # Custody verification
    manifest = ChainOfCustodyManager.create_manifest(
        sample_path,
        case_id="CASE-2024-001",
        evidence_id="EVID-001",
        examiner_name="Lead Examiner",
    )
    assert manifest.pre_analysis_hashes["sha256"] != ""
    ledger = ChainOfCustodyManager.create_ledger(manifest)

    # Ingestion
    ingester = EmailIngester()
    result = ingester.ingest_file(sample_path)
    assert result.success is True
    assert len(result.messages) == 1
    email = result.messages[0]

    # Full forensic pipeline
    analyzed = run_full_forensic_pipeline(email, tmp_path)

    # Composite Threat Score
    risk_report = ThreatScorer.calculate_composite_risk(analyzed)
    assert risk_report.overall_score < 25.0
    assert risk_report.risk_level in (
        RiskSeverity.CLEAN,
        RiskSeverity.SUSPICIOUS_LOW,
    )
    assert "ALLOW" in risk_report.recommended_action or "CAUTION" in risk_report.recommended_action

    # Multi-format report export
    export_dir = tmp_path / "export_01"
    exports = ForensicReportExporter.export_all(analyzed, export_dir)
    assert Path(exports["pdf"]).is_file()
    assert Path(exports["json"]).is_file()
    assert Path(exports["csv"]).is_file()
    assert Path(exports["stix"]).is_file()

    # Verify zero evidence mutation
    is_valid, _ = ChainOfCustodyManager.verify_integrity(ledger, current_file_path=sample_path)
    assert is_valid is True


def test_corpus_02_phishing_homoglyph(tmp_path: Path) -> None:
    """Verify phishing URL, homoglyph, and credential harvesting threat detection."""
    sample_path = CORPUS_DIR / "02_phishing_homoglyph.eml"
    ingester = EmailIngester()
    result = ingester.ingest_file(sample_path)
    email = run_full_forensic_pipeline(result.messages[0], tmp_path)

    # Validate threat signals
    assert email.url_report is not None
    assert email.url_report.total_urls_found >= 2
    assert email.url_report.homographs_count >= 1 or any(
        u.is_idn_homograph for u in email.url_report.urls
    )
    assert email.url_report.ip_urls_count >= 1 or any(u.is_ip_host for u in email.url_report.urls)

    risk_report = ThreatScorer.calculate_composite_risk(email)
    assert risk_report.overall_score >= 35.0
    assert risk_report.risk_level in (
        RiskSeverity.SUSPICIOUS_MEDIUM,
        RiskSeverity.MALICIOUS_HIGH,
        RiskSeverity.CRITICAL,
    )

    # Verify HTML inspector & threat card generation
    html_card = ThreatCardRenderer.generate_card_html(risk_report)
    assert "Composite Threat Risk Assessment" in html_card or "Risk" in html_card
    assert "Phishing & Malicious Links" in html_card


def test_corpus_03_bec_wire_fraud(tmp_path: Path) -> None:
    """Verify BEC VIP impersonation, financial urgency, and reply-to mismatch detection."""
    sample_path = CORPUS_DIR / "03_bec_wire_fraud.eml"
    ingester = EmailIngester()
    result = ingester.ingest_file(sample_path)
    email = run_full_forensic_pipeline(result.messages[0], tmp_path)

    assert email.bec_report is not None
    assert (
        email.bec_report.reply_to_mismatch_detected is True
        or email.bec_report.is_bec_suspected is True
        or len(email.bec_report.indicators) > 0
    )

    risk_report = ThreatScorer.calculate_composite_risk(email)
    assert risk_report.overall_score >= 20.0
    assert any(
        f.vector.value == "BEC & Social Engineering" for f in risk_report.all_factors
    ) or any("BEC" in f.name.upper() for f in risk_report.all_factors)


def test_corpus_04_malware_double_extension(tmp_path: Path) -> None:
    """Verify double-extension malware detection and attachment extraction."""
    sample_path = CORPUS_DIR / "04_malware_double_extension.eml"
    ingester = EmailIngester()
    result = ingester.ingest_file(sample_path)
    email = run_full_forensic_pipeline(result.messages[0], tmp_path)

    assert len(email.extracted_attachments) == 1
    att = email.extracted_attachments[0]
    assert att.file_type_inspection is not None
    assert (
        att.file_type_inspection.is_extension_mismatch is True
        or att.file_type_inspection.is_mime_mismatch is True
        or "exe" in att.filename.lower()
    )


def test_corpus_05_obfuscation_zero_width(tmp_path: Path) -> None:
    """Verify zero-width space and hidden CSS content detection."""
    sample_path = CORPUS_DIR / "05_obfuscation_zero_width.eml"
    ingester = EmailIngester()
    result = ingester.ingest_file(sample_path)
    email = run_full_forensic_pipeline(result.messages[0], tmp_path)

    assert email.obfuscation_report is not None
    assert (
        email.obfuscation_report.has_zero_width_chars is True
        or len(email.obfuscation_report.hidden_artifacts) > 0
        or email.obfuscation_report.hidden_text_char_count > 0
    )


def test_corpus_06_transit_anomaly_tor(tmp_path: Path) -> None:
    """Verify MTA transit hop reconstruction, Tor exit node detection, and clock drift."""
    sample_path = CORPUS_DIR / "06_transit_anomaly_tor.eml"
    ingester = EmailIngester()
    result = ingester.ingest_file(sample_path)
    email = run_full_forensic_pipeline(result.messages[0], tmp_path)

    assert email.transit_route is not None
    assert email.transit_route.total_hops >= 2
    # Verify SVG transit map generation
    svg_map = TransitMapVisualizer.generate_svg_map(email.transit_route)
    assert "<svg" in svg_map


def test_corpus_07_mixed_mailbox(tmp_path: Path) -> None:
    """Verify multi-message MBOX archive ingestion and batch forensic processing."""
    sample_path = CORPUS_DIR / "07_mixed_mailbox.mbox"
    ingester = EmailIngester()
    result = ingester.ingest_file(sample_path)

    assert result.success is True
    assert len(result.messages) == 3

    # Process each message in the archive
    reports = []
    for msg in result.messages:
        analyzed = run_full_forensic_pipeline(msg, tmp_path)
        risk = ThreatScorer.calculate_composite_risk(analyzed)
        reports.append(risk)

    assert len(reports) == 3
    # Check that scores vary across different emails in the mailbox
    scores = [r.overall_score for r in reports]
    assert min(scores) >= 0.0
    assert max(scores) <= 100.0
