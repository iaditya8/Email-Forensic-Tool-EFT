"""Comprehensive test suite for ThreatScorer and ThreatCardRenderer (Task 5.3)."""

from pathlib import Path

import pytest

from eft.analysis.threat_scorer import ThreatScorer
from eft.models.canonical import (
    AttachmentAnalysisReport,
    AttachmentThreatAnalysis,
    BECAnalysisReport,
    BECIndicator,
    CanonicalEmail,
    ContentObfuscationReport,
    DecodedBlobArtifact,
    DKIMSignatureArtifact,
    DMARCResult,
    EmailAuthenticationReport,
    ExtractedURL,
    HiddenContentArtifact,
    IPNetworkIntelligence,
    RelayHop,
    SPFResult,
    TransitRoute,
    URLExtractionReport,
    YARAMatchArtifact,
)
from eft.models.threat import (
    RiskSeverity,
    RiskVectorType,
)
from eft.ui.threat_card import ThreatCardRenderer


@pytest.fixture
def clean_email() -> CanonicalEmail:
    """Fixture for a completely benign canonical email."""
    return CanonicalEmail(
        ordered_headers=[
            ("From", "alice@example.com"),
            ("To", "bob@example.com"),
            ("Subject", "Weekly status update"),
        ],
        body_plain="Hello Bob, here is the weekly report.",
        body_html="<p>Hello Bob, here is the weekly report.</p>",
        authentication_report=EmailAuthenticationReport(
            spf=SPFResult(status="pass", sender_ip="93.184.216.34"),
            dkim_signatures=[
                DKIMSignatureArtifact(status="pass", domain="example.com", selector="s1")
            ],
            dmarc=DMARCResult(status="pass", disposition="none", policy="none"),
        ),
    )


@pytest.fixture
def malicious_email() -> CanonicalEmail:
    """Fixture for a weaponized email triggering multiple forensic threat vectors."""
    return CanonicalEmail(
        ordered_headers=[
            ("From", "security@paypal-update.com"),
            ("To", "victim@company.com"),
            ("Subject", "URGENT: Wire Transfer Authorization Required"),
        ],
        body_plain="Authorize wire transfer immediately via http://198.51.100.25/login",
        body_html="<p>Authorize wire transfer immediately via <a href='http://198.51.100.25/login'>https://paypal.com/verify</a></p>",
        authentication_report=EmailAuthenticationReport(
            spf=SPFResult(status="fail", sender_ip="198.51.100.25"),
            dkim_signatures=[
                DKIMSignatureArtifact(status="fail", domain="paypal.com", selector="s1")
            ],
            dmarc=DMARCResult(status="fail", disposition="reject", policy="reject"),
        ),
        url_report=URLExtractionReport(
            total_urls_found=2,
            urls=[
                ExtractedURL(
                    url="http://198.51.100.25/login.php",
                    defanged_url="hxxp://198.51.100.25/login[.]php",
                    domain="198.51.100.25",
                    is_ip_host=True,
                    risk_flags=["CREDENTIAL_HARVESTING_KEYWORD"],
                ),
                ExtractedURL(
                    url="http://xn--pypal-4ve.com/account",
                    defanged_url="hxxp://xn--pypal-4ve[.]com/account",
                    domain="xn--pypal-4ve.com",
                    is_idn_homograph=True,
                    is_anchor_mismatch=True,
                    anchor_text="https://paypal.com/account",
                ),
            ],
        ),
        bec_report=BECAnalysisReport(
            threat_score=85.0,
            overall_threat_level="MALICIOUS",
            indicators=[
                BECIndicator(
                    indicator_type="FINANCIAL_URGENCY",
                    description="High pressure financial demand",
                    confidence_score=0.9,
                    observed_value="wire transfer immediately",
                    severity="HIGH",
                ),
                BECIndicator(
                    indicator_type="EXECUTIVE_IMPERSONATION",
                    description="Impersonating Chief Security Officer",
                    confidence_score=0.85,
                    observed_value="security@paypal-update.com",
                    severity="HIGH",
                ),
            ],
        ),
        attachment_threat_report=AttachmentAnalysisReport(
            total_attachments_scanned=1,
            malicious_attachments_count=1,
            attachment_analyses=[
                AttachmentThreatAnalysis(
                    is_malicious=True,
                    threat_level="MALICIOUS",
                    threat_score=95.0,
                    threat_categories=["EMBEDDED_PE", "DANGEROUS_EXTENSION"],
                    dangerous_extension=True,
                    extension_mismatch=True,
                    yara_matches=[
                        YARAMatchArtifact(rule_name="Trojan_Dropper_Generic", tags=["malware"])
                    ],
                )
            ],
        ),
        obfuscation_report=ContentObfuscationReport(
            total_hidden_artifacts=1,
            total_decoded_blobs=1,
            hidden_text_char_count=42,
            has_zero_width_chars=True,
            overall_obfuscation_risk="HIGH_RISK_OBFUSCATION",
            hidden_artifacts=[
                HiddenContentArtifact(
                    technique="CSS_DISPLAY_NONE",
                    hidden_text="secret payload",
                )
            ],
            decoded_blobs=[
                DecodedBlobArtifact(
                    encoding_type="BASE64",
                    raw_blob="TVqQAAMAAAAEAAAA//8AALgA...",
                )
            ],
        ),
        transit_route=TransitRoute(
            total_hops=1,
            anomalies_detected=["Negative transit delay detected"],
            hops=[
                RelayHop(
                    hop_number=1,
                    from_ip="185.220.101.5",
                    network_intelligence=IPNetworkIntelligence(
                        ip="185.220.101.5",
                        is_tor_exit_node=True,
                    ),
                )
            ],
        ),
    )


def test_threat_scorer_clean_email(clean_email: CanonicalEmail):
    """Verify that a benign email scores low and is classified as CLEAN."""
    report = ThreatScorer.calculate_composite_risk(clean_email)
    assert report.overall_score < 20.0
    assert report.risk_level == RiskSeverity.CLEAN
    assert "allow" in report.recommended_action.lower()
    assert len(report.all_factors) == 0


def test_threat_scorer_malicious_email(malicious_email: CanonicalEmail):
    """Verify that a heavily weaponized email achieves high composite threat score and CRITICAL severity."""
    report = ThreatScorer.calculate_composite_risk(malicious_email)
    assert report.overall_score >= 80.0
    assert report.risk_level in (
        RiskSeverity.MALICIOUS_HIGH,
        RiskSeverity.CRITICAL,
    )
    assert "QUARANTINE" in report.recommended_action or "BLOCK" in report.recommended_action
    assert len(report.all_factors) >= 5

    # Check vector breakdown presence
    assert RiskVectorType.AUTHENTICATION.value in report.vector_breakdown
    assert RiskVectorType.PHISHING_URL.value in report.vector_breakdown
    assert RiskVectorType.BEC_SOCIAL_ENGINEERING.value in report.vector_breakdown
    assert RiskVectorType.ATTACHMENT_MALWARE.value in report.vector_breakdown
    assert RiskVectorType.OBFUSCATION_TRANSIT.value in report.vector_breakdown


def test_threat_scorer_individual_vectors():
    """Verify vector scores capping and specific factor scoring."""
    # Email with only SPF SoftFail and URL shortener
    email = CanonicalEmail(
        authentication_report=EmailAuthenticationReport(
            spf=SPFResult(status="softfail", sender_ip="1.2.3.4")
        ),
        url_report=URLExtractionReport(
            total_urls_found=1,
            urls=[
                ExtractedURL(
                    url="https://bit.ly/xyz",
                    defanged_url="hxxps://bit[.]ly/xyz",
                    is_shortener=True,
                )
            ],
        ),
    )
    report = ThreatScorer.calculate_composite_risk(email)
    assert report.overall_score > 0.0
    assert report.risk_level in (
        RiskSeverity.CLEAN,
        RiskSeverity.SUSPICIOUS_LOW,
    )
    assert any(f.name == "SPF SoftFail" for f in report.all_factors)
    assert any(f.name == "URL Shortener Obfuscation" for f in report.all_factors)


def test_svg_gauge_generation():
    """Verify standalone SVG gauge dial generation."""
    svg_clean = ThreatCardRenderer.generate_svg_gauge(15.0, RiskSeverity.CLEAN)
    assert svg_clean.startswith("<svg")
    assert svg_clean.endswith("</svg>")
    assert "15.0" in svg_clean
    assert "CLEAN" in svg_clean

    svg_critical = ThreatCardRenderer.generate_svg_gauge(95.0, RiskSeverity.CRITICAL)
    assert "95.0" in svg_critical
    assert "CRITICAL" in svg_critical


def test_mermaid_risk_tree_generation(malicious_email: CanonicalEmail):
    """Verify Mermaid risk tree generation adhering to repository visualization rules."""
    report = ThreatScorer.calculate_composite_risk(malicious_email)
    mermaid_code = ThreatCardRenderer.generate_mermaid_risk_tree(report)

    assert "flowchart TD" in mermaid_code
    assert "classDef root" in mermaid_code
    assert "ROOT" in mermaid_code
    assert "Authentication & Spoofing" in mermaid_code
    assert (
        "YARA Malware Signature" in mermaid_code or "Attachment MIME Type Spoofing" in mermaid_code
    )


def test_html_card_generation_air_gapped(malicious_email: CanonicalEmail, tmp_path: Path):
    """Verify standalone HTML card generation, file writing, and strict air-gap safety."""
    out_file = tmp_path / "threat_card.html"
    html_output = ThreatCardRenderer.generate_card_html(
        malicious_email,
        output_path=out_file,
        title="Forensic Threat Assessment",
    )

    assert out_file.is_file()
    assert out_file.read_text(encoding="utf-8") == html_output

    assert "<!DOCTYPE html>" in html_output
    assert "<title>Forensic Threat Assessment</title>" in html_output
    assert "Composite Risk Dial" in html_output
    assert "Vector Contribution Breakdown" in html_output
    assert "Identified Forensic Threat Indicators" in html_output
    assert "Mermaid Risk Factor Decomposition Flowchart" in html_output

    # Air-Gapped Verification: No remote CDN script or stylesheet dependencies
    assert "<script src=" not in html_output
    assert '<link rel="stylesheet"' not in html_output
    assert '<link href="http' not in html_output
    assert "@import url(" not in html_output


def test_cli_card_rendering(malicious_email: CanonicalEmail, clean_email: CanonicalEmail):
    """Verify terminal Rich panel rendering for clean and malicious emails."""
    panel_mal = ThreatCardRenderer.generate_cli_card(malicious_email)
    assert panel_mal is not None
    assert "Forensic Threat Risk Indicator" in str(panel_mal.title)

    panel_clean = ThreatCardRenderer.generate_cli_card(clean_email)
    assert panel_clean is not None
