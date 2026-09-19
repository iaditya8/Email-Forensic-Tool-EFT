"""Comprehensive unit and integration tests for Multi-Format Forensic Report Exporter."""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from eft.models.canonical import (
    AttachmentAnalysisReport,
    AttachmentThreatAnalysis,
    BECAnalysisReport,
    BECIndicator,
    CanonicalEmail,
    ContentObfuscationReport,
    DecodedBlobArtifact,
    DKIMSignatureArtifact,
    EmailAuthenticationReport,
    ExtractedAttachment,
    ExtractedURL,
    IPNetworkIntelligence,
    RelayHop,
    SourceFileInfo,
    SPFResult,
    TransitRoute,
    URLExtractionReport,
    YARAMatchArtifact,
)
from eft.reporting.exporter import ForensicReportExporter


@pytest.fixture
def rich_canonical_email() -> CanonicalEmail:
    """Create a fully-populated CanonicalEmail instance with threat findings across all engines."""
    t0 = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Source File Info
    src_info = SourceFileInfo(
        file_path="/evidence/suspect_email_001.eml",
        file_name="suspect_email_001.eml",
        file_format="eml",
        file_size_bytes=14520,
        hashes={
            "md5": "0123456789abcdef0123456789abcdef",
            "sha1": "0123456789abcdef0123456789abcdef01234567",
            "sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "sha512": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        },
    )

    # 2. Transit Routing with GeoIP/ASN
    intel = IPNetworkIntelligence(
        ip="198.51.100.42",
        country="United States",
        country_code="US",
        city="Ashburn",
        asn=16509,
        as_org="Amazon.com, Inc.",
        is_cloud_provider=True,
        cloud_provider_name="AWS",
        is_tor_exit_node=False,
        is_vpn=False,
    )
    hop1 = RelayHop(
        hop_number=1,
        from_host="mail-sender.org",
        from_ip="198.51.100.42",
        by_host="mx.recipient.com",
        by_ip="203.0.113.10",
        protocol="ESMTPS",
        tls_cipher="TLS_AES_256_GCM_SHA384",
        delay_seconds=3.2,
        network_intelligence=intel,
    )
    transit = TransitRoute(
        total_hops=1,
        originating_ip="198.51.100.42",
        originating_ip_intelligence=intel,
        hops=[hop1],
    )

    # 3. Authentication Report
    spf = SPFResult(status="pass", sender_ip="198.51.100.42", is_aligned=True)
    dkim = DKIMSignatureArtifact(
        domain="sender.org", selector="s2026", status="pass", is_aligned=True
    )
    auth = EmailAuthenticationReport(
        overall_verdict="PASS",
        spf=spf,
        dkim_signatures=[dkim],
    )

    # 4. URLs
    url1 = ExtractedURL(
        url="https://secure-login.bank-update.com/login",
        defanged_url="hxxps[://]secure-login[.]bank-update[.]com/login",
        anchor_text="Click here to verify account",
        source_location="html_href",
        domain="bank-update.com",
        is_anchor_mismatch=True,
        anchor_domain="chase.com",
        is_idn_homograph=False,
        risk_score=75.0,
        risk_flags=["ANCHOR_URL_MISMATCH", "SUSPICIOUS_TLD"],
    )
    url_rep = URLExtractionReport(
        total_urls_found=1,
        unique_domains=["bank-update.com"],
        urls=[url1],
        overall_url_risk="SUSPICIOUS",
    )

    # 5. BEC Report
    bec_ind = BECIndicator(
        indicator_type="DISPLAY_NAME_SPOOF",
        severity="HIGH",
        description="Display name impersonates Executive CEO <ceo@company.com>",
        observed_value="CEO John Doe <attacker@freemail.com>",
    )
    bec_rep = BECAnalysisReport(
        is_bec_suspected=True,
        overall_threat_level="HIGH_RISK",
        threat_score=80.0,
        display_name_spoof_detected=True,
        indicators=[bec_ind],
    )

    # 6. Attachment with YARA Match
    yara_m = YARAMatchArtifact(
        rule_name="SUSP_VBA_Macro_AutoExec",
        tags=["macro", "evasion"],
        severity="HIGH",
    )
    att_threat = AttachmentThreatAnalysis(
        is_malicious=True,
        threat_level="MALICIOUS",
        threat_score=95.0,
        dangerous_extension=True,
        yara_matches=[yara_m],
        threat_indicators=["MALICIOUS_VBA_MACRO_DETECTED"],
    )
    att = ExtractedAttachment(
        attachment_index=0,
        filename="urgent_invoice.xlsm",
        safe_filename="urgent_invoice.xlsm",
        size_bytes=45200,
        content_type="application/vnd.ms-excel.sheet.macroEnabled.12",
        hashes={
            "md5": "e4d909c290d0fb1ca068ffaddf22cbd0",
            "sha1": "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
            "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        },
        threat_analysis=att_threat,
    )
    att_rep = AttachmentAnalysisReport(
        total_attachments_scanned=1,
        malicious_attachments_count=1,
        overall_attachment_risk="MALICIOUS",
        threat_score=95.0,
        attachment_analyses=[att_threat],
    )

    # 7. Obfuscation
    blob = DecodedBlobArtifact(
        encoding_type="BASE64",
        raw_blob="UG93ZXJTaGVsbCAtaWRlbnRpdHk=",
        decoded_text="PowerShell -identity",
        decoded_bytes_sha256="112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
        source_location="html_body",
        suspicious_indicators=["POWERSHELL_CMD"],
    )
    obf_rep = ContentObfuscationReport(
        total_decoded_blobs=1,
        has_script_payload=True,
        overall_obfuscation_risk="SUSPICIOUS",
        decoded_blobs=[blob],
    )

    return CanonicalEmail(
        message_id="<dfir-test-msg-001@sender.org>",
        date="Sat, 19 Sep 2026 12:00:00 +0000",
        subject="URGENT: Executive Wire Transfer Confirmation",
        from_address="CEO John Doe <attacker@freemail.com>",
        to_addresses=["finance@victimcorp.com"],
        cc_addresses=["accounting@victimcorp.com"],
        reply_to="attacker-inbox@shadow-c2.net",
        return_path="bounce@freemail.com",
        body_plain="Please process the attached urgent invoice immediately.",
        body_html="<p>Please process the attached urgent invoice immediately.</p>",
        source_file=src_info,
        transit_route=transit,
        authentication_report=auth,
        url_report=url_rep,
        bec_report=bec_rep,
        extracted_attachments=[att],
        attachment_threat_report=att_rep,
        obfuscation_report=obf_rep,
        ingestion_timestamp_utc=t0,
    )


def test_export_json(rich_canonical_email: CanonicalEmail, tmp_path: Path):
    json_path = tmp_path / "forensic_export.json"
    json_str = ForensicReportExporter.export_json(rich_canonical_email, output_path=json_path)

    assert json_path.exists()
    assert len(json_str) > 100

    # Parse and validate JSON structure
    data = json.loads(json_str)
    assert data["subject"] == "URGENT: Executive Wire Transfer Confirmation"
    assert (
        data["source_file"]["hashes"]["sha256"]
        == "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    )
    assert (
        data["url_report"]["urls"][0]["defanged_url"]
        == "hxxps[://]secure-login[.]bank-update[.]com/login"
    )

    # Reconstruct back into CanonicalEmail
    reloaded_email = CanonicalEmail.model_validate(data)
    assert reloaded_email.message_id == rich_canonical_email.message_id


def test_export_csv(rich_canonical_email: CanonicalEmail, tmp_path: Path):
    csv_path = tmp_path / "forensic_iocs.csv"
    csv_str = ForensicReportExporter.export_csv(rich_canonical_email, output_path=csv_path)

    assert csv_path.exists()

    reader = list(csv.reader(csv_str.splitlines()))
    assert len(reader) >= 6  # Header + IP + From + Reply-To + URL + SHA-256 + MD5 + BEC + Blob

    headers = reader[0]
    assert headers == [
        "ioc_type",
        "ioc_value",
        "source_context",
        "severity",
        "threat_category",
        "description",
    ]

    # Verify IP IoC present
    ip_rows = [r for r in reader if r[0] == "ip-address"]
    assert len(ip_rows) >= 1
    assert ip_rows[0][1] == "198.51.100.42"

    # Verify URL IoC present
    url_rows = [r for r in reader if r[0] == "url"]
    assert len(url_rows) >= 1
    assert "secure-login.bank-update.com" in url_rows[0][1]

    # Verify Attachment Hash present
    hash_rows = [r for r in reader if r[0] == "file-hash-sha256"]
    assert len(hash_rows) >= 1
    assert hash_rows[0][1] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_export_stix(rich_canonical_email: CanonicalEmail, tmp_path: Path):
    stix_path = tmp_path / "forensic_bundle.stix2.json"
    stix_str = ForensicReportExporter.export_stix(rich_canonical_email, output_path=stix_path)

    assert stix_path.exists()
    stix_data = json.loads(stix_str)

    assert stix_data["type"] == "bundle"
    assert "objects" in stix_data

    objects = stix_data["objects"]
    types = [obj["type"] for obj in objects]

    assert "email-message" in types
    assert "email-addr" in types
    assert "ipv4-addr" in types
    assert "url" in types
    assert "file" in types
    assert "indicator" in types
    assert "relationship" in types

    # Check EmailMessage object
    email_obj = next(o for o in objects if o["type"] == "email-message")
    assert email_obj["subject"] == "URGENT: Executive Wire Transfer Confirmation"


def test_export_pdf(rich_canonical_email: CanonicalEmail, tmp_path: Path):
    pdf_path = tmp_path / "court_forensic_report.pdf"
    result_path = ForensicReportExporter.export_pdf(
        rich_canonical_email,
        output_path=pdf_path,
        case_id="CASE-2026-FEDERAL-009",
        examiner_name="Special Agent D. Rossi",
        examiner_agency="Federal Cyber Division",
    )

    assert result_path.exists()
    assert pdf_path.stat().st_size > 1000

    # Read binary header to ensure valid PDF
    pdf_bytes = pdf_path.read_bytes()
    assert pdf_bytes.startswith(b"%PDF")
    assert b"%%EOF" in pdf_bytes


def test_export_all_batch(rich_canonical_email: CanonicalEmail, tmp_path: Path):
    out_dir = tmp_path / "batch_output"
    results = ForensicReportExporter.export_all(
        rich_canonical_email,
        output_dir=out_dir,
        base_name="case_001_evidence",
        case_id="CASE-BATCH-001",
    )

    assert "json" in results
    assert "csv" in results
    assert "stix" in results
    assert "pdf" in results

    assert results["json"].exists()
    assert results["csv"].exists()
    assert results["stix"].exists()
    assert results["pdf"].exists()
