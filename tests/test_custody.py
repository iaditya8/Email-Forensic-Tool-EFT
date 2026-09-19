"""Comprehensive unit and integration tests for Evidence Chain of Custody & Cryptographic Ledger."""

from pathlib import Path

import pytest

from eft.core.exceptions import EvidenceTamperedException
from eft.core.integrity import compute_bytes_hashes
from eft.models.custody import (
    CustodyAction,
)
from eft.reporting.custody import ChainOfCustodyManager


@pytest.fixture
def sample_raw_eml(sample_eml_content: bytes) -> bytes:
    return sample_eml_content


@pytest.fixture
def sample_eml_file(tmp_path: Path, sample_raw_eml: bytes) -> Path:
    eml_file = tmp_path / "evidence_case_001.eml"
    eml_file.write_bytes(sample_raw_eml)
    return eml_file


def test_create_manifest_from_file(sample_eml_file: Path):
    manifest = ChainOfCustodyManager.create_manifest(
        file_path=sample_eml_file,
        case_id="CASE-2026-DFIR-001",
        evidence_id="EVID-EML-001",
        examiner_name="Special Agent J. Miller",
        examiner_agency="Federal Cyber Defense Command",
        notes="Seized during search warrant execution at suspect premises.",
        metadata={"host": "investigator-workstation-09", "tool_version": "1.0.0"},
    )

    assert manifest.case_id == "CASE-2026-DFIR-001"
    assert manifest.evidence_id == "EVID-EML-001"
    assert manifest.examiner_name == "Special Agent J. Miller"
    assert manifest.examiner_agency == "Federal Cyber Defense Command"
    assert manifest.source_file_name == "evidence_case_001.eml"
    assert manifest.source_file_size_bytes == sample_eml_file.stat().st_size
    assert manifest.file_format == "eml"
    assert manifest.integrity_verified is True
    assert manifest.post_analysis_hashes is None

    # Check multi-algorithm cryptographic hashes
    assert "md5" in manifest.pre_analysis_hashes
    assert "sha1" in manifest.pre_analysis_hashes
    assert "sha256" in manifest.pre_analysis_hashes
    assert "sha512" in manifest.pre_analysis_hashes
    assert len(manifest.pre_analysis_hashes["md5"]) == 32
    assert len(manifest.pre_analysis_hashes["sha1"]) == 40
    assert len(manifest.pre_analysis_hashes["sha256"]) == 64
    assert len(manifest.pre_analysis_hashes["sha512"]) == 128


def test_create_manifest_file_not_found(tmp_path: Path):
    missing_path = tmp_path / "non_existent_file.eml"
    with pytest.raises(FileNotFoundError):
        ChainOfCustodyManager.create_manifest(
            file_path=missing_path,
            case_id="CASE-404",
            evidence_id="EVID-404",
            examiner_name="Investigator X",
        )


def test_create_manifest_from_bytes(sample_raw_eml: bytes):
    manifest = ChainOfCustodyManager.create_manifest_from_bytes(
        data=sample_raw_eml,
        source_file_name="stream_capture.eml",
        case_id="CASE-INMEMORY-02",
        evidence_id="EVID-MEM-002",
        examiner_name="Forensic Tech A",
        file_format="eml",
    )

    assert manifest.case_id == "CASE-INMEMORY-02"
    assert manifest.evidence_id == "EVID-MEM-002"
    assert manifest.source_file_size_bytes == len(sample_raw_eml)
    assert manifest.source_file_path == "memory://stream_capture.eml"
    assert "sha256" in manifest.pre_analysis_hashes
    assert manifest.pre_analysis_hashes["sha256"] == compute_bytes_hashes(sample_raw_eml)["sha256"]


def test_create_ledger_and_record_events(sample_eml_file: Path):
    manifest = ChainOfCustodyManager.create_manifest(
        file_path=sample_eml_file,
        case_id="CASE-2026-003",
        evidence_id="EVID-003",
        examiner_name="Analyst Smith",
        examiner_agency="DFIR Labs",
    )

    ledger = ChainOfCustodyManager.create_ledger(manifest=manifest)

    assert ledger.case_id == "CASE-2026-003"
    assert ledger.evidence_id == "EVID-003"
    assert len(ledger.events) == 1
    assert ledger.events[0].action == CustodyAction.ACQUISITION.value
    assert ledger.events[0].performed_by == "Analyst Smith"
    assert ledger.events[0].agency == "DFIR Labs"
    assert ledger.events[0].evidence_hash == manifest.pre_analysis_hashes["sha256"]

    # Record additional sequential events
    event2 = ChainOfCustodyManager.record_event(
        ledger=ledger,
        action=CustodyAction.INGESTION,
        performed_by="EFT-Core-Parser",
        description="Ingested MIME structure and verified envelope headers.",
        details={"headers_parsed": 12, "attachments_count": 0},
    )
    assert event2.action == "INGESTION"
    assert len(ledger.events) == 2

    event3 = ChainOfCustodyManager.record_event(
        ledger=ledger,
        action="CUSTOM_MALWARE_SCAN",
        performed_by="YARA-Engine",
        agency="DFIR Labs",
        description="Executed static rule scans on email payload.",
        details={"rules_evaluated": 25, "matches": 0},
    )
    assert event3.action == "CUSTOM_MALWARE_SCAN"
    assert len(ledger.events) == 3
    assert ledger.is_tampered is False


def test_verify_integrity_success(sample_eml_file: Path):
    manifest = ChainOfCustodyManager.create_manifest(
        file_path=sample_eml_file,
        case_id="CASE-2026-INT-01",
        evidence_id="EVID-INT-01",
        examiner_name="Examiner Alpha",
    )
    ledger = ChainOfCustodyManager.create_ledger(manifest)

    is_valid, report = ChainOfCustodyManager.verify_integrity(ledger)

    assert is_valid is True
    assert report["status"] == "VERIFIED"
    assert report["integrity_verified"] is True
    assert ledger.manifest.integrity_verified is True
    assert ledger.manifest.post_analysis_hashes is not None
    assert ledger.manifest.post_analysis_hashes == ledger.manifest.pre_analysis_hashes
    assert ledger.is_tampered is False

    # Check that an INTEGRITY_CHECK event was appended
    assert len(ledger.events) == 2
    assert ledger.events[-1].action == CustodyAction.INTEGRITY_CHECK.value


def test_verify_integrity_bytes_success(sample_raw_eml: bytes):
    manifest = ChainOfCustodyManager.create_manifest_from_bytes(
        data=sample_raw_eml,
        source_file_name="mem_test.eml",
        case_id="CASE-BYTES-01",
        evidence_id="EVID-BYTES-01",
        examiner_name="Examiner Beta",
    )
    ledger = ChainOfCustodyManager.create_ledger(manifest)

    is_valid, report = ChainOfCustodyManager.verify_integrity(ledger, current_bytes=sample_raw_eml)

    assert is_valid is True
    assert report["status"] == "VERIFIED"
    assert ledger.manifest.integrity_verified is True


def test_verify_integrity_tamper_detected(sample_eml_file: Path):
    manifest = ChainOfCustodyManager.create_manifest(
        file_path=sample_eml_file,
        case_id="CASE-2026-TAMPER-01",
        evidence_id="EVID-TAMPER-01",
        examiner_name="Examiner Gamma",
    )
    ledger = ChainOfCustodyManager.create_ledger(manifest)

    # Simulate tampering by mutating the underlying evidence file
    tampered_content = sample_eml_file.read_bytes() + b"\nTAMPERED_MALICIOUS_BYTES"
    sample_eml_file.write_bytes(tampered_content)

    is_valid, report = ChainOfCustodyManager.verify_integrity(ledger, raise_on_tamper=False)

    assert is_valid is False
    assert report["status"] == "TAMPER_DETECTED"
    assert ledger.manifest.integrity_verified is False
    assert ledger.is_tampered is True
    assert "EVIDENCE TAMPER DETECTED" in (ledger.tamper_details or "")

    # Check that TAMPER_DETECTED event was recorded
    assert ledger.events[-1].action == CustodyAction.TAMPER_DETECTED.value
    assert "TAMPER" in ledger.events[-1].description

    # Test raise_on_tamper=True raises EvidenceTamperedException
    with pytest.raises(EvidenceTamperedException):
        ChainOfCustodyManager.verify_integrity(ledger, raise_on_tamper=True)


def test_verify_integrity_missing_file(tmp_path: Path, sample_raw_eml: bytes):
    test_file = tmp_path / "temp_evidence.eml"
    test_file.write_bytes(sample_raw_eml)

    manifest = ChainOfCustodyManager.create_manifest(
        file_path=test_file,
        case_id="CASE-MISSING",
        evidence_id="EVID-MISSING",
        examiner_name="Examiner Delta",
    )
    ledger = ChainOfCustodyManager.create_ledger(manifest)

    # Delete evidence file
    test_file.unlink()

    is_valid, report = ChainOfCustodyManager.verify_integrity(ledger, raise_on_tamper=False)
    assert is_valid is False
    assert report["status"] == "FILE_NOT_FOUND"
    assert ledger.is_tampered is True

    with pytest.raises(FileNotFoundError):
        ChainOfCustodyManager.verify_integrity(ledger, raise_on_tamper=True)


def test_json_export_and_load_roundtrip(sample_eml_file: Path, tmp_path: Path):
    manifest = ChainOfCustodyManager.create_manifest(
        file_path=sample_eml_file,
        case_id="CASE-ROUNDTRIP",
        evidence_id="EVID-ROUNDTRIP",
        examiner_name="Inspector Gadget",
        examiner_agency="Metro Cyber DFIR",
        notes="High-profile phishing campaign investigation.",
        metadata={"jurisdiction": "State", "court_id": "CR-2026-99"},
    )
    ledger = ChainOfCustodyManager.create_ledger(manifest)
    ChainOfCustodyManager.record_event(
        ledger=ledger,
        action=CustodyAction.PARSING,
        performed_by="EFT-Engine",
        description="Parsed MIME hierarchy and headers.",
    )

    manifest_file = tmp_path / "evidence_manifest.json"
    ledger_file = tmp_path / "chain_of_custody_ledger.json"

    # Export to disk
    manifest_json_str = ChainOfCustodyManager.export_manifest_json(
        manifest, output_path=manifest_file
    )
    ledger_json_str = ChainOfCustodyManager.export_ledger_json(ledger, output_path=ledger_file)

    assert manifest_file.exists()
    assert ledger_file.exists()

    # Load from disk
    loaded_manifest = ChainOfCustodyManager.load_manifest_json(manifest_file)
    loaded_ledger = ChainOfCustodyManager.load_ledger_json(ledger_file)

    assert loaded_manifest.case_id == manifest.case_id
    assert loaded_manifest.pre_analysis_hashes == manifest.pre_analysis_hashes
    assert loaded_manifest.metadata["court_id"] == "CR-2026-99"

    assert loaded_ledger.case_id == ledger.case_id
    assert len(loaded_ledger.events) == 2
    assert loaded_ledger.events[1].action == "PARSING"

    # Load from raw string
    str_loaded_manifest = ChainOfCustodyManager.load_manifest_json(manifest_json_str)
    str_loaded_ledger = ChainOfCustodyManager.load_ledger_json(ledger_json_str)
    assert str_loaded_manifest.manifest_id == manifest.manifest_id
    assert str_loaded_ledger.ledger_id == ledger.ledger_id


def test_markdown_summary_and_timeline_generation(sample_eml_file: Path):
    manifest = ChainOfCustodyManager.create_manifest(
        file_path=sample_eml_file,
        case_id="CASE-SUMMARY-01",
        evidence_id="EVID-CARD-01",
        examiner_name="Lead Examiner Vance",
        examiner_agency="CERT DFIR Unit",
        notes="Extracted from infected endpoint.",
    )
    ledger = ChainOfCustodyManager.create_ledger(manifest)
    ChainOfCustodyManager.record_event(
        ledger=ledger,
        action=CustodyAction.ATTACHMENT_EXTRACTION,
        performed_by="Extractor Engine",
        agency="CERT DFIR Unit",
        description="Extracted invoice_fake.pdf payload.",
    )
    ChainOfCustodyManager.verify_integrity(ledger)

    summary_md = ChainOfCustodyManager.generate_manifest_summary(ledger.manifest)
    timeline_md = ChainOfCustodyManager.generate_custody_timeline(ledger)

    assert "# Evidence Manifest: EVID-CARD-01" in summary_md
    assert "Lead Examiner Vance (CERT DFIR Unit)" in summary_md
    assert "SHA-256:" in summary_md
    assert "VERIFIED IMMUTABLE" in summary_md
    assert "Extracted from infected endpoint." in summary_md

    assert "# Chain of Custody Timeline: EVID-CARD-01" in timeline_md
    assert "| `ACQUISITION` |" in timeline_md
    assert "| `ATTACHMENT_EXTRACTION` |" in timeline_md
    assert "| `INTEGRITY_CHECK` |" in timeline_md
    assert "invoice_fake.pdf" in timeline_md
