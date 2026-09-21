"""Unit tests for MemoryYARAScanner and volatile memory threat attribution models."""

from pathlib import Path

import pytest

from eft.analysis.memory_yara_scanner import MemoryYARAScanner
from eft.models.memory_forensics import MemoryThreatFamily


@pytest.fixture
def yara_scanner() -> MemoryYARAScanner:
    """Provide a configured MemoryYARAScanner instance."""
    return MemoryYARAScanner(default_chunk_size=1024)


def test_cobalt_strike_beacon_detection(yara_scanner: MemoryYARAScanner) -> None:
    """Verify detection of Cobalt Strike named pipe markers and beacon DLL strings."""
    data = (
        b"\x00" * 32
        + b"Connecting to named pipe \\\\.\\pipe\\msagent_9812 for IPC\x00"
        + b"Loaded payload module: beacon.x64.dll\x00"
        + b"\x00" * 64
    )
    matches = yara_scanner.scan_bytes(data, base_offset=100)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_name == "MEMORY_COBALT_STRIKE_BEACON"
    assert m.threat_family == MemoryThreatFamily.COBALT_STRIKE
    assert m.severity == "CRITICAL"
    assert m.risk_score >= 90
    assert len(m.strings_matched) >= 2


def test_mimikatz_detection(yara_scanner: MemoryYARAScanner) -> None:
    """Verify detection of Mimikatz in-memory credential dumper artifacts."""
    data = (
        b"\x90" * 16
        + b"privilege::debug\x00"
        + b"sekurlsa::logonpasswords\x00"
        + b"Author: gentilkiwi\x00"
    )
    matches = yara_scanner.scan_bytes(data, base_offset=0)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_name == "MEMORY_MIMIKATZ_CREDENTIAL_DUMPER"
    assert m.threat_family == MemoryThreatFamily.MIMIKATZ
    assert m.mitre_attack == "T1003.001"


def test_meterpreter_detection(yara_scanner: MemoryYARAScanner) -> None:
    """Verify detection of Metasploit Meterpreter stagers and command channels."""
    data = b"\x00" * 20 + b"Stage loaded: metsrv.dll and channel core_channel_open initialized\x00"
    matches = yara_scanner.scan_bytes(data, base_offset=200)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_name == "MEMORY_METASPLOIT_METERPRETER"
    assert m.threat_family == MemoryThreatFamily.METERPRETER
    assert m.severity == "CRITICAL"


def test_lumma_stealer_detection(yara_scanner: MemoryYARAScanner) -> None:
    """Verify detection of Lumma info-stealer strings and crypto wallet extension hooks."""
    data = (
        b"\x00" * 10
        + b"Targeting wallet extension: nkbihfbeogaeaoehlefnkodbefgpgknn (MetaMask)\x00"
        + b"C2 Beacon: https://gate.lummac2.io/api/v1/lumma\x00"
    )
    matches = yara_scanner.scan_bytes(data, base_offset=50)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_name == "MEMORY_LUMMA_STEALER_INFO_STEALER"
    assert m.threat_family == MemoryThreatFamily.LUMMA_STEALER
    assert m.severity == "HIGH"


def test_reflective_injection_detection(yara_scanner: MemoryYARAScanner) -> None:
    """Verify detection of reflective DLL injection and process hollowing API sequences."""
    data = (
        b"Calling VirtualAllocEx and WriteProcessMemory followed by CreateRemoteThread\x00"
        + b"Export: ReflectiveLoader\x00"
    )
    matches = yara_scanner.scan_bytes(data, base_offset=0)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_name == "MEMORY_REFLECTIVE_DLL_INJECTION"
    assert m.threat_family == MemoryThreatFamily.REFLECTIVE_INJECTION


def test_ransomware_detection(yara_scanner: MemoryYARAScanner) -> None:
    """Verify detection of volume shadow copy deletion and ransom note signatures."""
    data = (
        b"Executing command: vssadmin delete shadows /all /quiet\x00"
        + b"Writing note: ALL YOUR DATA HAS BEEN LOCKED! Read instructions to recover.\x00"
    )
    matches = yara_scanner.scan_bytes(data, base_offset=0)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_name == "MEMORY_RANSOMWARE_ENCRYPTOR"
    assert m.threat_family == MemoryThreatFamily.RANSOMWARE_ENCRYPTOR
    assert m.severity == "CRITICAL"


def test_benign_memory_buffer(yara_scanner: MemoryYARAScanner) -> None:
    """Verify clean memory buffer returns 0 matches."""
    data = b"Clean standard operating system process memory without threats."
    matches = yara_scanner.scan_bytes(data, base_offset=0)
    assert len(matches) == 0


def test_scan_stream_multi_family_attribution(tmp_path: Path) -> None:
    """Verify streaming analysis across file and attribution synthesis for multiple threats."""
    dump_file = tmp_path / "memory_apt_dump.bin"
    payload = (
        b"\x00" * 128
        + b"\\\\.\\pipe\\msagent_1142 beacon.dll\x00"
        + b"\x00" * 256
        + b"sekurlsa::logonpasswords gentilkiwi\x00"
        + b"\x00" * 128
    )
    dump_file.write_bytes(payload)

    scanner = MemoryYARAScanner(default_chunk_size=128)
    report = scanner.scan_stream(dump_file)

    assert report.evidence_path == str(dump_file)
    assert report.total_yara_matches == 2
    assert MemoryThreatFamily.COBALT_STRIKE in report.threat_families_detected
    assert MemoryThreatFamily.MIMIKATZ in report.threat_families_detected
    assert report.composite_threat_score >= 95
    assert report.threat_level == "CRITICAL"
    assert "COBALT_STRIKE" in report.attribution_summary
    assert "MIMIKATZ" in report.attribution_summary
    assert len(report.evidence_hashes["sha256"]) == 64


def test_custom_rule_integration() -> None:
    """Verify support for user-supplied custom YARA rule definitions."""
    custom_rule = {
        "rule_name": "CUSTOM_BLACKCAT_RANSOMWARE",
        "threat_family": MemoryThreatFamily.RANSOMWARE_ENCRYPTOR,
        "severity": "CRITICAL",
        "tags": ["custom", "blackcat"],
        "meta": {"description": "Custom signature for BlackCat/ALPHV ransomware"},
        "patterns": [(r"(?i)\b(?:alphv_encryptor|blackcat_locker)\b", "ALPHV_STR")],
        "condition": "any",
        "risk_score": 98,
        "mitre_attack": "T1486",
    }
    scanner = MemoryYARAScanner(custom_rules=[custom_rule])
    data = b"Executing alphv_encryptor in memory"
    matches = scanner.scan_bytes(data)
    assert len(matches) == 1
    assert matches[0].rule_name == "CUSTOM_BLACKCAT_RANSOMWARE"
    assert matches[0].risk_score == 98


def test_file_not_found_raises(yara_scanner: MemoryYARAScanner) -> None:
    """Verify FileNotFoundError is raised for non-existent evidence paths."""
    with pytest.raises(FileNotFoundError):
        yara_scanner.scan_stream("C:\\non_existent_memory_dump_9999.dmp")
