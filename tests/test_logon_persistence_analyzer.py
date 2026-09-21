"""Unit tests for WindowsSecurityAnalyzer, logon anomalies, privilege escalation, and persistence detection."""

import json
from pathlib import Path

import pytest

from eft.analysis.logon_persistence_analyzer import WindowsSecurityAnalyzer
from eft.models.logon_persistence import (
    SecurityThreatClassification,
    WindowsLogonType,
)


@pytest.fixture
def analyzer() -> WindowsSecurityAnalyzer:
    """Fixture providing an instance of WindowsSecurityAnalyzer."""
    return WindowsSecurityAnalyzer(
        brute_force_threshold=5, spray_threshold=3, time_window_seconds=600
    )


def test_successful_and_failed_logon_parsing(analyzer: WindowsSecurityAnalyzer) -> None:
    """Test parsing Windows Security Event 4624 and 4625 records with logon types and sub-status mapping."""
    events = [
        {
            "EventID": 4624,
            "RecordId": 101,
            "Timestamp": "2026-03-22T08:30:00Z",
            "EventData": {
                "LogonType": "2",
                "TargetUserName": "alice",
                "TargetDomainName": "CORP",
                "TargetUserSid": "S-1-5-21-123-456-789-1001",
                "IpAddress": "-",
                "WorkstationName": "WKST-01",
                "AuthenticationPackageName": "Negotiate",
                "LogonProcessName": "User32",
            },
        },
        {
            "EventID": 4624,
            "RecordId": 102,
            "Timestamp": "2026-03-22T08:35:00Z",
            "EventData": {
                "LogonType": "10",
                "TargetUserName": "bob",
                "TargetDomainName": "CORP",
                "IpAddress": "192.168.1.100",
                "IpPort": "54321",
                "WorkstationName": "REMOTE-PC",
                "AuthenticationPackageName": "Kerberos",
            },
        },
        {
            "EventID": 4625,
            "RecordId": 103,
            "Timestamp": "2026-03-22T08:40:00Z",
            "EventData": {
                "LogonType": "2",
                "TargetUserName": "alice",
                "TargetDomainName": "CORP",
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
                "IpAddress": "127.0.0.1",
            },
        },
    ]

    report = analyzer.analyze_events(events)

    assert report.total_events_parsed == 3
    assert report.total_successful_logons == 2
    assert report.total_failed_logons == 1

    # Check parsed logons
    assert len(report.logons) == 3
    alice_success = report.logons[0]
    assert alice_success.target_user_name == "alice"
    assert alice_success.logon_type == WindowsLogonType.INTERACTIVE
    assert alice_success.is_success is True

    bob_rdp = report.logons[1]
    assert bob_rdp.target_user_name == "bob"
    assert bob_rdp.logon_type == WindowsLogonType.REMOTE_INTERACTIVE
    assert bob_rdp.ip_address == "192.168.1.100"

    alice_fail = report.logons[2]
    assert alice_fail.is_success is False
    assert alice_fail.sub_status == "0xC000006A"
    assert "Bad password" in (alice_fail.failure_reason or "")


def test_brute_force_and_account_compromise_detection(analyzer: WindowsSecurityAnalyzer) -> None:
    """Test detection of brute force attack followed by account compromise."""
    events = []
    # 5 Failed logons
    for i in range(5):
        events.append(
            {
                "EventID": 4625,
                "RecordId": 200 + i,
                "Timestamp": f"2026-03-22T09:00:0{i}Z",
                "EventData": {
                    "LogonType": "3",
                    "TargetUserName": "admin_victim",
                    "IpAddress": "198.51.100.50",
                    "SubStatus": "0xC000006A",
                },
            }
        )

    # Subsequent Successful Logon (Compromise)
    events.append(
        {
            "EventID": 4624,
            "RecordId": 210,
            "Timestamp": "2026-03-22T09:01:00Z",
            "EventData": {
                "LogonType": "3",
                "TargetUserName": "admin_victim",
                "IpAddress": "198.51.100.50",
                "AuthenticationPackageName": "NTLM",
            },
        }
    )

    report = analyzer.analyze_events(events)

    assert report.verdict == "MALICIOUS"
    assert report.threat_score >= 40.0

    bf_anomalies = [
        a
        for a in report.anomalies
        if a.classification == SecurityThreatClassification.BRUTE_FORCE_ATTACK
    ]
    assert len(bf_anomalies) == 1
    assert bf_anomalies[0].severity == "CRITICAL"
    assert "compromised" in bf_anomalies[0].detection_reason.lower()
    assert bf_anomalies[0].source_ip == "198.51.100.50"
    assert "198.51.100.50" in report.extracted_iocs or any(
        "198.51.100.50" in ioc for ioc in report.extracted_iocs
    )


def test_password_spraying_detection(analyzer: WindowsSecurityAnalyzer) -> None:
    """Test detection of password spraying targeting multiple distinct accounts from one IP."""
    target_users = ["accounting", "helpdesk", "finance", "executive"]
    events = []
    for idx, user in enumerate(target_users):
        events.append(
            {
                "EventID": 4625,
                "RecordId": 300 + idx,
                "Timestamp": f"2026-03-22T10:0{idx}:00Z",
                "EventData": {
                    "LogonType": "3",
                    "TargetUserName": user,
                    "IpAddress": "203.0.113.99",
                    "SubStatus": "0xC000006A",
                },
            }
        )

    report = analyzer.analyze_events(events)

    spray_anomalies = [
        a
        for a in report.anomalies
        if a.classification == SecurityThreatClassification.PASSWORD_SPRAY
    ]
    assert len(spray_anomalies) == 1
    assert spray_anomalies[0].source_ip == "203.0.113.99"
    assert spray_anomalies[0].severity == "HIGH"
    assert "T1110.003" in (spray_anomalies[0].mitre_attack_technique or "")


def test_pass_the_hash_and_cleartext_logons(analyzer: WindowsSecurityAnalyzer) -> None:
    """Test detection of Pass-the-Hash (Logon Type 9) and Cleartext Logon (Logon Type 8)."""
    events = [
        {
            "EventID": 4624,
            "RecordId": 401,
            "Timestamp": "2026-03-22T11:00:00Z",
            "EventData": {
                "LogonType": "9",  # NewCredentials
                "TargetUserName": "corp_admin",
                "LogonProcessName": "seclogo",
                "AuthenticationPackageName": "Negotiate",
                "IpAddress": "-",
            },
        },
        {
            "EventID": 4624,
            "RecordId": 402,
            "Timestamp": "2026-03-22T11:05:00Z",
            "EventData": {
                "LogonType": "8",  # NetworkCleartext
                "TargetUserName": "legacy_user",
                "IpAddress": "10.0.0.55",
                "AuthenticationPackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
            },
        },
    ]

    report = analyzer.analyze_events(events)

    anomalies = {a.classification for a in report.anomalies}
    assert SecurityThreatClassification.PASS_THE_HASH in anomalies
    assert SecurityThreatClassification.CLEARTEXT_LOGON in anomalies


def test_special_privileges_assignment(analyzer: WindowsSecurityAnalyzer) -> None:
    """Test parsing Windows Security Event 4672 special privilege assignments."""
    events = [
        {
            "EventID": 4672,
            "RecordId": 501,
            "Timestamp": "2026-03-22T12:00:00Z",
            "EventData": {
                "SubjectUserName": "Administrator",
                "SubjectDomainName": "CORP",
                "PrivilegeList": "SeSecurityPrivilege\r\n\tSeBackupPrivilege\r\n\tSeRestorePrivilege\r\n\tSeDebugPrivilege\r\n\tSeImpersonatePrivilege",
            },
        }
    ]

    report = analyzer.analyze_events(events)

    assert report.total_admin_logons == 1
    assert len(report.special_privileges) == 1
    priv = report.special_privileges[0]
    assert priv.subject_user_name == "Administrator"
    assert "SeDebugPrivilege" in priv.privilege_list
    assert len(priv.privilege_list) == 5


def test_suspicious_service_persistence(analyzer: WindowsSecurityAnalyzer) -> None:
    """Test detection of malicious service installation (Event 7045 / 4697)."""
    events = [
        {
            "EventID": 7045,
            "RecordId": 601,
            "Timestamp": "2026-03-22T13:00:00Z",
            "EventData": {
                "ServiceName": "WindowsUpdateHelper",
                "ImagePath": "powershell.exe -w hidden -enc SQBFAFgAKAA... -ep bypass",
                "ServiceType": "user mode service",
                "StartType": "auto start",
                "AccountName": "LocalSystem",
            },
        },
        {
            "EventID": 4697,
            "RecordId": 602,
            "Timestamp": "2026-03-22T13:05:00Z",
            "EventData": {
                "ServiceName": "TempService",
                "ServiceFileName": "C:\\Users\\Public\\malware.exe",
                "ServiceAccount": "LocalSystem",
            },
        },
    ]

    report = analyzer.analyze_events(events)

    assert report.verdict == "MALICIOUS"
    svc_anomalies = [
        a
        for a in report.anomalies
        if a.classification == SecurityThreatClassification.SUSPICIOUS_SERVICE_INSTALLATION
    ]
    assert len(svc_anomalies) == 2
    assert any("WindowsUpdateHelper" in ioc for ioc in report.extracted_iocs)


def test_suspicious_scheduled_task_persistence(analyzer: WindowsSecurityAnalyzer) -> None:
    """Test detection of malicious scheduled task creation (Event 4698)."""
    task_xml = (
        "<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>"
        "<Principals><Principal id='Author'><UserId>S-1-5-18</UserId></Principal></Principals>"
        "<Actions Context='Author'>"
        "<Exec><Command>cmd.exe</Command><Arguments>/c powershell -enc JABjAGwAaQBlAG4AdAA=</Arguments></Exec>"
        "</Actions>"
        "</Task>"
    )

    events = [
        {
            "EventID": 4698,
            "RecordId": 701,
            "Timestamp": "2026-03-22T14:00:00Z",
            "EventData": {
                "TaskName": "\\Microsoft\\Windows\\MaintenanceJob",
                "TaskContent": task_xml,
                "SubjectUserName": "Administrator",
            },
        }
    ]

    report = analyzer.analyze_events(events)

    assert report.verdict == "MALICIOUS"
    task_anomalies = [
        a
        for a in report.anomalies
        if a.classification == SecurityThreatClassification.SUSPICIOUS_SCHEDULED_TASK
    ]
    assert len(task_anomalies) == 1
    assert task_anomalies[0].severity == "CRITICAL"
    assert any("MaintenanceJob" in ioc for ioc in report.extracted_iocs)


def test_user_creation_and_domain_admin_escalation(analyzer: WindowsSecurityAnalyzer) -> None:
    """Test detection of rogue account creation and escalation to Domain Admins."""
    events = [
        {
            "EventID": 4720,
            "RecordId": 801,
            "Timestamp": "2026-03-22T15:00:00Z",
            "EventData": {
                "TargetUserName": "backdoor_admin",
                "TargetDomainName": "CORP",
                "SubjectUserName": "compromised_svc",
            },
        },
        {
            "EventID": 4728,
            "RecordId": 802,
            "Timestamp": "2026-03-22T15:02:00Z",
            "EventData": {
                "MemberName": "backdoor_admin",
                "TargetUserName": "Domain Admins",
                "SubjectUserName": "compromised_svc",
            },
        },
    ]

    report = analyzer.analyze_events(events)

    assert report.verdict == "MALICIOUS"
    anomalies = {a.classification for a in report.anomalies}
    assert SecurityThreatClassification.UNAUTHORIZED_ACCOUNT_CREATION in anomalies
    assert SecurityThreatClassification.PRIVILEGE_GROUP_ESCALATION in anomalies
    assert any("backdoor_admin" in ioc for ioc in report.extracted_iocs)


def test_master_timeline_synthesis(analyzer: WindowsSecurityAnalyzer) -> None:
    """Test synthesis of security events into sorted UTC TimelineEvents with delta calculations."""
    events = [
        {
            "EventID": 4624,
            "RecordId": 901,
            "Timestamp": "2026-03-22T16:00:00Z",
            "EventData": {"LogonType": "2", "TargetUserName": "analyst"},
        },
        {
            "EventID": 4672,
            "RecordId": 902,
            "Timestamp": "2026-03-22T16:00:05Z",
            "EventData": {"SubjectUserName": "analyst", "PrivilegeList": "SeDebugPrivilege"},
        },
        {
            "EventID": 7045,
            "RecordId": 903,
            "Timestamp": "2026-03-22T16:01:00Z",
            "EventData": {
                "ServiceName": "NormalSvc",
                "ImagePath": "C:\\Windows\\System32\\svchost.exe",
            },
        },
    ]

    report = analyzer.analyze_events(events)

    assert len(report.timeline_events) == 3
    assert report.timeline_events[0].event_type == "LOGON_SUCCESS"
    assert report.timeline_events[1].event_type == "SPECIAL_PRIVILEGE_ASSIGNED"
    assert report.timeline_events[2].event_type == "SERVICE_INSTALLED"

    # Verify delta timing
    assert report.timeline_events[1].time_delta_seconds == 5.0
    assert report.timeline_events[1].time_delta_formatted == "+5.0s"
    assert report.timeline_events[2].time_delta_seconds == 55.0


def test_benign_security_log_baseline(analyzer: WindowsSecurityAnalyzer) -> None:
    """Test benign security activity resulting in zero anomalies and BENIGN verdict."""
    events = [
        {
            "EventID": 4624,
            "RecordId": 991,
            "Timestamp": "2026-03-22T17:00:00Z",
            "EventData": {"LogonType": "2", "TargetUserName": "engineer", "IpAddress": "-"},
        },
        {
            "EventID": 4624,
            "RecordId": 992,
            "Timestamp": "2026-03-22T17:05:00Z",
            "EventData": {"LogonType": "5", "TargetUserName": "SYSTEM", "IpAddress": "-"},
        },
    ]

    report = analyzer.analyze_events(events)

    assert report.threat_score == 0.0
    assert report.verdict == "BENIGN"
    assert len(report.anomalies) == 0


def test_file_ingestion_and_error_handling(
    analyzer: WindowsSecurityAnalyzer, tmp_path: Path
) -> None:
    """Test analyze_file with on-disk JSON log and error handling for missing files."""
    log_file = tmp_path / "security_sample.json"
    log_file.write_text(
        json.dumps(
            [
                {
                    "EventID": 4624,
                    "RecordId": 1,
                    "Timestamp": "2026-03-22T18:00:00Z",
                    "EventData": {"LogonType": "2", "TargetUserName": "test_user"},
                }
            ]
        ),
        encoding="utf-8",
    )

    report = analyzer.analyze_file(log_file)
    assert report.filename == "security_sample.json"
    assert report.total_events_parsed == 1

    # Verify serialization
    data_dict = report.to_dict()
    assert isinstance(data_dict, dict)
    assert data_dict["verdict"] == "BENIGN"

    # Non-existent file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        analyzer.analyze_file(tmp_path / "missing_sec.evtx")
