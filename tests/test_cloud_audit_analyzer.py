"""Unit tests for CloudAuditAnalyzer, M365 UAL, and Google Workspace audit log forensics."""

import json
from pathlib import Path
from typing import Any

import pytest

from eft.analysis.cloud_audit_analyzer import CloudAuditAnalyzer
from eft.models.cloud_audit import (
    CloudProvider,
    CloudThreatClassification,
)


@pytest.fixture
def analyzer() -> CloudAuditAnalyzer:
    """Fixture providing an instance of CloudAuditAnalyzer."""
    return CloudAuditAnalyzer()


def test_m365_inbox_rule_external_forwarding(analyzer: CloudAuditAnalyzer) -> None:
    """Test detection of M365 inbox rule configured for external automated email exfiltration."""
    events = [
        {
            "CreationTime": "2026-03-22T10:00:00Z",
            "Operation": "New-InboxRule",
            "UserId": "cfo@enterprise.com",
            "ClientIP": "198.51.100.22",
            "Workload": "Exchange",
            "Parameters": [
                {"Name": "Name", "Value": "ForwardFinancials"},
                {"Name": "ForwardTo", "Value": "attacker@darkweb-exfil.xyz"},
                {"Name": "SubjectContainsWords", "Value": "invoice, payment, wire, swift"},
            ],
        }
    ]

    report = analyzer.analyze_records(events, detected_provider=CloudProvider.M365)

    assert report.total_records_parsed == 1
    assert report.total_inbox_rules == 1
    assert report.verdict == "MALICIOUS"
    assert report.threat_score >= 40.0

    fwd_anomalies = [
        a
        for a in report.anomalies
        if a.classification == CloudThreatClassification.EXTERNAL_FORWARDING
    ]
    assert len(fwd_anomalies) == 1
    assert fwd_anomalies[0].severity == "CRITICAL"
    assert "attacker@darkweb-exfil.xyz" in report.external_forwarding_destinations
    assert any("attacker@darkweb-exfil.xyz" in ioc for ioc in report.extracted_iocs)


def test_m365_inbox_rule_email_hiding(analyzer: CloudAuditAnalyzer) -> None:
    """Test detection of BEC email hiding rule moving alerts to RSS Feeds folder and auto-deleting."""
    events = [
        {
            "CreationTime": "2026-03-22T11:00:00Z",
            "Operation": "Set-InboxRule",
            "UserId": "victim@enterprise.com",
            "ClientIP": "203.0.113.88",
            "AuditData": json.dumps(
                {
                    "Operation": "Set-InboxRule",
                    "UserId": "victim@enterprise.com",
                    "Parameters": [
                        {"Name": "Name", "Value": "CleanRule"},
                        {"Name": "MoveToFolder", "Value": "RSS Feeds"},
                        {"Name": "DeleteMessage", "Value": "true"},
                        {
                            "Name": "SubjectContainsWords",
                            "Value": "security, alert, fraud, password",
                        },
                    ],
                }
            ),
        }
    ]

    report = analyzer.analyze_records(events, detected_provider=CloudProvider.M365)

    assert report.verdict == "MALICIOUS"
    hiding_anomalies = [
        a
        for a in report.anomalies
        if a.classification == CloudThreatClassification.EMAIL_HIDING_RULE
    ]
    assert len(hiding_anomalies) == 1
    assert hiding_anomalies[0].severity == "CRITICAL"
    assert "T1564.008" in (hiding_anomalies[0].mitre_attack_technique or "")


def test_m365_mailbox_delegation_backdoor(analyzer: CloudAuditAnalyzer) -> None:
    """Test detection of FullAccess mailbox delegation granted to external/rogue user."""
    events = [
        {
            "CreationTime": "2026-03-22T12:00:00Z",
            "Operation": "Add-MailboxPermission",
            "UserId": "admin@enterprise.com",
            "ClientIP": "198.51.100.99",
            "Parameters": [
                {"Name": "Identity", "Value": "ceo@enterprise.com"},
                {"Name": "User", "Value": "adversary@gmail.com"},
                {"Name": "AccessRights", "Value": "FullAccess"},
            ],
        }
    ]

    report = analyzer.analyze_records(events, detected_provider=CloudProvider.M365)

    assert report.total_mailbox_delegations == 1
    assert report.verdict == "MALICIOUS"
    del_anomalies = [
        a
        for a in report.anomalies
        if a.classification == CloudThreatClassification.UNAUTHORIZED_MAILBOX_DELEGATION
    ]
    assert len(del_anomalies) == 1
    assert any("adversary@gmail.com" in ioc for ioc in report.extracted_iocs)


def test_illicit_oauth_application_consent(analyzer: CloudAuditAnalyzer) -> None:
    """Test detection of illicit OAuth application consent grant targeting mailbox read/send scopes."""
    events = [
        {
            "CreationTime": "2026-03-22T13:00:00Z",
            "Operation": "Consent to application.",
            "UserId": "executive@enterprise.com",
            "ClientIP": "192.0.2.45",
            "Target": [{"name": "PDF Viewer Enterprise"}],
            "Scope": "openid profile Mail.ReadWrite Mail.Send offline_access",
            "AppId": "00000003-0000-0000-c000-000000000000",
        }
    ]

    report = analyzer.analyze_records(events, detected_provider=CloudProvider.M365)

    assert report.total_oauth_consents == 1
    assert report.verdict == "MALICIOUS"
    oauth_anomalies = [
        a
        for a in report.anomalies
        if a.classification == CloudThreatClassification.ILLICIT_OAUTH_CONSENT
    ]
    assert len(oauth_anomalies) == 1
    assert oauth_anomalies[0].severity == "CRITICAL"
    assert "T1528" in (oauth_anomalies[0].mitre_attack_technique or "")


def test_impossible_travel_login_detection(analyzer: CloudAuditAnalyzer) -> None:
    """Test detection of impossible travel between disparate geolocations within 15 minutes."""
    events = [
        {
            "CreationTime": "2026-03-22T14:00:00Z",
            "Operation": "UserLoggedIn",
            "UserId": "sales_lead@enterprise.com",
            "ClientIP": "198.51.100.1",
            "Country": "US",
            "City": "New York",
            "ResultStatus": "Success",
        },
        {
            "CreationTime": "2026-03-22T14:15:00Z",
            "Operation": "UserLoggedIn",
            "UserId": "sales_lead@enterprise.com",
            "ClientIP": "203.0.113.77",
            "Country": "RO",
            "City": "Bucharest",
            "ResultStatus": "Success",
        },
    ]

    report = analyzer.analyze_records(events, detected_provider=CloudProvider.M365)

    assert report.total_logins == 2
    assert report.verdict == "MALICIOUS"
    travel_anomalies = [
        a
        for a in report.anomalies
        if a.classification == CloudThreatClassification.IMPOSSIBLE_TRAVEL_LOGIN
    ]
    assert len(travel_anomalies) == 1
    assert (
        "US" in travel_anomalies[0].detection_reason
        and "RO" in travel_anomalies[0].detection_reason
    )


def test_google_workspace_reports_api_format(analyzer: CloudAuditAnalyzer) -> None:
    """Test parsing Google Workspace Admin audit Reports API JSON format."""
    google_json = {
        "items": [
            {
                "id": {"time": "2026-03-22T15:00:00Z", "uniqueQualifier": "g-101"},
                "actor": {"email": "admin@workspace-org.com"},
                "ipAddress": "198.51.100.55",
                "events": [
                    {
                        "name": "CHANGE_USER_SETTING",
                        "type": "EMAIL_ROUTING",
                        "parameters": [
                            {"name": "SETTING_NAME", "value": "AUTO_FORWARDING"},
                            {"name": "FORWARD_TO", "value": "exfil@external.com"},
                        ],
                    }
                ],
            }
        ]
    }

    report = analyzer.analyze_bytes(
        json.dumps(google_json).encode("utf-8"), filename="google_audit.json"
    )

    assert report.detected_provider == CloudProvider.GOOGLE_WORKSPACE
    assert report.total_records_parsed == 1
    assert len(report.google_admin_events) == 1
    assert len(report.anomalies) >= 1
    assert report.anomalies[0].classification == CloudThreatClassification.SUSPICIOUS_ADMIN_ACTIVITY


def test_m365_csv_export_parsing(analyzer: CloudAuditAnalyzer) -> None:
    """Test parsing M365 Unified Audit Log CSV export."""
    csv_content = (
        "CreationDate,UserIds,Operations,RecordType,ResultStatus,AuditData\n"
        '2026-03-22T16:00:00Z,user@corp.com,New-InboxRule,ExchangeItem,Success,"{""Operation"":""New-InboxRule"",""UserId"":""user@corp.com"",""Parameters"":[{""Name"":""ForwardTo"",""Value"":""bad@evil.com""}]}"\n'
    )

    report = analyzer.analyze_bytes(csv_content.encode("utf-8"), filename="m365_ual.csv")

    assert report.detected_provider == CloudProvider.M365
    assert report.total_records_parsed == 1
    assert report.total_inbox_rules == 1
    assert report.verdict == "MALICIOUS"


def test_benign_cloud_baseline(analyzer: CloudAuditAnalyzer) -> None:
    """Test normal cloud activity producing 0 score and BENIGN verdict."""
    events = [
        {
            "CreationTime": "2026-03-22T17:00:00Z",
            "Operation": "UserLoggedIn",
            "UserId": "normal_user@enterprise.com",
            "ClientIP": "10.0.0.1",
            "Country": "US",
            "City": "Austin",
            "ResultStatus": "Success",
        }
    ]

    report = analyzer.analyze_records(events)

    assert report.threat_score == 0.0
    assert report.verdict == "BENIGN"
    assert len(report.anomalies) == 0


def test_cloud_timeline_synthesis(analyzer: CloudAuditAnalyzer) -> None:
    """Test synthesis of cloud events into sorted UTC TimelineEvents with delta calculations."""
    events: list[dict[str, Any]] = [
        {
            "CreationTime": "2026-03-22T18:00:00Z",
            "Operation": "UserLoggedIn",
            "UserId": "analyst@enterprise.com",
            "ClientIP": "10.0.0.2",
            "ResultStatus": "Success",
        },
        {
            "CreationTime": "2026-03-22T18:00:30Z",
            "Operation": "New-InboxRule",
            "UserId": "analyst@enterprise.com",
            "Parameters": [{"Name": "Name", "Value": "TestRule"}],
        },
    ]

    report = analyzer.analyze_records(events)

    assert len(report.timeline_events) == 2
    assert report.timeline_events[0].event_type == "CLOUD_LOGIN_SUCCESS"
    assert report.timeline_events[1].event_type == "CLOUD_INBOX_RULE_CREATED"
    assert report.timeline_events[1].time_delta_seconds == 30.0
    assert report.timeline_events[1].time_delta_formatted == "+30.0s"


def test_file_ingestion_and_error_handling(analyzer: CloudAuditAnalyzer, tmp_path: Path) -> None:
    """Test analyze_file with on-disk JSON log and error handling for missing files."""
    log_file = tmp_path / "cloud_sample.json"
    log_file.write_text(
        json.dumps(
            [
                {
                    "CreationTime": "2026-03-22T19:00:00Z",
                    "Operation": "UserLoggedIn",
                    "UserId": "test@enterprise.com",
                    "ClientIP": "127.0.0.1",
                    "ResultStatus": "Success",
                }
            ]
        ),
        encoding="utf-8",
    )

    report = analyzer.analyze_file(log_file)
    assert report.filename == "cloud_sample.json"
    assert report.total_records_parsed == 1

    # Verify serialization
    data_dict = report.to_dict()
    assert isinstance(data_dict, dict)
    assert data_dict["verdict"] == "BENIGN"

    # Non-existent file error
    with pytest.raises(FileNotFoundError):
        analyzer.analyze_file(tmp_path / "missing_cloud.json")
