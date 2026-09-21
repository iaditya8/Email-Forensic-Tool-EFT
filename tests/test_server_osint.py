"""Integration tests for Server OSINT REST API (/api/osint/lookup) and Dashboard OSINT UI."""

from fastapi.testclient import TestClient

from eft.server.app import create_app

client = TestClient(create_app())


def test_api_osint_lookup_domain_offline() -> None:
    """Verify POST /api/osint/lookup returns structured domain intelligence."""
    res = client.post(
        "/api/osint/lookup",
        json={"target": "example.com", "offline": True, "dns_timeout": 3.0},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    report = data["report"]
    assert report["input_target"] == "example.com"
    assert report["analyzed_domain"] == "example.com"
    assert report["registered_domain"] == "example.com"
    assert "dns_posture" in report
    assert "reputation_score" in report
    assert "risk_factors" in report
    assert "remediation_advice" in report


def test_api_osint_lookup_email_offline() -> None:
    """Verify POST /api/osint/lookup correctly parses and inspects email addresses."""
    res = client.post(
        "/api/osint/lookup",
        json={"target": "investigator@forensics.corp", "offline": True},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    report = data["report"]
    assert report["input_target"] == "investigator@forensics.corp"
    assert report["username"] == "investigator"
    assert report["analyzed_domain"] == "forensics.corp"
    assert report["is_email_address"] is True


def test_api_osint_lookup_lookalike_brand() -> None:
    """Verify POST /api/osint/lookup detects lookalike homoglyph brand targeting."""
    res = client.post(
        "/api/osint/lookup",
        json={"target": "micros0ft.com", "offline": True},
    )
    assert res.status_code == 200
    data = res.json()
    report = data["report"]
    assert report["brand_risk"] is not None
    assert report["brand_risk"]["matched_brand_domain"] == "microsoft.com"
    assert report["reputation_score"] >= 40.0


def test_api_osint_lookup_disposable_domain() -> None:
    """Verify POST /api/osint/lookup flags disposable temporary mailboxes."""
    res = client.post(
        "/api/osint/lookup",
        json={"target": "throwaway@temp-mail.org", "offline": True},
    )
    assert res.status_code == 200
    data = res.json()
    report = data["report"]
    assert report["category"] == "Disposable / Temporary Email Service"
    assert report["disposable_service"] is not None


def test_api_osint_lookup_empty_target() -> None:
    """Verify POST /api/osint/lookup validates non-empty target input."""
    res = client.post(
        "/api/osint/lookup",
        json={"target": "   ", "offline": True},
    )
    assert res.status_code == 400
    assert "required" in res.json()["detail"].lower()


def test_dashboard_html_contains_osint_components() -> None:
    """Verify GET / dashboard contains OSINT Inspector tab, switcher, and panels."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.text
    assert "Domain & Email OSINT Inspector" in html
    assert "osint-mode-container" in html
    assert "osint-target-input" in html
    assert "osint-submit-btn" in html
    assert "switchMainMode" in html
    assert "renderEmailSenderOSINT" in html
    assert "tab-osint" in html
