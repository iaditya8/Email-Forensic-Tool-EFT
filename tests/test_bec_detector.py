"""Unit and integration tests for Business Email Compromise (BEC) and Spoofing Detection."""

import pytest

from eft.analysis.bec_detector import BECDetector
from eft.models.canonical import BECAnalysisReport, CanonicalEmail


@pytest.fixture
def detector() -> BECDetector:
    return BECDetector()


def test_vip_executive_impersonation(detector: BECDetector) -> None:
    """Validate detection of VIP executive display name impersonation sent via external/freemail accounts."""
    protected_execs = [
        {"name": "Satya Nadella", "email": "satya@microsoft.com", "title": "CEO"},
        {"name": "Tim Cook", "email": "tcook@apple.com", "title": "CEO"},
    ]

    # Malicious email impersonating Satya Nadella from Gmail
    email = CanonicalEmail(
        message_id="<bec-vip-test@example.com>",
        from_address='"Satya Nadella" <satya.nadella.ceo@gmail.com>',
        to_addresses=["employee@enterprise.com"],
        subject="Urgent request from Satya",
        body_plain="Are you at your desk? I need an urgent favor right now.",
    )

    report: BECAnalysisReport = detector.detect(
        email=email,
        protected_executives=protected_execs,
    )

    assert report.is_bec_suspected is True
    assert report.overall_threat_level == "CRITICAL_BEC"
    assert report.display_name_spoof_detected is True
    assert (
        report.impersonated_identity is not None and "Satya Nadella" in report.impersonated_identity
    )
    assert "VIP_IMPERSONATION" in report.flags
    assert report.threat_score >= 60.0


def test_embedded_email_display_name_spoof(detector: BECDetector) -> None:
    """Validate detection of embedded target email address inside display name."""
    email = CanonicalEmail(
        message_id="<embedded-email-test@example.com>",
        from_address='"payroll@acme-corp.com" <scammer-inbox@mail.ru>',
        to_addresses=["finance@acme-corp.com"],
        subject="Updated direct deposit form",
        body_plain="Please process my updated bank account for paycheck.",
    )

    report = detector.detect(email)

    assert report.is_bec_suspected is True
    assert report.display_name_spoof_detected is True
    assert "DISPLAY_NAME_EMBEDDED_EMAIL_SPOOF" in report.flags
    assert report.threat_score >= 60.0


def test_cousin_domain_typosquatting(detector: BECDetector) -> None:
    """Validate Levenshtein distance detection for lookalike / typosquatted cousin domains."""
    # micros0ft.com (distance 1 from microsoft.com)
    email_msft = CanonicalEmail(
        message_id="<typosquat-msft@example.com>",
        from_address='"Microsoft Account Security" <alert@micros0ft.com>',
        to_addresses=["user@acme.com"],
        subject="Security Notice",
    )
    report_msft = detector.detect(email_msft)
    assert report_msft.cousin_domain_detected is True
    assert "COUSIN_DOMAIN_TYPOSQUAT" in report_msft.flags
    assert report_msft.target_domain_simulated == "microsoft.com"

    # paypa1.com (distance 1 from paypal.com)
    email_paypal = CanonicalEmail(
        message_id="<typosquat-paypal@example.com>",
        from_address='"PayPal Support" <service@paypa1.com>',
        to_addresses=["user@acme.com"],
    )
    report_paypal = detector.detect(email_paypal)
    assert report_paypal.cousin_domain_detected is True
    assert "COUSIN_DOMAIN_TYPOSQUAT" in report_paypal.flags
    assert report_paypal.target_domain_simulated == "paypal.com"


def test_combosquatting_domain(detector: BECDetector) -> None:
    """Validate detection of deceptive combosquatted domains combining target brands with keywords."""
    email = CanonicalEmail(
        message_id="<combosquat@example.com>",
        from_address='"DocuSign Notification" <notify@docusign-signature-verify.com>',
        to_addresses=["recipient@company.com"],
    )
    report = detector.detect(email)
    assert report.cousin_domain_detected is True
    assert "COUSIN_DOMAIN_COMBOSQUAT" in report.flags
    assert report.target_domain_simulated == "docusign.com"


def test_reply_to_routing_mismatch(detector: BECDetector) -> None:
    """Validate detection of asymmetric response routing (From corporate vs Reply-To external)."""
    email = CanonicalEmail(
        message_id="<reply-to-mismatch@example.com>",
        from_address='"CEO Office" <ceo@corporation.com>',
        reply_to="attacker-drop@freemail.ru",
        to_addresses=["controller@corporation.com"],
        subject="Confidential invoice inquiry",
    )
    report = detector.detect(email)
    assert report.reply_to_mismatch_detected is True
    assert "REPLY_TO_DOMAIN_MISMATCH" in report.flags
    assert report.overall_threat_level in ("HIGH_RISK", "CRITICAL_BEC")


def test_bec_urgency_and_financial_keywords(detector: BECDetector) -> None:
    """Validate heuristic recognition of wire transfer, payroll, and executive urgency patterns."""
    email = CanonicalEmail(
        message_id="<bec-keywords@example.com>",
        from_address='"Vendor Billing" <billing@custom-supplier.com>',
        to_addresses=["ap@enterprise.com"],
        subject="Urgent wire transfer instructions for overdue invoice payment",
        body_plain="Please find attached our new banking details and routing number. Process this payment today.",
    )
    report = detector.detect(email)
    assert "BEC_URGENCY_KEYWORDS" in report.flags
    assert any("WIRE_TRANSFER_PAYMENT" in ind.description for ind in report.indicators)


def test_executive_title_from_freemail(detector: BECDetector) -> None:
    """Validate flagging of executive titles in display name sent from public consumer webmail."""
    email = CanonicalEmail(
        message_id="<cfo-freemail@example.com>",
        from_address='"Chief Financial Officer" <cfo.emergency@yahoo.com>',
        to_addresses=["accounting@enterprise.com"],
        subject="Quick question",
        body_plain="Are you available right now?",
    )
    report = detector.detect(email)
    assert "EXECUTIVE_TITLE_FREEMAIL_SPOOF" in report.flags
    assert report.threat_score >= 40.0


def test_clean_baseline_email(detector: BECDetector) -> None:
    """Validate that normal legitimate corporate emails produce a clean zero-risk report."""
    email = CanonicalEmail(
        message_id="<legit-meeting@enterprise.com>",
        from_address='"Alice Smith" <alice@enterprise.com>',
        to_addresses=["bob@enterprise.com"],
        subject="Sprint planning meeting notes",
        body_plain="Hi Bob, attached are the notes from our sprint planning session today. Best, Alice.",
    )
    report = detector.detect(email)
    assert report.is_bec_suspected is False
    assert report.overall_threat_level == "CLEAN"
    assert report.threat_score == 0.0
    assert len(report.indicators) == 0
    assert len(report.flags) == 0
