"""Comprehensive unit and integration tests for Domain & Email OSINT Intelligence Engine."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import pytest

from eft.analysis.domain_osint import DomainOSINTAnalyzer
from eft.models.osint import (
    DMARCEnforcement,
    DomainCategory,
    DomainOSINTReport,
    SPFStrictness,
)
from eft.models.threat import RiskSeverity


@pytest.fixture
def analyzer(tmp_path: Path) -> DomainOSINTAnalyzer:
    # Use workspace watchlist.json if available
    watchlist_file = Path("watchlist.json")
    return DomainOSINTAnalyzer(watchlist_path=watchlist_file if watchlist_file.exists() else None)


# ---------------------------------------------------------------------------
# 1. Target Normalization & Parsing Tests
# ---------------------------------------------------------------------------


def test_normalize_plain_domain(analyzer: DomainOSINTAnalyzer):
    info = analyzer._normalize_target("example.com")
    assert info["analyzed_domain"] == "example.com"
    assert info["registered_domain"] == "example.com"
    assert info["tld"] == "com"
    assert info["username"] is None
    assert info["is_email_address"] is False
    assert info["is_punycode"] is False


def test_normalize_email_address(analyzer: DomainOSINTAnalyzer):
    info = analyzer._normalize_target("Executive User <exec.user@sub.corp.acme.com>")
    assert info["analyzed_domain"] == "sub.corp.acme.com"
    assert info["registered_domain"] == "acme.com"
    assert info["tld"] == "com"
    assert info["username"] == "exec.user"
    assert info["is_email_address"] is True


def test_normalize_url_target(analyzer: DomainOSINTAnalyzer):
    info = analyzer._normalize_target("https://portal.bankofamerica.com/login/auth")
    assert info["analyzed_domain"] == "portal.bankofamerica.com"
    assert info["registered_domain"] == "bankofamerica.com"
    assert info["tld"] == "com"


def test_normalize_punycode_and_homoglyph_domain(analyzer: DomainOSINTAnalyzer):
    # Cyrillic 'а' in pаypal
    homoglyph_target = "pаypal.com"
    info = analyzer._normalize_target(homoglyph_target)
    assert info["is_punycode"] is True
    assert "xn--" in info["analyzed_domain"]


# ---------------------------------------------------------------------------
# 2. DNS Authentication Posture & SPF/DMARC Tests (Offline / Simulated)
# ---------------------------------------------------------------------------


def test_dns_spf_strict_hardfail(analyzer: DomainOSINTAnalyzer):
    custom_records: Dict[str, Dict[str, List[str]]] = {
        "secure-corp.com": {
            "TXT": ["v=spf1 ip4:192.0.2.1 include:_spf.google.com -all"],
            "MX": ["10 mail.secure-corp.com"],
            "A": ["192.0.2.1"],
        },
        "_dmarc.secure-corp.com": {
            "TXT": ["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@secure-corp.com"],
        },
    }

    report: DomainOSINTReport = analyzer.analyze(
        "security@secure-corp.com",
        offline=True,
        custom_dns_records=custom_records,
    )

    assert report.dns_posture.has_mx is True
    assert report.dns_posture.spf.strictness == SPFStrictness.STRICT
    assert report.dns_posture.spf.qualifier == "-all"
    assert report.dns_posture.spf.is_valid is True

    assert report.dns_posture.dmarc.enforcement == DMARCEnforcement.REJECT
    assert report.dns_posture.dmarc.policy == "reject"
    assert report.dns_posture.dmarc.rua_uris == ["mailto:dmarc-reports@secure-corp.com"]
    assert report.reputation_score <= 10.0
    assert report.risk_level in {RiskSeverity.CLEAN, RiskSeverity.SUSPICIOUS_LOW}


def test_dns_spf_dangerous_permissive_qualifier(analyzer: DomainOSINTAnalyzer):
    custom_records: Dict[str, Dict[str, List[str]]] = {
        "bad-config.org": {
            "TXT": ["v=spf1 +all"],
            "MX": ["10 mail.bad-config.org"],
            "A": ["198.51.100.1"],
        },
        "_dmarc.bad-config.org": {
            "TXT": ["v=DMARC1; p=none"],
        },
    }

    report = analyzer.analyze(
        "admin@bad-config.org", offline=True, custom_dns_records=custom_records
    )

    assert report.dns_posture.spf.strictness == SPFStrictness.PERMISSIVE
    assert report.dns_posture.spf.is_valid is False
    assert any("permissive qualifier (+all" in w for w in report.dns_posture.spf.warnings)

    assert report.dns_posture.dmarc.enforcement == DMARCEnforcement.NONE
    assert report.reputation_score >= 35.0


def test_dns_missing_spf_and_missing_dmarc(analyzer: DomainOSINTAnalyzer):
    custom_records: Dict[str, Dict[str, List[str]]] = {
        "unprotected-domain.net": {
            "MX": ["10 mail.unprotected-domain.net"],
            "A": ["203.0.113.5"],
            "TXT": [],
        }
    }

    report = analyzer.analyze(
        "user@unprotected-domain.net", offline=True, custom_dns_records=custom_records
    )

    assert report.dns_posture.spf.strictness == SPFStrictness.MISSING
    assert report.dns_posture.dmarc.enforcement == DMARCEnforcement.MISSING
    assert report.reputation_score >= 30.0
    assert any(f.name == "Missing SPF Record" for f in report.risk_factors)
    assert any(f.name == "Missing DMARC Policy" for f in report.risk_factors)


def test_dns_multiple_spf_records_warning(analyzer: DomainOSINTAnalyzer):
    custom_records: Dict[str, Dict[str, List[str]]] = {
        "multi-spf.com": {
            "TXT": [
                "v=spf1 ip4:192.0.2.1 ~all",
                "v=spf1 include:_spf.salesforce.com ~all",
            ],
            "MX": ["10 mail.multi-spf.com"],
        }
    }

    report = analyzer.analyze("multi-spf.com", offline=True, custom_dns_records=custom_records)
    assert report.dns_posture.spf.strictness == SPFStrictness.INVALID
    assert any("Multiple SPF records found" in w for w in report.dns_posture.spf.warnings)


# ---------------------------------------------------------------------------
# 3. DKIM Selector Discovery & BIMI Tests
# ---------------------------------------------------------------------------


def test_dkim_selector_discovery(analyzer: DomainOSINTAnalyzer):
    custom_records: Dict[str, Dict[str, List[str]]] = {
        "enterprise.corp": {
            "MX": ["10 mail.enterprise.corp"],
            "TXT": ["v=spf1 -all"],
        },
        "google._domainkey.enterprise.corp": {
            "TXT": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0..."],
        },
        "default._bimi.enterprise.corp": {
            "TXT": [
                "v=BIMI1; l=https://enterprise.corp/logo.svg; a=https://enterprise.corp/vmc.pem"
            ],
        },
    }

    report = analyzer.analyze("enterprise.corp", offline=True, custom_dns_records=custom_records)

    assert len(report.dns_posture.discovered_dkim) == 1
    dkim = report.dns_posture.discovered_dkim[0]
    assert dkim.selector == "google"
    assert dkim.key_type == "rsa"
    assert dkim.is_valid is True

    assert report.dns_posture.bimi.is_valid is True
    assert report.dns_posture.bimi.has_vmc is True
    assert report.dns_posture.bimi.logo_url == "https://enterprise.corp/logo.svg"


# ---------------------------------------------------------------------------
# 4. Homoglyph, Lookalike & Typosquatting Brand Match Tests
# ---------------------------------------------------------------------------


def test_brand_exact_match_is_clean(analyzer: DomainOSINTAnalyzer):
    # Official brand domain in watchlist
    custom_records: Dict[str, Dict[str, List[str]]] = {
        "microsoft.com": {
            "MX": ["10 microsoft-com.mail.protection.outlook.com"],
            "TXT": ["v=spf1 include:_spf-a.microsoft.com -all"],
        },
        "_dmarc.microsoft.com": {
            "TXT": ["v=DMARC1; p=reject; pct=100; rua=mailto:d@rua.ag.ms"],
        },
    }

    report = analyzer.analyze("microsoft.com", offline=True, custom_dns_records=custom_records)
    assert report.brand_risk is not None
    assert report.brand_risk.risk_indicator == "CLEAN"
    assert report.brand_risk.levenshtein_distance == 0
    assert report.brand_risk.similarity_score == 1.0
    assert report.category == DomainCategory.CORPORATE


def test_typosquat_lookalike_detection(analyzer: DomainOSINTAnalyzer):
    # Typosquatted microsoft
    custom_records: Dict[str, Dict[str, List[str]]] = {
        "micros0ft.com": {
            "MX": ["10 mail.evil-relay.net"],
            "TXT": [],
        }
    }

    report = analyzer.analyze(
        "support@micros0ft.com", offline=True, custom_dns_records=custom_records
    )
    assert report.brand_risk is not None
    assert report.brand_risk.matched_brand_domain == "microsoft.com"
    assert report.brand_risk.risk_indicator in {"CRITICAL", "HIGH_RISK"}
    assert report.category == DomainCategory.LOOKALIKE
    assert report.reputation_score >= 50.0
    assert report.risk_level in {RiskSeverity.MALICIOUS_HIGH, RiskSeverity.CRITICAL}


def test_homoglyph_cyrillic_lookalike_attack(analyzer: DomainOSINTAnalyzer):
    # pаypal with Cyrillic 'а'
    target = "pаypal.com"
    custom_records: Dict[str, Dict[str, List[str]]] = {
        "xn--pypal-47a.com": {
            "MX": ["10 mx.attacker.ru"],
        }
    }

    report = analyzer.analyze(target, offline=True, custom_dns_records=custom_records)
    assert report.brand_risk is not None
    assert report.brand_risk.has_homoglyphs is True
    assert report.brand_risk.risk_indicator == "CRITICAL"
    assert report.reputation_score >= 70.0
    assert report.risk_level == RiskSeverity.CRITICAL


# ---------------------------------------------------------------------------
# 5. Disposable Email & Freemail Tests
# ---------------------------------------------------------------------------


def test_disposable_email_domain_detection(analyzer: DomainOSINTAnalyzer):
    custom_records: Dict[str, Dict[str, List[str]]] = {
        "mailinator.com": {
            "MX": ["10 mail.mailinator.com"],
        }
    }

    report = analyzer.analyze(
        "hacker@mailinator.com", offline=True, custom_dns_records=custom_records
    )
    assert report.category == DomainCategory.DISPOSABLE
    assert report.disposable_service is not None
    assert report.reputation_score >= 40.0
    assert any("Disposable" in f.name for f in report.risk_factors)


def test_freemail_provider_classification(analyzer: DomainOSINTAnalyzer):
    custom_records: Dict[str, Dict[str, List[str]]] = {
        "gmail.com": {
            "MX": ["5 gmail-smtp-in.l.google.com"],
            "TXT": ["v=spf1 redirect=_spf.google.com"],
        },
        "_dmarc.gmail.com": {
            "TXT": ["v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"],
        },
    }

    report = analyzer.analyze("john.doe@gmail.com", offline=True, custom_dns_records=custom_records)
    assert report.category == DomainCategory.FREEMAIL
    assert report.freemail_provider is not None


# ---------------------------------------------------------------------------
# 6. Trusted MX Vendor Recognition
# ---------------------------------------------------------------------------


def test_trusted_partner_vendor_mx_match(analyzer: DomainOSINTAnalyzer):
    custom_records: Dict[str, Dict[str, List[str]]] = {
        "acme-vendor.com": {
            "MX": ["10 enterprise-acme.mail.protection.outlook.com"],
            "TXT": ["v=spf1 include:spf.protection.outlook.com -all"],
        },
        "_dmarc.acme-vendor.com": {
            "TXT": ["v=DMARC1; p=reject"],
        },
    }

    report = analyzer.analyze(
        "billing@acme-vendor.com", offline=True, custom_dns_records=custom_records
    )
    assert len(report.dns_posture.mx_records) == 1
    mx = report.dns_posture.mx_records[0]
    assert mx.matches_trusted_vendor is True
    assert mx.trusted_vendor_name == "Microsoft 365"


# ---------------------------------------------------------------------------
# 7. Unresolved / Parked Domain Test
# ---------------------------------------------------------------------------


def test_unresolved_inactive_domain(analyzer: DomainOSINTAnalyzer):
    custom_records: Dict[str, Dict[str, List[str]]] = {"completely-dead-domain-xyz.net": {}}

    report = analyzer.analyze(
        "user@completely-dead-domain-xyz.net", offline=True, custom_dns_records=custom_records
    )
    assert report.category == DomainCategory.UNRESOLVED
    assert report.dns_posture.has_mx is False
    assert len(report.dns_posture.a_records) == 0
    assert report.reputation_score >= 35.0


# ---------------------------------------------------------------------------
# 8. Serialization & Helper Methods
# ---------------------------------------------------------------------------


def test_report_serialization_to_dict(analyzer: DomainOSINTAnalyzer):
    custom_records: Dict[str, Dict[str, List[str]]] = {
        "acme.com": {
            "MX": ["10 mail.acme.com"],
            "TXT": ["v=spf1 -all"],
        },
        "_dmarc.acme.com": {
            "TXT": ["v=DMARC1; p=reject"],
        },
    }

    report = analyzer.analyze("info@acme.com", offline=True, custom_dns_records=custom_records)
    d = report.to_dict()

    assert isinstance(d, dict)
    assert d["analyzed_domain"] == "acme.com"
    assert "dns_posture" in d
    assert "reputation_score" in d
    assert "risk_level" in d
    assert isinstance(d["risk_factors"], list)
    assert isinstance(d["remediation_advice"], list)
