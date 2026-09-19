"""Composite Forensic Threat Scoring and Risk Attribution Engine."""

from __future__ import annotations

from typing import Dict, List

from eft.models.canonical import CanonicalEmail
from eft.models.threat import (
    CompositeRiskReport,
    RiskFactor,
    RiskSeverity,
    RiskVectorType,
    VectorRiskScore,
)


class ThreatScorer:
    """Forensic composite threat scoring engine evaluating all threat vectors."""

    MAX_SCORES: Dict[RiskVectorType, float] = {
        RiskVectorType.AUTHENTICATION: 25.0,
        RiskVectorType.PHISHING_URL: 25.0,
        RiskVectorType.BEC_SOCIAL_ENGINEERING: 20.0,
        RiskVectorType.ATTACHMENT_MALWARE: 20.0,
        RiskVectorType.OBFUSCATION_TRANSIT: 10.0,
    }

    @classmethod
    def calculate_composite_risk(cls, email_obj: CanonicalEmail) -> CompositeRiskReport:
        """Calculate the comprehensive composite risk score for a canonical email.

        Args:
            email_obj: The CanonicalEmail instance to evaluate.

        Returns:
            CompositeRiskReport containing overall score, severity, breakdown, and remediation.
        """
        all_factors: List[RiskFactor] = []
        vector_scores: Dict[str, VectorRiskScore] = {}

        # 1. Authentication & Spoofing Vector (Max 25)
        auth_factors = cls._evaluate_authentication(email_obj)
        auth_score = min(
            cls.MAX_SCORES[RiskVectorType.AUTHENTICATION],
            sum(f.score_contribution for f in auth_factors),
        )
        vector_scores[RiskVectorType.AUTHENTICATION.value] = VectorRiskScore(
            vector=RiskVectorType.AUTHENTICATION,
            score=round(auth_score, 1),
            max_score=cls.MAX_SCORES[RiskVectorType.AUTHENTICATION],
            factors=auth_factors,
        )
        all_factors.extend(auth_factors)

        # 2. Phishing & Malicious Links Vector (Max 25)
        phish_factors = cls._evaluate_phishing_urls(email_obj)
        phish_score = min(
            cls.MAX_SCORES[RiskVectorType.PHISHING_URL],
            sum(f.score_contribution for f in phish_factors),
        )
        vector_scores[RiskVectorType.PHISHING_URL.value] = VectorRiskScore(
            vector=RiskVectorType.PHISHING_URL,
            score=round(phish_score, 1),
            max_score=cls.MAX_SCORES[RiskVectorType.PHISHING_URL],
            factors=phish_factors,
        )
        all_factors.extend(phish_factors)

        # 3. BEC & Social Engineering Vector (Max 20)
        bec_factors = cls._evaluate_bec_social_engineering(email_obj)
        bec_score = min(
            cls.MAX_SCORES[RiskVectorType.BEC_SOCIAL_ENGINEERING],
            sum(f.score_contribution for f in bec_factors),
        )
        vector_scores[RiskVectorType.BEC_SOCIAL_ENGINEERING.value] = VectorRiskScore(
            vector=RiskVectorType.BEC_SOCIAL_ENGINEERING,
            score=round(bec_score, 1),
            max_score=cls.MAX_SCORES[RiskVectorType.BEC_SOCIAL_ENGINEERING],
            factors=bec_factors,
        )
        all_factors.extend(bec_factors)

        # 4. Attachments & Malware Vector (Max 20)
        malware_factors = cls._evaluate_attachments_malware(email_obj)
        malware_score = min(
            cls.MAX_SCORES[RiskVectorType.ATTACHMENT_MALWARE],
            sum(f.score_contribution for f in malware_factors),
        )
        vector_scores[RiskVectorType.ATTACHMENT_MALWARE.value] = VectorRiskScore(
            vector=RiskVectorType.ATTACHMENT_MALWARE,
            score=round(malware_score, 1),
            max_score=cls.MAX_SCORES[RiskVectorType.ATTACHMENT_MALWARE],
            factors=malware_factors,
        )
        all_factors.extend(malware_factors)

        # 5. Content Obfuscation & Transit Anomalies Vector (Max 10)
        obfuscation_factors = cls._evaluate_obfuscation_transit(email_obj)
        obf_score = min(
            cls.MAX_SCORES[RiskVectorType.OBFUSCATION_TRANSIT],
            sum(f.score_contribution for f in obfuscation_factors),
        )
        vector_scores[RiskVectorType.OBFUSCATION_TRANSIT.value] = VectorRiskScore(
            vector=RiskVectorType.OBFUSCATION_TRANSIT,
            score=round(obf_score, 1),
            max_score=cls.MAX_SCORES[RiskVectorType.OBFUSCATION_TRANSIT],
            factors=obfuscation_factors,
        )
        all_factors.extend(obfuscation_factors)

        # Calculate Total Composite Score
        total_score = round(auth_score + phish_score + bec_score + malware_score + obf_score, 1)
        total_score = max(0.0, min(100.0, total_score))

        # Determine Risk Severity Level
        severity = cls._determine_severity(total_score, all_factors)

        # Synthesize Summary and Action
        action, summary = cls._synthesize_recommendation(severity, total_score, all_factors)

        return CompositeRiskReport(
            overall_score=total_score,
            risk_level=severity,
            confidence_score=0.95 if all_factors else 1.0,
            vector_breakdown=vector_scores,
            all_factors=all_factors,
            recommended_action=action,
            summary=summary,
        )

    @classmethod
    def _evaluate_authentication(cls, email_obj: CanonicalEmail) -> List[RiskFactor]:
        """Evaluate authentication, SPF, DKIM, DMARC, and ARC signals."""
        factors: List[RiskFactor] = []

        auth_rep = email_obj.authentication_report or getattr(email_obj, "auth_report", None)
        spf_res = (
            getattr(auth_rep, "spf", None)
            or getattr(auth_rep, "spf_result", None)
            or getattr(email_obj, "spf_result", None)
        )
        dkim_res = (
            getattr(auth_rep, "dkim_signatures", None)
            or getattr(auth_rep, "dkim_results", None)
            or getattr(email_obj, "dkim_results", [])
        )
        dmarc_res = (
            getattr(auth_rep, "dmarc", None)
            or getattr(auth_rep, "dmarc_result", None)
            or getattr(email_obj, "dmarc_result", None)
        )
        arc_res = (
            getattr(auth_rep, "arc", None)
            or getattr(auth_rep, "arc_chain", None)
            or getattr(email_obj, "arc_chain", None)
        )

        # Check SPF
        if spf_res:
            status = spf_res.status.lower()
            if status in ("fail", "permerror"):
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.AUTHENTICATION,
                        name="SPF Validation Failure",
                        score_contribution=10.0,
                        severity="HIGH",
                        description=f"SPF record validation returned '{status}' for sender IP {spf_res.sender_ip or 'unknown'}.",
                        evidence_reference=f"SPF Status: {status}",
                    )
                )
            elif status == "softfail":
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.AUTHENTICATION,
                        name="SPF SoftFail",
                        score_contribution=5.0,
                        severity="MEDIUM",
                        description="SPF returned SoftFail (~all), indicating sender IP is not explicitly authorized.",
                        evidence_reference="SPF Status: softfail",
                    )
                )

        # Check DKIM
        if dkim_res:
            failed_dkim = [
                d for d in dkim_res if d.status.lower() in ("fail", "permerror", "temperror")
            ]
            if failed_dkim and not any(d.status.lower() == "pass" for d in dkim_res):
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.AUTHENTICATION,
                        name="DKIM Cryptographic Signature Invalid",
                        score_contribution=10.0,
                        severity="HIGH",
                        description="All DKIM cryptographic signatures failed cryptographic or canonical verification.",
                        evidence_reference=f"DKIM Selector: {failed_dkim[0].selector or 'N/A'}",
                    )
                )

        # Check DMARC
        if dmarc_res:
            dmarc_status = getattr(dmarc_res, "status", "none").lower()
            dmarc_passed = (dmarc_status == "pass") or getattr(dmarc_res, "passed", False)
            if not dmarc_passed and dmarc_status in (
                "fail",
                "permerror",
                "temperror",
            ):
                dmarc_policy = getattr(dmarc_res, "policy", "none").lower()
                contrib = 15.0 if dmarc_policy in ("reject", "quarantine") else 10.0
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.AUTHENTICATION,
                        name="DMARC Policy Alignment Failure",
                        score_contribution=contrib,
                        severity="CRITICAL" if dmarc_policy == "reject" else "HIGH",
                        description=f"DMARC failed alignment checks with effective policy '{dmarc_policy}'.",
                        evidence_reference=f"DMARC Disposition: {getattr(dmarc_res, 'disposition', 'none')}",
                    )
                )

        # Check ARC Chain
        if arc_res:
            is_valid = getattr(arc_res, "is_valid", False) or getattr(arc_res, "chain_valid", False)
            if not is_valid and getattr(arc_res, "instance_count", 0) > 0:
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.AUTHENTICATION,
                        name="ARC Authentication Chain Broken",
                        score_contribution=8.0,
                        severity="MEDIUM",
                        description="Authenticated Received Chain (ARC) verification failed along intermediate forwarders.",
                        evidence_reference=f"ARC Status: {getattr(arc_res, 'arc_seal_status', 'none')}",
                    )
                )

        return factors

    @classmethod
    def _evaluate_phishing_urls(cls, email_obj: CanonicalEmail) -> List[RiskFactor]:
        """Evaluate extracted URLs and suspicious domain patterns."""
        factors: List[RiskFactor] = []

        if not email_obj.url_report:
            return factors

        for url in email_obj.url_report.urls:
            # Homoglyph attack
            is_homoglyph = getattr(url, "is_idn_homograph", False) or getattr(
                url, "has_idn_homoglyph", False
            )
            if is_homoglyph:
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.PHISHING_URL,
                        name="IDN Homoglyph / Lookalike Domain",
                        score_contribution=15.0,
                        severity="CRITICAL",
                        description=f"Punycode / Homoglyph lookalike domain spoofing in URL: {url.url[:60]}",
                        evidence_reference=url.url,
                    )
                )

            # Raw IP Hostname
            is_ip = getattr(url, "is_ip_host", False) or getattr(url, "is_ip_address", False)
            if is_ip:
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.PHISHING_URL,
                        name="Raw IP Address URL Hostname",
                        score_contribution=12.0,
                        severity="HIGH",
                        description=f"URL uses a direct raw IP address rather than a domain name: {url.url[:60]}",
                        evidence_reference=url.url,
                    )
                )

            # Mismatched display text vs target href
            is_mismatch = getattr(url, "is_anchor_mismatch", False) or getattr(
                url, "is_mismatched", False
            )
            if is_mismatch:
                disp_text = (
                    getattr(url, "anchor_text", "") or getattr(url, "display_text", "") or "Hidden"
                )
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.PHISHING_URL,
                        name="Hyperlink Anchor Mismatch",
                        score_contribution=10.0,
                        severity="HIGH",
                        description=f"Visible anchor text '{disp_text[:40]}' points to different URL destination: {url.url[:50]}",
                        evidence_reference=url.url,
                    )
                )

            # Suspicious URL shortener / redirector
            is_short = getattr(url, "is_shortener", False) or getattr(url, "is_shortened", False)
            if is_short:
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.PHISHING_URL,
                        name="URL Shortener Obfuscation",
                        score_contribution=8.0,
                        severity="MEDIUM",
                        description=f"URL shortener service hides the actual landing destination: {url.url[:60]}",
                        evidence_reference=url.url,
                    )
                )

            # Phishing keywords in URL / Risk flags
            has_login = getattr(url, "has_login_keywords", False) or any(
                "LOGIN" in flag.upper() or "CREDENTIAL" in flag.upper()
                for flag in getattr(url, "risk_flags", [])
            )
            if has_login:
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.PHISHING_URL,
                        name="Credential Harvesting Keywords in URL",
                        score_contribution=8.0,
                        severity="HIGH",
                        description=f"URL contains sensitive credential-harvesting tokens: {url.url[:60]}",
                        evidence_reference=url.url,
                    )
                )

        return factors

    @classmethod
    def _evaluate_bec_social_engineering(cls, email_obj: CanonicalEmail) -> List[RiskFactor]:
        """Evaluate Business Email Compromise (BEC) and social engineering indicators."""
        factors: List[RiskFactor] = []

        if not email_obj.bec_report:
            return factors

        for ind in email_obj.bec_report.indicators:
            conf = getattr(ind, "confidence_score", None)
            if conf is None:
                conf = getattr(ind, "confidence", 1.0)
            conf_val = float(conf) if conf is not None else 1.0

            raw_ind_type = getattr(ind, "indicator_type", None) or getattr(
                ind, "category", "BEC Threat Indicator"
            )
            ind_type = str(raw_ind_type)
            ind_sev = str(getattr(ind, "severity", "MEDIUM"))
            obs_val = getattr(ind, "observed_value", None) or getattr(ind, "matched_text", None)

            factors.append(
                RiskFactor(
                    vector=RiskVectorType.BEC_SOCIAL_ENGINEERING,
                    name=ind_type.replace("_", " ").title(),
                    score_contribution=round(conf_val * 15.0, 1),
                    severity=ind_sev,
                    description=ind.description,
                    evidence_reference=str(obs_val) if obs_val else None,
                )
            )

        return factors

    @classmethod
    def _evaluate_attachments_malware(cls, email_obj: CanonicalEmail) -> List[RiskFactor]:
        """Evaluate attachments, YARA matches, and executable payloads."""
        factors: List[RiskFactor] = []

        # Check Attachment Scanner Report
        att_report = email_obj.attachment_threat_report or getattr(
            email_obj, "attachment_report", None
        )
        if att_report:
            threat_list = getattr(att_report, "attachment_analyses", []) or getattr(
                att_report, "threats", []
            )
            for i, threat in enumerate(threat_list):
                fname = getattr(threat, "filename", None) or f"Attachment #{i + 1}"
                sha_hash = getattr(threat, "sha256", None) or f"Attachment #{i + 1}"

                # YARA matches
                if getattr(threat, "yara_matches", []):
                    for ym in threat.yara_matches:
                        factors.append(
                            RiskFactor(
                                vector=RiskVectorType.ATTACHMENT_MALWARE,
                                name=f"YARA Malware Signature: {ym.rule_name}",
                                score_contribution=20.0,
                                severity="CRITICAL",
                                description=f"{fname} triggered YARA rule '{ym.rule_name}'.",
                                evidence_reference=sha_hash,
                            )
                        )

                # Mismatch & Double extension
                is_mismatch = getattr(threat, "is_mime_mismatch", False) or getattr(
                    threat, "extension_mismatch", False
                )
                if is_mismatch:
                    factors.append(
                        RiskFactor(
                            vector=RiskVectorType.ATTACHMENT_MALWARE,
                            name="Attachment MIME Type Spoofing",
                            score_contribution=15.0,
                            severity="HIGH",
                            description=f"{fname} contains extension or MIME type mismatch.",
                            evidence_reference=fname,
                        )
                    )

                is_double_ext = getattr(threat, "is_double_extension", False) or getattr(
                    threat, "dangerous_extension", False
                )
                if is_double_ext:
                    factors.append(
                        RiskFactor(
                            vector=RiskVectorType.ATTACHMENT_MALWARE,
                            name="Double File Extension Camouflage",
                            score_contribution=15.0,
                            severity="HIGH",
                            description=f"{fname} contains deceptive double file extensions.",
                            evidence_reference=fname,
                        )
                    )

                # Threat categories (e.g. MACRO_VBA, EMBEDDED_PE, SCRIPT_PAYLOAD)
                cats = getattr(threat, "threat_categories", [])
                if getattr(threat, "has_vba_macros", False) or "MACRO_VBA" in cats:
                    factors.append(
                        RiskFactor(
                            vector=RiskVectorType.ATTACHMENT_MALWARE,
                            name="Embedded VBA Macros Detected",
                            score_contribution=12.0,
                            severity="HIGH",
                            description=f"{fname} contains active VBA macro code.",
                            evidence_reference=fname,
                        )
                    )

                if (
                    getattr(threat, "is_executable", False)
                    or getattr(threat, "is_script", False)
                    or "EMBEDDED_PE" in cats
                    or "SCRIPT_PAYLOAD" in cats
                ):
                    factors.append(
                        RiskFactor(
                            vector=RiskVectorType.ATTACHMENT_MALWARE,
                            name="Executable or Script Payload",
                            score_contribution=15.0,
                            severity="CRITICAL",
                            description=f"{fname} contains dangerous executable or script code.",
                            evidence_reference=fname,
                        )
                    )

        return factors

    @classmethod
    def _evaluate_obfuscation_transit(cls, email_obj: CanonicalEmail) -> List[RiskFactor]:
        """Evaluate hidden/obfuscated HTML text and routing transit anomalies."""
        factors: List[RiskFactor] = []

        # Check Content Obfuscation
        obf = email_obj.obfuscation_report
        if obf:
            if getattr(obf, "has_zero_width_chars", False):
                count_str = str(
                    getattr(obf, "zero_width_count", None)
                    or getattr(obf, "hidden_text_char_count", "multiple")
                )
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.OBFUSCATION_TRANSIT,
                        name="Zero-Width Character Obfuscation",
                        score_contribution=8.0,
                        severity="MEDIUM",
                        description=f"Detected {count_str} invisible zero-width characters in message body.",
                        evidence_reference="Zero-width unicode characters",
                    )
                )

            has_hidden_css = getattr(obf, "has_hidden_css_content", False) or any(
                "CSS" in getattr(h, "technique", "") for h in getattr(obf, "hidden_artifacts", [])
            )
            if has_hidden_css:
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.OBFUSCATION_TRANSIT,
                        name="Hidden CSS Styled Text",
                        score_contribution=6.0,
                        severity="MEDIUM",
                        description="Message body conceals text using hidden CSS styles (display:none, opacity:0, font-size:0).",
                        evidence_reference="Hidden CSS selectors",
                    )
                )

            blobs = getattr(obf, "decoded_blobs", []) or getattr(obf, "embedded_base64_blobs", [])
            if blobs:
                factors.append(
                    RiskFactor(
                        vector=RiskVectorType.OBFUSCATION_TRANSIT,
                        name="Embedded Base64 Payloads",
                        score_contribution=6.0,
                        severity="MEDIUM",
                        description="Message body contains encoded base64 executable or binary payload strings.",
                        evidence_reference="Base64 encoded payload",
                    )
                )

        # Check Transit Route Anomalies
        if email_obj.transit_route:
            if email_obj.transit_route.anomalies_detected:
                for anom in email_obj.transit_route.anomalies_detected:
                    factors.append(
                        RiskFactor(
                            vector=RiskVectorType.OBFUSCATION_TRANSIT,
                            name="MTA Routing Anomaly",
                            score_contribution=5.0,
                            severity="MEDIUM",
                            description=f"Relay hop routing anomaly detected: {anom}",
                            evidence_reference=anom,
                        )
                    )

            # Tor Exit Node check in hops
            for hop in email_obj.transit_route.hops:
                if hop.network_intelligence and hop.network_intelligence.is_tor_exit_node:
                    factors.append(
                        RiskFactor(
                            vector=RiskVectorType.OBFUSCATION_TRANSIT,
                            name="Origin / Transit Hop via Tor Exit Node",
                            score_contribution=8.0,
                            severity="HIGH",
                            description=f"Hop #{hop.hop_number} ({hop.from_ip}) is identified as an active Tor Exit Node.",
                            evidence_reference=hop.from_ip,
                        )
                    )

        return factors

    @classmethod
    def _determine_severity(cls, score: float, factors: List[RiskFactor]) -> RiskSeverity:
        """Map composite score and critical signals to a RiskSeverity tier."""
        # Immediate Critical escalation if any factor is CRITICAL and score >= 50
        has_critical = any(f.severity == "CRITICAL" for f in factors)

        if score >= 90.0 or (has_critical and score >= 75.0):
            return RiskSeverity.CRITICAL
        elif score >= 70.0:
            return RiskSeverity.MALICIOUS_HIGH
        elif score >= 40.0:
            return RiskSeverity.SUSPICIOUS_MEDIUM
        elif score >= 20.0:
            return RiskSeverity.SUSPICIOUS_LOW
        return RiskSeverity.CLEAN

    @classmethod
    def _synthesize_recommendation(
        cls, severity: RiskSeverity, score: float, factors: List[RiskFactor]
    ) -> tuple[str, str]:
        """Synthesize actionable remediation advice and executive summary."""
        if severity == RiskSeverity.CRITICAL:
            action = "QUARANTINE / BLOCK IMMEDIATELY — Initiate Incident Response."
            summary = f"CRITICAL THREAT (Score: {score}/100): Confirmed weaponized malicious indicators (malware signatures, active credential harvesting, or critical spoofing)."
        elif severity == RiskSeverity.MALICIOUS_HIGH:
            action = "BLOCK & PURGE — Isolate mailbox and extract IoCs for firewall."
            summary = f"MALICIOUS HIGH (Score: {score}/100): Strong malicious intent identified across multiple threat vectors."
        elif severity == RiskSeverity.SUSPICIOUS_MEDIUM:
            action = "FLAG & INVESTIGATE — Place in user quarantine and review headers/links."
            summary = f"SUSPICIOUS MEDIUM (Score: {score}/100): Multiple security anomalies and suspicious characteristics detected."
        elif severity == RiskSeverity.SUSPICIOUS_LOW:
            action = "CAUTION — Deliver with forensic warning banner."
            summary = f"SUSPICIOUS LOW (Score: {score}/100): Minor non-standard traits detected (e.g. SPF SoftFail or tracking shortener)."
        else:
            action = "ALLOW — Standard email message."
            summary = f"CLEAN (Score: {score}/100): No notable forensic threat signals or authentication violations detected."

        return action, summary
