"""Business Email Compromise (BEC), Display Name Spoofing, and Cousin Domain Detection Engine.

Provides heuristic analysis to detect VIP/executive impersonation, display name deception,
typosquatted/combosquatted cousin domains, multi-header asymmetric routing (From vs Reply-To),
and financial coercion/urgency patterns.
"""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Dict, List, Optional, Set

import tldextract

from eft.models.canonical import BECAnalysisReport, BECIndicator, CanonicalEmail

# Common global public webmail providers (Freemail)
FREEMAIL_DOMAINS: Set[str] = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "rocketmail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "aol.com",
    "mail.com",
    "zoho.com",
    "protonmail.com",
    "proton.me",
    "yandex.com",
    "yandex.ru",
    "mail.ru",
    "gmx.com",
    "gmx.net",
    "fastmail.com",
    "tutanota.com",
    "tutamail.com",
}

# Known disposable/temporary email domains
DISPOSABLE_DOMAINS: Set[str] = {
    "tempmail.com",
    "temp-mail.org",
    "mailinator.com",
    "10minutemail.com",
    "guerrillamail.com",
    "guerrillamail.net",
    "trashmail.com",
    "sharklasers.com",
    "throwawaymail.com",
    "yopmail.com",
    "getairmail.com",
    "dispostable.com",
    "maildrop.cc",
}

# Default top-targeted global brands and cloud providers
DEFAULT_PROTECTED_DOMAINS: List[str] = [
    "microsoft.com",
    "office.com",
    "office365.com",
    "live.com",
    "google.com",
    "apple.com",
    "paypal.com",
    "amazon.com",
    "docusign.com",
    "docusign.net",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citi.com",
    "dropbox.com",
    "adobe.com",
    "github.com",
    "linkedin.com",
    "netflix.com",
    "zoom.us",
]

# High-risk executive and administrative title keywords
EXECUTIVE_TITLE_KEYWORDS: List[str] = [
    "ceo",
    "chief executive officer",
    "cfo",
    "chief financial officer",
    "coo",
    "chief operating officer",
    "cio",
    "cto",
    "chief technology officer",
    "ciso",
    "president",
    "managing director",
    "executive director",
    "vice president",
    "general counsel",
    "payroll director",
    "payroll department",
    "human resources director",
    "hr department",
    "accounts payable",
]

# BEC linguistic keyword patterns categorized by intent
BEC_KEYWORD_PATTERNS: Dict[str, List[str]] = {
    "WIRE_TRANSFER_PAYMENT": [
        r"\bwire\s+transfer\b",
        r"\bbank\s+transfer\b",
        r"\bswift\s+(?:code|payment|transfer)\b",
        r"\bremittance\s+advice\b",
        r"\bupdated?\s+bank\s+(?:details|account|information)\b",
        r"\bnew\s+banking\s+details\b",
        r"\bpayment\s+instructions?\b",
        r"\brouting\s+number\b",
        r"\boverdue\s+invoice\s+payment\b",
        r"\bprocess\s+(?:this\s+)?payment\b",
    ],
    "PAYROLL_DIRECT_DEPOSIT": [
        r"\bupdate\s+(?:my\s+)?direct\s+deposit\b",
        r"\bchange\s+(?:my\s+)?payroll\b",
        r"\bnew\s+bank\s+account\s+for\s+(?:paycheck|payroll)\b",
        r"\bw-?2\s+(?:form|statement|document)\b",
        r"\bpayroll\s+direct\s+deposit\b",
    ],
    "GIFT_CARD_FRAUD": [
        r"\bgift\s+cards?\b",
        r"\bapple\s+gift\s+cards?\b",
        r"\bgoogle\s+play\s+cards?\b",
        r"\bamazon\s+gift\s+cards?\b",
        r"\bpurchase\s+(?:some\s+)?(?:cards?|vouchers?)\b",
        r"\bscratch\s+the\s+back\b",
        r"\bclaim\s+code\b",
    ],
    "EXECUTIVE_URGENCY": [
        r"\bare\s+you\s+at\s+your\s+desk\b",
        r"\bare\s+you\s+available\b",
        r"\bhandle\s+this\s+discreetly\b",
        r"\bstrictly\s+confidential\b",
        r"\burgent\s+(?:task|request|favor)\b",
        r"\bdo\s+not\s+call\s+me\b",
        r"\bi['’]?m\s+in\s+a\s+meeting\b",
    ],
}


class BECDetector:
    """Forensic engine for Business Email Compromise (BEC) and spoofing detection."""

    def __init__(self) -> None:
        self.tld_extractor = tldextract.TLDExtract()

    def detect(
        self,
        email: CanonicalEmail,
        protected_domains: Optional[List[str]] = None,
        protected_executives: Optional[List[Dict[str, str]]] = None,
    ) -> BECAnalysisReport:
        """Run comprehensive BEC, display name spoofing, and cousin domain detection.

        Args:
            email: CanonicalEmail evidence model.
            protected_domains: Custom list of domain names to protect against typosquatting.
            protected_executives: Custom list of dicts: [{"name": "John Doe", "email": "jdoe@corp.com", "title": "CEO"}]

        Returns:
            A populated BECAnalysisReport.
        """
        # Assemble target protected domains (merging defaults + recipient domains)
        target_domains = list(DEFAULT_PROTECTED_DOMAINS)
        if protected_domains:
            for dom in protected_domains:
                clean_dom = dom.lower().strip()
                if clean_dom not in target_domains:
                    target_domains.append(clean_dom)

        # Automatically extract recipient domains from To/Cc to protect organization domains
        for recipient in email.to_addresses + email.cc_addresses:
            _, rec_email = parseaddr(recipient)
            if "@" in rec_email:
                rec_domain = rec_email.split("@")[-1].lower()
                rec_reg = self._get_registered_domain(rec_domain)
                if rec_reg and rec_reg not in target_domains and rec_reg not in FREEMAIL_DOMAINS:
                    target_domains.append(rec_reg)

        executives = protected_executives or []

        # Parse sender headers
        from_display, from_addr = parseaddr(email.from_address or "")
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

        _, reply_to_addr = parseaddr(email.reply_to or "")
        reply_to_domain = reply_to_addr.split("@")[-1].lower() if "@" in reply_to_addr else ""

        _, sender_addr = parseaddr(str(email.headers.get("sender", "")))
        _, return_path_addr = parseaddr(email.return_path or "")

        indicators: List[BECIndicator] = []

        # 1. Display Name Spoofing & Embedded Email Analysis
        dn_indicators = self.check_display_name_spoofing(
            display_name=from_display,
            sender_email=from_addr,
            sender_domain=from_domain,
            protected_executives=executives,
        )
        indicators.extend(dn_indicators)

        # 2. Cousin / Typosquatted Domain Analysis
        cousin_indicators = self.check_cousin_domains(
            sender_domain=from_domain,
            protected_domains=target_domains,
        )
        indicators.extend(cousin_indicators)

        # 3. Multi-Header Routing Discrepancies (From vs Reply-To vs Return-Path)
        route_indicators = self.check_header_routing_discrepancies(
            from_addr=from_addr,
            from_domain=from_domain,
            reply_to_addr=reply_to_addr,
            reply_to_domain=reply_to_domain,
            sender_addr=sender_addr,
            return_path_addr=return_path_addr,
        )
        indicators.extend(route_indicators)

        # 4. Freemail & Disposable Domain Abusive Routing
        free_indicators = self.check_freemail_and_disposable(
            sender_domain=from_domain,
            reply_to_domain=reply_to_domain,
            display_name=from_display,
        )
        indicators.extend(free_indicators)

        # 5. BEC Intent & Urgency Linguistic Analysis
        body_text = f"{email.subject or ''}\n{email.body_plain or ''}"
        ling_indicators = self.check_bec_urgency_keywords(
            subject=email.subject,
            body_text=body_text,
        )
        indicators.extend(ling_indicators)

        # Calculate Threat Score & Aggregate Flags
        flags: List[str] = []
        score = 0.0
        display_name_spoofed = False
        cousin_detected = False
        reply_to_mismatch = False
        impersonated_id: Optional[str] = None
        target_simulated: Optional[str] = None

        weight_map = {
            "VIP_IMPERSONATION": 50.0,
            "DISPLAY_NAME_EMBEDDED_EMAIL_SPOOF": 45.0,
            "COUSIN_DOMAIN_TYPOSQUAT": 45.0,
            "REPLY_TO_DOMAIN_MISMATCH": 40.0,
            "BRAND_DISPLAY_NAME_SPOOF": 30.0,
            "COUSIN_DOMAIN_COMBOSQUAT": 30.0,
            "DISPOSABLE_EMAIL_DOMAIN": 25.0,
            "EXECUTIVE_TITLE_FREEMAIL_SPOOF": 25.0,
            "BEC_URGENCY_KEYWORDS": 20.0,
            "FREEMAIL_BRAND_MISMATCH": 20.0,
            "RETURN_PATH_MISMATCH": 10.0,
        }

        for ind in indicators:
            if ind.indicator_type not in flags:
                flags.append(ind.indicator_type)
            score += weight_map.get(ind.indicator_type, 15.0)

            if ind.indicator_type in (
                "VIP_IMPERSONATION",
                "DISPLAY_NAME_EMBEDDED_EMAIL_SPOOF",
                "BRAND_DISPLAY_NAME_SPOOF",
            ):
                display_name_spoofed = True
                if ind.expected_or_target_value and not impersonated_id:
                    impersonated_id = ind.expected_or_target_value

            if ind.indicator_type in ("COUSIN_DOMAIN_TYPOSQUAT", "COUSIN_DOMAIN_COMBOSQUAT"):
                cousin_detected = True
                if ind.expected_or_target_value and not target_simulated:
                    target_simulated = ind.expected_or_target_value

            if ind.indicator_type == "REPLY_TO_DOMAIN_MISMATCH":
                reply_to_mismatch = True

        threat_score = min(score, 100.0)

        # Determine overall threat level
        if (
            threat_score >= 60.0
            or "VIP_IMPERSONATION" in flags
            or "COUSIN_DOMAIN_TYPOSQUAT" in flags
            or "DISPLAY_NAME_EMBEDDED_EMAIL_SPOOF" in flags
        ):
            overall_level = "CRITICAL_BEC"
        elif threat_score >= 40.0:
            overall_level = "HIGH_RISK"
        elif threat_score >= 20.0:
            overall_level = "SUSPICIOUS"
        else:
            overall_level = "CLEAN"

        is_bec = overall_level in ("CRITICAL_BEC", "HIGH_RISK")

        report = BECAnalysisReport(
            is_bec_suspected=is_bec,
            overall_threat_level=overall_level,
            threat_score=threat_score,
            display_name_spoof_detected=display_name_spoofed,
            cousin_domain_detected=cousin_detected,
            reply_to_mismatch_detected=reply_to_mismatch,
            impersonated_identity=impersonated_id,
            target_domain_simulated=target_simulated,
            indicators=indicators,
            flags=flags,
        )

        email.bec_report = report
        return report

    def check_display_name_spoofing(
        self,
        display_name: str,
        sender_email: str,
        sender_domain: str,
        protected_executives: List[Dict[str, str]],
    ) -> List[BECIndicator]:
        """Detect display name impersonation of VIPs, brands, or embedded email addresses."""
        indicators: List[BECIndicator] = []
        if not display_name:
            return indicators

        dn_clean = display_name.strip().strip("\"'").strip()
        dn_lower = dn_clean.lower()

        # 1. Embedded Email in Display Name (e.g., "ceo@corp.com" <scammer@gmail.com>)
        embedded_emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", dn_clean)
        for emb in embedded_emails:
            emb_lower = emb.lower()
            if emb_lower != sender_email.lower():
                indicators.append(
                    BECIndicator(
                        indicator_type="DISPLAY_NAME_EMBEDDED_EMAIL_SPOOF",
                        severity="CRITICAL",
                        description=f"Display name embeds deceptive address '{emb}' while actual sender is '{sender_email}'",
                        observed_value=dn_clean,
                        expected_or_target_value=emb,
                        confidence_score=0.95,
                    )
                )

        # 2. Protected Executive VIP Impersonation
        for exec_info in protected_executives:
            exec_name = exec_info.get("name", "").strip()
            exec_email = exec_info.get("email", "").strip().lower()
            if not exec_name:
                continue

            # Check if display name closely matches executive name
            if exec_name.lower() in dn_lower or dn_lower in exec_name.lower():
                # Check if sender email doesn't match official executive email
                if exec_email and sender_email.lower() != exec_email:
                    indicators.append(
                        BECIndicator(
                            indicator_type="VIP_IMPERSONATION",
                            severity="CRITICAL",
                            description=f"Display name matches VIP executive '{exec_name}' but sender email is '{sender_email}'",
                            observed_value=f"{dn_clean} <{sender_email}>",
                            expected_or_target_value=f"{exec_name} <{exec_email}>",
                            confidence_score=0.98,
                        )
                    )

        # 3. Executive Title Keyword Spoofing from Freemail
        if sender_domain in FREEMAIL_DOMAINS:
            for title in EXECUTIVE_TITLE_KEYWORDS:
                if re.search(r"\b" + re.escape(title) + r"\b", dn_lower):
                    indicators.append(
                        BECIndicator(
                            indicator_type="EXECUTIVE_TITLE_FREEMAIL_SPOOF",
                            severity="HIGH",
                            description=f"Display name claims executive/administrative title '{title.title()}' but originates from consumer freemail provider '{sender_domain}'",
                            observed_value=f"{dn_clean} <{sender_email}>",
                            expected_or_target_value="Enterprise corporate domain",
                            confidence_score=0.90,
                        )
                    )
                    break

        # 4. Brand Name in Display Name with Non-Brand Sender Domain
        brand_list = [
            "paypal",
            "microsoft",
            "office 365",
            "google",
            "apple",
            "docusign",
            "chase bank",
            "netflix",
            "amazon",
        ]
        for brand in brand_list:
            if re.search(r"\b" + re.escape(brand) + r"\b", dn_lower):
                # If sender domain does not contain the brand name
                brand_slug = brand.replace(" ", "")
                if brand_slug not in sender_domain.replace(".", "").replace("-", ""):
                    indicators.append(
                        BECIndicator(
                            indicator_type="BRAND_DISPLAY_NAME_SPOOF",
                            severity="HIGH",
                            description=f"Display name references trusted brand '{brand.title()}' but email is sent from unrelated domain '{sender_domain}'",
                            observed_value=f"{dn_clean} <{sender_email}>",
                            expected_or_target_value=f"Official {brand.title()} domain",
                            confidence_score=0.85,
                        )
                    )
                    break

        return indicators

    def check_cousin_domains(
        self,
        sender_domain: str,
        protected_domains: List[str],
    ) -> List[BECIndicator]:
        """Detect cousin, typosquatted, and combosquatted domains using Levenshtein distance."""
        indicators: List[BECIndicator] = []
        if (
            not sender_domain
            or sender_domain in FREEMAIL_DOMAINS
            or sender_domain in DISPOSABLE_DOMAINS
        ):
            return indicators

        sender_reg = self._get_registered_domain(sender_domain)
        if not sender_reg:
            return indicators

        sender_label = sender_reg.split(".")[0]

        for target in protected_domains:
            target_reg = self._get_registered_domain(target)
            if not target_reg or sender_reg == target_reg:
                continue

            target_label = target_reg.split(".")[0]

            # 1. Levenshtein Distance Check (Typosquatting)
            dist = self.calculate_levenshtein(sender_label, target_label)
            if (
                0 < dist <= 2
                and len(target_label) >= 4
                and abs(len(sender_label) - len(target_label)) <= 2
            ):
                indicators.append(
                    BECIndicator(
                        indicator_type="COUSIN_DOMAIN_TYPOSQUAT",
                        severity="CRITICAL",
                        description=f"Sender domain '{sender_reg}' is a lookalike/typosquatted cousin domain of '{target_reg}' (edit distance: {dist})",
                        observed_value=sender_reg,
                        expected_or_target_value=target_reg,
                        confidence_score=0.92,
                    )
                )
                continue

            # 2. Combosquatting / Deceptive Hyphenation (e.g. microsoft-security.com or login-paypal.com)
            if target_label in sender_label and (
                "-" in sender_label
                or any(
                    k in sender_label
                    for k in ["security", "support", "verify", "login", "update", "service"]
                )
            ):
                indicators.append(
                    BECIndicator(
                        indicator_type="COUSIN_DOMAIN_COMBOSQUAT",
                        severity="HIGH",
                        description=f"Sender domain '{sender_reg}' is combosquatted using target brand name '{target_label}' with deceptive keywords",
                        observed_value=sender_reg,
                        expected_or_target_value=target_reg,
                        confidence_score=0.88,
                    )
                )

        return indicators

    def check_header_routing_discrepancies(
        self,
        from_addr: str,
        from_domain: str,
        reply_to_addr: str,
        reply_to_domain: str,
        sender_addr: str,
        return_path_addr: str,
    ) -> List[BECIndicator]:
        """Detect asymmetric routing between From, Reply-To, Sender, and Return-Path."""
        indicators: List[BECIndicator] = []

        from_reg = self._get_registered_domain(from_domain)

        # 1. From vs Reply-To Mismatch
        if reply_to_addr and reply_to_domain:
            reply_to_reg = self._get_registered_domain(reply_to_domain)
            if from_reg and reply_to_reg and from_reg != reply_to_reg:
                severity = (
                    "CRITICAL"
                    if reply_to_domain in FREEMAIL_DOMAINS or reply_to_domain in DISPOSABLE_DOMAINS
                    else "HIGH"
                )
                indicators.append(
                    BECIndicator(
                        indicator_type="REPLY_TO_DOMAIN_MISMATCH",
                        severity=severity,
                        description=f"Reply-To address '{reply_to_addr}' routes responses to domain '{reply_to_reg}', differing from From address domain '{from_reg}'",
                        observed_value=reply_to_addr,
                        expected_or_target_value=from_addr,
                        confidence_score=0.90,
                    )
                )

        # 2. Return-Path Mismatch
        if return_path_addr:
            return_domain = (
                return_path_addr.split("@")[-1].lower() if "@" in return_path_addr else ""
            )
            return_reg = self._get_registered_domain(return_domain)
            if from_reg and return_reg and from_reg != return_reg:
                indicators.append(
                    BECIndicator(
                        indicator_type="RETURN_PATH_MISMATCH",
                        severity="MEDIUM",
                        description=f"Return-Path envelope domain '{return_reg}' does not match header From domain '{from_reg}'",
                        observed_value=return_path_addr,
                        expected_or_target_value=from_addr,
                        confidence_score=0.75,
                    )
                )

        return indicators

    def check_freemail_and_disposable(
        self,
        sender_domain: str,
        reply_to_domain: str,
        display_name: str,
    ) -> List[BECIndicator]:
        """Flag usage of disposable email domains or consumer webmail masquerading as corporate senders."""
        indicators: List[BECIndicator] = []

        # Check disposable domain
        if sender_domain in DISPOSABLE_DOMAINS or reply_to_domain in DISPOSABLE_DOMAINS:
            indicators.append(
                BECIndicator(
                    indicator_type="DISPOSABLE_EMAIL_DOMAIN",
                    severity="HIGH",
                    description=f"Sender or Reply-To is using a known temporary/disposable mailbox domain ('{sender_domain or reply_to_domain}')",
                    observed_value=sender_domain or reply_to_domain,
                    expected_or_target_value="Legitimate permanent domain",
                    confidence_score=0.95,
                )
            )

        return indicators

    def check_bec_urgency_keywords(
        self,
        subject: Optional[str],
        body_text: str,
    ) -> List[BECIndicator]:
        """Scan subject and message body for high-risk BEC financial intent and urgency keywords."""
        indicators: List[BECIndicator] = []
        if not body_text:
            return indicators

        matched_categories: Dict[str, List[str]] = {}

        for category, patterns in BEC_KEYWORD_PATTERNS.items():
            for pat in patterns:
                matches = re.findall(pat, body_text, flags=re.IGNORECASE)
                if matches:
                    if category not in matched_categories:
                        matched_categories[category] = []
                    for m in matches:
                        if m.lower() not in matched_categories[category]:
                            matched_categories[category].append(m.lower())

        if matched_categories:
            summary_parts = []
            for cat, words in matched_categories.items():
                summary_parts.append(f"{cat}: [{', '.join(words[:3])}]")

            indicators.append(
                BECIndicator(
                    indicator_type="BEC_URGENCY_KEYWORDS",
                    severity="HIGH" if len(matched_categories) >= 2 else "MEDIUM",
                    description=f"Detected high-risk BEC intent phrases in message content: {'; '.join(summary_parts)}",
                    observed_value=", ".join(summary_parts),
                    expected_or_target_value=None,
                    confidence_score=0.85,
                )
            )

        return indicators

    # -------------------------------------------------------------------------
    # Helper Algorithms
    # -------------------------------------------------------------------------

    @staticmethod
    def calculate_levenshtein(s1: str, s2: str) -> int:
        """Compute the Levenshtein edit distance between two strings using dynamic programming."""
        if s1 == s2:
            return 0
        if not s1:
            return len(s2)
        if not s2:
            return len(s1)

        m, n = len(s1), len(s2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]

        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if s1[i - 1] == s2[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1]
                else:
                    dp[i][j] = 1 + min(
                        dp[i - 1][j],  # deletion
                        dp[i][j - 1],  # insertion
                        dp[i - 1][j - 1],  # substitution
                    )

        return dp[m][n]

    def _get_registered_domain(self, domain_or_host: str) -> str:
        """Safely extract the registered domain under public suffix without deprecation warnings."""
        if not domain_or_host:
            return ""
        extracted = self.tld_extractor(domain_or_host)
        if hasattr(extracted, "top_domain_under_public_suffix"):
            return str(extracted.top_domain_under_public_suffix or "").lower()
        if hasattr(extracted, "registered_domain"):
            return str(extracted.registered_domain or "").lower()
        return domain_or_host.lower()
