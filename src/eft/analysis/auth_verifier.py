"""Email Authentication Verification Engine evaluating SPF, DKIM, DMARC, and ARC."""

from __future__ import annotations

import email.utils
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import tldextract

try:
    import authres  # type: ignore
except ImportError:  # pragma: no cover
    authres = None

from eft.models.canonical import (
    ARCChain,
    CanonicalEmail,
    DKIMSignatureArtifact,
    DMARCResult,
    EmailAuthenticationReport,
    SPFResult,
)

# Regex fallbacks for Authentication-Results clauses
SPF_AUTH_REGEX = re.compile(
    r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b(?:\s*\(([^)]*)\))?",
    re.IGNORECASE,
)
DKIM_AUTH_REGEX = re.compile(
    r"\bdkim=(pass|fail|none|neutral|temperror|permerror)\b(?:\s*\(([^)]*)\))?",
    re.IGNORECASE,
)
DMARC_AUTH_REGEX = re.compile(
    r"\bdmarc=(pass|fail|none|temperror|permerror)\b(?:\s*\(([^)]*)\))?",
    re.IGNORECASE,
)
ARC_AUTH_REGEX = re.compile(
    r"\barc=(pass|fail|none)\b(?:\s*\(([^)]*)\))?",
    re.IGNORECASE,
)

# Tag extractor for DKIM-Signature and Received-SPF headers
DKIM_TAG_REGEX = re.compile(r"([a-zA-Z0-9]+)\s*=\s*([^;]+)")
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class AuthenticationVerifier:
    """Forensic email authentication analyzer evaluating SPF, DKIM, DMARC, and ARC."""

    @classmethod
    def extract_domain_from_address(cls, address: Optional[str]) -> str:
        """Extract the domain portion from an email address (e.g. 'User <u@domain.com>')."""
        if not address:
            return ""
        _, addr = email.utils.parseaddr(address)
        if "@" in addr:
            return addr.split("@")[-1].strip().lower()
        if "@" in address:
            return address.split("@")[-1].strip().rstrip(">").lower()
        return address.strip().lower()

    @classmethod
    def get_organizational_domain(cls, domain: str) -> str:
        """Extract the registered organizational domain (e.g. 'sub.paypal.co.uk' -> 'paypal.co.uk')."""
        if not domain:
            return ""
        extracted = tldextract.extract(domain)
        if extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
        return extracted.domain.lower() if extracted.domain else domain.lower()

    @classmethod
    def check_domain_alignment(
        cls,
        domain_a: str,
        domain_b: str,
        mode: str = "relaxed",
    ) -> bool:
        """Check identifier alignment between two domains in 'strict' or 'relaxed' mode.

        - Strict: Requires exact FQDN match (e.g., `sub.example.com == sub.example.com`).
        - Relaxed: Requires organizational domain match (e.g., `sub.example.com` matches `example.com`).
        """
        if not domain_a or not domain_b:
            return False

        da = domain_a.lower().strip()
        db = domain_b.lower().strip()

        if da == db:
            return True

        if mode.lower() == "strict":
            return False

        # Relaxed mode: check organizational domain equivalence
        org_a = cls.get_organizational_domain(da)
        org_b = cls.get_organizational_domain(db)
        return bool(org_a and org_b and org_a == org_b)

    @classmethod
    def parse_dkim_signature_header(cls, header_val: str) -> DKIMSignatureArtifact:
        """Parse raw DKIM-Signature header tag-value pairs into a structured artifact."""
        tags: Dict[str, str] = {}
        for match in DKIM_TAG_REGEX.finditer(header_val):
            k = match.group(1).lower().strip()
            v = match.group(2).strip()
            tags[k] = v

        domain = tags.get("d", "")
        selector = tags.get("s", "")
        algo = tags.get("a", "rsa-sha256")
        canon = tags.get("c")
        body_hash = tags.get("bh")
        sig_data = tags.get("b", "").replace(" ", "").replace("\t", "")

        headers_signed: List[str] = []
        if "h" in tags:
            headers_signed = [h.strip().lower() for h in tags["h"].split(":") if h.strip()]

        timestamp_signed: Optional[datetime] = None
        if "t" in tags:
            try:
                timestamp_signed = datetime.fromtimestamp(int(tags["t"]), tz=timezone.utc)
            except Exception:
                pass

        expiration: Optional[datetime] = None
        if "x" in tags:
            try:
                expiration = datetime.fromtimestamp(int(tags["x"]), tz=timezone.utc)
            except Exception:
                pass

        return DKIMSignatureArtifact(
            domain=domain,
            selector=selector,
            algorithm=algo,
            canonicalization=canon,
            body_hash=body_hash,
            signature_data=sig_data,
            signed_headers=headers_signed,
            status="none",
            timestamp_signed=timestamp_signed,
            expiration=expiration,
            details=f"DKIM Signature for d={domain} s={selector} a={algo}",
        )

    @classmethod
    def parse_authentication_results(
        cls,
        auth_headers: List[str],
    ) -> Tuple[
        Optional[SPFResult], List[DKIMSignatureArtifact], Optional[DMARCResult], Optional[ARCChain]
    ]:
        """Parse RFC 8601 Authentication-Results headers using authres and regex fallbacks."""
        spf_res: Optional[SPFResult] = None
        dkim_list: List[DKIMSignatureArtifact] = []
        dmarc_res: Optional[DMARCResult] = None
        arc_res: Optional[ARCChain] = None

        for raw_hdr in auth_headers:
            clean_hdr = re.sub(r"\s+", " ", raw_hdr).strip()

            # 1. Parse SPF clause
            spf_match = SPF_AUTH_REGEX.search(clean_hdr)
            if spf_match and not spf_res:
                status = spf_match.group(1).lower()
                details = spf_match.group(2) or ""

                sender_ip = None
                ip_match = IP_REGEX.search(clean_hdr)
                if ip_match:
                    sender_ip = ip_match.group(0)

                mail_from = None
                mail_from_match = re.search(r"smtp\.mailfrom=([^\s;)]+)", clean_hdr, re.IGNORECASE)
                if mail_from_match:
                    mail_from = mail_from_match.group(1).strip().lower()

                helo = None
                helo_match = re.search(r"smtp\.helo=([^\s;)]+)", clean_hdr, re.IGNORECASE)
                if helo_match:
                    helo = helo_match.group(1).strip().lower()

                spf_res = SPFResult(
                    status=status,
                    sender_ip=sender_ip,
                    mail_from_domain=cls.extract_domain_from_address(mail_from),
                    helo_domain=helo,
                    details=details.strip() if details else f"SPF {status}",
                )

            # 2. Parse DKIM clause(s)
            for dkim_match in DKIM_AUTH_REGEX.finditer(clean_hdr):
                status = dkim_match.group(1).lower()
                details = dkim_match.group(2) or ""

                d_match = re.search(r"header\.(?:d|i)=@?([^\s;)]+)", clean_hdr, re.IGNORECASE)
                s_match = re.search(r"header\.s=([^\s;)]+)", clean_hdr, re.IGNORECASE)

                d_val = d_match.group(1).strip().lstrip("@") if d_match else ""
                s_val = s_match.group(1).strip() if s_match else ""

                dkim_item = DKIMSignatureArtifact(
                    domain=d_val,
                    selector=s_val,
                    status=status,
                    details=details.strip() if details else f"DKIM {status} (d={d_val})",
                )
                dkim_list.append(dkim_item)

            # 3. Parse DMARC clause
            dmarc_match = DMARC_AUTH_REGEX.search(clean_hdr)
            if dmarc_match and not dmarc_res:
                status = dmarc_match.group(1).lower()
                details = dmarc_match.group(2) or ""

                action_match = re.search(r"action=([a-zA-Z]+)", clean_hdr, re.IGNORECASE)
                policy_match = re.search(r"policy=([a-zA-Z]+)", clean_hdr, re.IGNORECASE)
                from_match = re.search(r"header\.from=([^\s;)]+)", clean_hdr, re.IGNORECASE)

                policy_val = policy_match.group(1).lower() if policy_match else "none"
                disp_val = action_match.group(1).lower() if action_match else "none"
                hdr_from = from_match.group(1).strip() if from_match else ""

                dmarc_res = DMARCResult(
                    status=status,
                    policy=policy_val,
                    disposition=disp_val,
                    header_from_domain=hdr_from,
                    details=details.strip() if details else f"DMARC {status}",
                )

            # 4. Parse ARC clause
            arc_match = ARC_AUTH_REGEX.search(clean_hdr)
            if arc_match and not arc_res:
                arc_status = arc_match.group(1).lower()
                arc_res = ARCChain(
                    arc_auth_results_status=arc_status,
                    is_valid=(arc_status == "pass"),
                    details=f"ARC {arc_status}",
                )

        return spf_res, dkim_list, dmarc_res, arc_res

    @classmethod
    def evaluate_spf_alignment(
        cls,
        spf: Optional[SPFResult],
        from_domain: str,
        return_path_domain: str = "",
    ) -> None:
        """Evaluate SPF identifier alignment against Header.From domain."""
        if not spf:
            return

        align_domain = spf.mail_from_domain or return_path_domain or spf.helo_domain or ""
        if align_domain and from_domain:
            spf.is_aligned = cls.check_domain_alignment(
                from_domain, align_domain, mode=spf.alignment_mode
            )

    @classmethod
    def evaluate_dkim_alignment(
        cls,
        dkim_list: List[DKIMSignatureArtifact],
        from_domain: str,
    ) -> None:
        """Evaluate DKIM identifier alignment (d= tag) against Header.From domain."""
        for dkim in dkim_list:
            if dkim.domain and from_domain:
                dkim.is_aligned = cls.check_domain_alignment(
                    from_domain, dkim.domain, mode=dkim.alignment_mode
                )

    @classmethod
    def evaluate_dmarc(
        cls,
        from_domain: str,
        spf: Optional[SPFResult],
        dkim_list: List[DKIMSignatureArtifact],
        recorded_dmarc: Optional[DMARCResult],
    ) -> DMARCResult:
        """Evaluate DMARC pass/fail condition per RFC 7489 standard.

        DMARC PASS = (SPF Pass AND SPF Aligned) OR (At least one DKIM Pass AND DKIM Aligned).
        """
        spf_pass_aligned = bool(spf and spf.status.lower() == "pass" and spf.is_aligned)
        dkim_pass_aligned = any(d.status.lower() == "pass" and d.is_aligned for d in dkim_list)

        dmarc_pass = spf_pass_aligned or dkim_pass_aligned

        policy = recorded_dmarc.policy if recorded_dmarc else "none"
        disp = recorded_dmarc.disposition if recorded_dmarc else "none"

        status = "pass" if dmarc_pass else ("fail" if (spf or dkim_list) else "none")
        if recorded_dmarc and recorded_dmarc.status.lower() == "pass" and dmarc_pass:
            status = "pass"
        elif recorded_dmarc and recorded_dmarc.status.lower() == "fail" and not dmarc_pass:
            status = "fail"

        return DMARCResult(
            status=status,
            policy=policy,
            spf_alignment=spf_pass_aligned,
            dkim_alignment=dkim_pass_aligned,
            header_from_domain=from_domain,
            disposition=disp,
            details=f"DMARC {status} (SPF Aligned Pass: {spf_pass_aligned}, DKIM Aligned Pass: {dkim_pass_aligned})",
        )

    @classmethod
    def synthesize_overall_verdict(
        cls,
        spf: Optional[SPFResult],
        dkim_list: List[DKIMSignatureArtifact],
        dmarc: Optional[DMARCResult],
        from_domain: str,
    ) -> Tuple[str, str, List[str]]:
        """Synthesize overall forensic authentication verdict and alert flags."""
        flags: List[str] = []

        has_spf = spf is not None and spf.status.lower() != "none"
        has_dkim = len(dkim_list) > 0 and any(d.status.lower() != "none" for d in dkim_list)
        has_dmarc = dmarc is not None and dmarc.status.lower() not in {"none", ""}

        if not has_spf and not has_dkim and not has_dmarc:
            return (
                "INSUFFICIENT_DATA",
                "No authentication headers found.",
                ["NO_AUTH_HEADERS_FOUND"],
            )

        # Accumulate protocol specific flags
        if spf:
            if spf.status.lower() == "fail":
                flags.append("SPF_HARD_FAIL")
            elif spf.status.lower() == "softfail":
                flags.append("SPF_SOFT_FAIL")
            elif spf.status.lower() == "pass":
                flags.append("SPF_PASSED")

        if dkim_list:
            if any(d.status.lower() == "fail" for d in dkim_list):
                flags.append("DKIM_SIGNATURE_VERIFICATION_FAILED")
            elif any(d.status.lower() == "pass" for d in dkim_list):
                flags.append("DKIM_PASSED")

        # Check DMARC failure (Primary indicator for email spoofing)
        if dmarc and dmarc.status.lower() == "fail":
            flags.insert(0, "SPOOFING_CRITICAL_DMARC_FAILED")
            if spf and not spf.is_aligned:
                flags.append("SPF_ALIGNMENT_MISMATCH")
            if dkim_list and not any(d.is_aligned for d in dkim_list):
                flags.append("DKIM_ALIGNMENT_MISMATCH")

            summary = (
                f"CRITICAL: DMARC Authentication Failed for domain '{from_domain}'. "
                f"Potential email spoofing or unauthorized sender."
            )
            return "FAIL", summary, flags

        # Check DMARC pass
        if dmarc and dmarc.status.lower() == "pass":
            flags.insert(0, "DMARC_PASSED")
            summary = (
                f"AUTHENTICATION PASSED: DMARC passed with valid alignment for '{from_domain}'."
            )
            return "PASS", summary, flags

        # If both SPF and DKIM passed
        if (
            spf
            and spf.status.lower() == "pass"
            and any(d.status.lower() == "pass" for d in dkim_list)
        ):
            flags.append("SPF_AND_DKIM_PASSED")
            summary = (
                f"AUTHENTICATION PASSED: SPF and DKIM signatures verified for '{from_domain}'."
            )
            return "PASS", summary, flags

        if spf and spf.status.lower() == "pass":
            return "PASS", f"SPF passed for sender domain '{from_domain}'.", flags

        if any(d.status.lower() == "pass" for d in dkim_list):
            return "PASS", f"DKIM passed for domain '{from_domain}'.", flags

        flags.append("UNVERIFIED_SENDER_AUTHENTICATION")
        return "SUSPICIOUS", f"Sender domain '{from_domain}' has unverified authentication.", flags

    @classmethod
    def verify_email(cls, email: CanonicalEmail) -> EmailAuthenticationReport:
        """Perform comprehensive forensic evaluation of email authentication."""
        auth_headers: List[str] = []
        dkim_sig_headers: List[str] = []
        received_spf_headers: List[str] = []

        # 1. Collect relevant authentication headers
        if email.header_decomposition:
            auth_headers = list(email.header_decomposition.auth_results_headers)
            dkim_sig_headers = list(email.header_decomposition.dkim_signatures)
        else:
            for name, val in email.ordered_headers:
                name_l = name.lower()
                if name_l in {"authentication-results", "arc-authentication-results"}:
                    auth_headers.append(val)
                elif name_l == "dkim-signature":
                    dkim_sig_headers.append(val)
                elif name_l == "received-spf":
                    received_spf_headers.append(val)

        from_domain = cls.extract_domain_from_address(email.from_address)
        return_path_domain = cls.extract_domain_from_address(email.return_path)

        # 2. Parse Authentication-Results
        spf_res, dkim_list, dmarc_res, arc_chain = cls.parse_authentication_results(auth_headers)

        # 3. Parse DKIM-Signature headers if not already in auth_results
        for dkim_hdr in dkim_sig_headers:
            dkim_art = cls.parse_dkim_signature_header(dkim_hdr)
            # Match with existing status if present
            matched = False
            for d in dkim_list:
                if d.domain == dkim_art.domain and (
                    not d.selector or d.selector == dkim_art.selector
                ):
                    dkim_art.status = d.status
                    dkim_art.details = d.details
                    matched = True
                    break
            if not matched:
                dkim_list.append(dkim_art)

        # 4. Evaluate Identifier Alignment
        cls.evaluate_spf_alignment(spf_res, from_domain, return_path_domain)
        cls.evaluate_dkim_alignment(dkim_list, from_domain)

        # 5. Evaluate DMARC
        dmarc_res = cls.evaluate_dmarc(from_domain, spf_res, dkim_list, dmarc_res)

        # 6. Overall Verdict Synthesis
        verdict, summary, flags = cls.synthesize_overall_verdict(
            spf_res, dkim_list, dmarc_res, from_domain
        )

        report = EmailAuthenticationReport(
            overall_verdict=verdict,
            verdict_summary=summary,
            spf=spf_res,
            dkim_signatures=dkim_list,
            dmarc=dmarc_res,
            arc=arc_chain,
            auth_results_raw=auth_headers,
            authentication_flags=flags,
        )

        email.authentication_report = report
        return report
