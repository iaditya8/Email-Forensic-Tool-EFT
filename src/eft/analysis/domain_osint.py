"""Standalone Domain & Email OSINT Intelligence Analyzer."""

from __future__ import annotations

import email.utils
import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import tldextract

try:
    import dns.exception  # type: ignore
    import dns.resolver  # type: ignore
except ImportError:  # pragma: no cover
    dns = None  # type: ignore[assignment]

from eft.analysis.bec_detector import (
    DEFAULT_PROTECTED_DOMAINS,
    DISPOSABLE_DOMAINS,
    FREEMAIL_DOMAINS,
)
from eft.models.osint import (
    BIMIPosture,
    BrandMatchResult,
    DKIMDiscovery,
    DMARCEnforcement,
    DMARCPosture,
    DNSAuthPosture,
    DomainCategory,
    DomainOSINTReport,
    MXRecordInfo,
    SPFPosture,
    SPFStrictness,
)
from eft.models.threat import RiskFactor, RiskSeverity, RiskVectorType

logger = logging.getLogger(__name__)

# Extended list of disposable/throwaway email providers
EXTENDED_DISPOSABLE_DOMAINS: Set[str] = DISPOSABLE_DOMAINS.union(
    {
        "10minutemail.net",
        "guerrillamailblock.com",
        "burnermail.io",
        "fakeinbox.com",
        "nada.ltd",
        "generator.email",
        "inboxkitten.com",
        "mohmal.com",
        "crazymailing.com",
        "fakemailgenerator.com",
        "tempail.com",
        "emailondeck.com",
        "trashmail.net",
        "mytemp.email",
        "disposablemail.com",
        "dropmail.me",
        "minuteinbox.com",
        "internxt.com/temporary-email",
        "tmailor.com",
    }
)

# Homoglyph character substitution map (Cyrillic, Greek, lookalike Latin)
HOMOGLYPH_MAP: Dict[str, str] = {
    "а": "a",
    "à": "a",
    "á": "a",
    "â": "a",
    "ã": "a",
    "ä": "a",
    "å": "a",
    "α": "a",
    "с": "c",
    "ç": "c",
    "ϲ": "c",
    "е": "e",
    "è": "e",
    "é": "e",
    "ê": "e",
    "ë": "e",
    "ε": "e",
    "і": "i",
    "í": "i",
    "ì": "i",
    "ï": "i",
    "ι": "i",
    "1": "i",
    "!": "i",
    "ј": "j",
    "о": "o",
    "ò": "o",
    "ó": "o",
    "ô": "o",
    "õ": "o",
    "ö": "o",
    "ο": "o",
    "0": "o",
    "р": "p",
    "ρ": "p",
    "ѕ": "s",
    "ș": "s",
    "$": "s",
    "5": "s",
    "у": "y",
    "ý": "y",
    "ÿ": "y",
    "γ": "y",
    "х": "x",
    "χ": "x",
    "ѵ": "v",
    "ν": "v",
    "ԁ": "d",
    "ԛ": "q",
    "ԍ": "g",
    "w": "vv",
}

# Standard DKIM selectors to probe during reconnaissance
COMMON_DKIM_SELECTORS: List[str] = [
    "default",
    "google",
    "k1",
    "selector1",
    "s1",
    "s2",
    "mail",
    "s2048",
    "smtp",
    "dkim",
    "mandrill",
    "zendesk",
    "evernote",
]


class DomainOSINTAnalyzer:
    """Forensic OSINT Reconnaissance and Threat Analysis Engine for Domains and Email Addresses."""

    def __init__(
        self,
        watchlist_path: Optional[Union[str, Path]] = None,
        default_dns_timeout: float = 3.0,
    ) -> None:
        self.default_dns_timeout = default_dns_timeout
        self.watchlist = self._load_watchlist(watchlist_path)

    @classmethod
    def _load_watchlist(cls, path: Optional[Union[str, Path]]) -> Dict[str, Any]:
        """Load protected domain and vendor watchlist from disk or default."""
        candidate_paths: List[Path] = []
        if path:
            candidate_paths.append(Path(path))
        else:
            candidate_paths.extend(
                [
                    Path("data/config/watchlist.json"),
                    Path(__file__).resolve().parent.parent.parent.parent
                    / "data"
                    / "config"
                    / "watchlist.json",
                    Path("watchlist.json"),
                ]
            )

        for target_path in candidate_paths:
            if target_path.is_file():
                try:
                    with open(target_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception as e:
                    logger.warning("Failed to load watchlist from %s: %e", target_path, e)

        return {
            "protected_domains": DEFAULT_PROTECTED_DOMAINS,
            "trusted_partner_vendors": [
                {
                    "vendor_name": "DocuSign",
                    "official_domain": "docusign.com",
                    "allowed_mx_patterns": ["*.docusign.net", "*.mktomail.com"],
                },
                {
                    "vendor_name": "Microsoft 365",
                    "official_domain": "microsoft.com",
                    "allowed_mx_patterns": ["*.protection.outlook.com"],
                },
                {
                    "vendor_name": "ADP Payroll",
                    "official_domain": "adp.com",
                    "allowed_mx_patterns": ["*.adp.com"],
                },
            ],
        }

    def analyze(
        self,
        target: str,
        dns_timeout: Optional[float] = None,
        resolver: Optional[Any] = None,
        offline: bool = False,
        custom_dns_records: Optional[Dict[str, Dict[str, List[str]]]] = None,
    ) -> DomainOSINTReport:
        """Analyze a raw email address or domain string.

        Args:
            target: Input string (e.g. 'user@domain.com', 'domain.com', 'https://domain.com/path').
            dns_timeout: DNS query timeout in seconds.
            resolver: Optional custom `dns.resolver.Resolver` instance.
            offline: If True, skips live DNS network queries and uses mock/cache data.
            custom_dns_records: Dict mapping query names and record types to string responses.

        Returns:
            DomainOSINTReport containing complete authentication posture, lookalike risk, and composite score.
        """
        timeout = dns_timeout or self.default_dns_timeout

        # 1. Normalize Target and Parse Domain Parts
        target_info = self._normalize_target(target)
        analyzed_domain = target_info["analyzed_domain"]
        registered_domain = target_info["registered_domain"]
        unicode_domain = target_info["unicode_domain"]

        # 2. DNS & Authentication Posture Query
        dns_posture = self._query_dns_posture(
            domain=analyzed_domain,
            registered_domain=registered_domain,
            timeout=timeout,
            resolver=resolver,
            offline=offline,
            custom_records=custom_dns_records,
        )

        # 3. Brand & Homoglyph Lookalike Evaluation
        brand_risk = self._evaluate_brand_risk(
            registered_domain=registered_domain,
            unicode_domain=unicode_domain,
            original_input=analyzed_domain,
        )

        # 4. Domain Classification (Corporate, Disposable, Freemail, Lookalike)
        is_disposable, disp_service = self._check_disposable(analyzed_domain, registered_domain)
        is_freemail, free_provider = self._check_freemail(analyzed_domain, registered_domain)
        is_lookalike = brand_risk is not None and brand_risk.risk_indicator in {
            "HIGH_RISK",
            "CRITICAL",
        }

        category = self._classify_domain(
            analyzed_domain=analyzed_domain,
            has_mx=dns_posture.has_mx,
            has_a=bool(dns_posture.a_records),
            is_disposable=is_disposable,
            is_freemail=is_freemail,
            is_lookalike=is_lookalike,
            tld=target_info["tld"],
        )

        # 5. Composite OSINT Threat Scoring
        score, risk_level, factors, summary, remediation = self._compute_osint_risk_score(
            target_info=target_info,
            dns_posture=dns_posture,
            brand_risk=brand_risk,
            category=category,
            is_disposable=is_disposable,
            is_freemail=is_freemail,
        )

        return DomainOSINTReport(
            input_target=target,
            analyzed_domain=analyzed_domain,
            registered_domain=registered_domain,
            tld=target_info["tld"],
            username=target_info["username"],
            is_email_address=target_info["is_email_address"],
            is_punycode=target_info["is_punycode"],
            unicode_domain=unicode_domain,
            category=category,
            dns_posture=dns_posture,
            brand_risk=brand_risk,
            disposable_service=disp_service,
            freemail_provider=free_provider,
            reputation_score=score,
            risk_level=risk_level,
            risk_factors=factors,
            summary=summary,
            remediation_advice=remediation,
            analyzed_at=datetime.now(timezone.utc),
        )

    # -------------------------------------------------------------------------
    # Target Normalization & Parsing
    # -------------------------------------------------------------------------

    def _normalize_target(self, target: str) -> Dict[str, Any]:
        """Normalize raw input into clean domain, username, and IDN details."""
        raw = target.strip()
        username: Optional[str] = None
        is_email = False

        # Strip URL schemes if present
        if "://" in raw:
            parsed = urlparse(raw)
            raw = parsed.netloc or parsed.path

        # Handle email format (e.g. "John Doe <jdoe@example.com>" or "user@example.com")
        _, addr = email.utils.parseaddr(raw)
        if "@" in addr:
            parts = addr.split("@", 1)
            username = parts[0].strip()
            domain_part = parts[1].strip()
            is_email = True
        elif "@" in raw:
            parts = raw.split("@", 1)
            username = parts[0].strip().lstrip("<")
            domain_part = parts[1].strip().rstrip(">")
            is_email = True
        else:
            domain_part = raw.split("/")[0].strip()

        domain_part = domain_part.lower().rstrip(".")

        # Handle Punycode (IDN) vs Unicode
        is_punycode = "xn--" in domain_part
        try:
            if is_punycode:
                unicode_domain = domain_part.encode("ascii").decode("idna")
            else:
                unicode_domain = domain_part
                # Test if domain contains non-ascii characters
                domain_part = unicode_domain.encode("idna").decode("ascii")
                if domain_part != unicode_domain:
                    is_punycode = True
        except Exception:
            unicode_domain = domain_part

        extracted = tldextract.extract(domain_part)
        if extracted.suffix:
            registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()
            tld = extracted.suffix.lower()
        else:
            registered_domain = extracted.domain.lower() if extracted.domain else domain_part
            tld = ""

        return {
            "analyzed_domain": domain_part,
            "registered_domain": registered_domain,
            "unicode_domain": unicode_domain,
            "tld": tld,
            "username": username,
            "is_email_address": is_email,
            "is_punycode": is_punycode,
        }

    # -------------------------------------------------------------------------
    # DNS Authentication Posture Queries
    # -------------------------------------------------------------------------

    def _query_dns_posture(
        self,
        domain: str,
        registered_domain: str,
        timeout: float,
        resolver: Optional[Any],
        offline: bool,
        custom_records: Optional[Dict[str, Dict[str, List[str]]]],
    ) -> DNSAuthPosture:
        """Query DNS for MX, A, NS, SPF, DMARC, DKIM, and BIMI records."""
        start_time = time.perf_counter()
        mx_list: List[MXRecordInfo] = []
        a_list: List[str] = []
        ns_list: List[str] = []
        spf_txt_records: List[str] = []
        dmarc_txt_records: List[str] = []
        bimi_txt_records: List[str] = []
        discovered_dkim: List[DKIMDiscovery] = []
        dns_error: Optional[str] = None

        if offline or custom_records is not None:
            records = custom_records or {}
            domain_rec = records.get(domain, {})
            reg_rec = records.get(registered_domain, {})

            # MX
            for mx_str in domain_rec.get("MX", []) or reg_rec.get("MX", []):
                parts = mx_str.split(None, 1)
                pref = int(parts[0]) if len(parts) > 1 and parts[0].isdigit() else 10
                host = parts[1] if len(parts) > 1 else parts[0]
                mx_list.append(self._enrich_mx_record(host.rstrip("."), pref))

            # A / AAAA
            a_list.extend(domain_rec.get("A", []) or reg_rec.get("A", []))
            a_list.extend(domain_rec.get("AAAA", []) or reg_rec.get("AAAA", []))

            # NS
            ns_list.extend(domain_rec.get("NS", []) or reg_rec.get("NS", []))

            # SPF (from TXT)
            spf_txt_records.extend(domain_rec.get("TXT", []) or reg_rec.get("TXT", []))

            # DMARC
            dmarc_domain_rec = records.get(f"_dmarc.{domain}", {})
            dmarc_reg_rec = records.get(f"_dmarc.{registered_domain}", {})
            dmarc_txt_records.extend(
                dmarc_domain_rec.get("TXT", []) or dmarc_reg_rec.get("TXT", [])
            )

            # BIMI
            bimi_rec = records.get(f"default._bimi.{domain}", {}) or records.get(
                f"default._bimi.{registered_domain}", {}
            )
            bimi_txt_records.extend(bimi_rec.get("TXT", []))

            # DKIM selectors
            for sel in COMMON_DKIM_SELECTORS:
                dkim_key = f"{sel}._domainkey.{domain}"
                dkim_rec = records.get(dkim_key, {})
                for txt in dkim_rec.get("TXT", []):
                    if "v=dkim1" in txt.lower() or "p=" in txt.lower():
                        discovered_dkim.append(self._parse_dkim_txt(sel, dkim_key, txt))

        elif dns is not None:
            res = resolver or dns.resolver.Resolver()
            res.timeout = timeout
            res.lifetime = timeout

            # 1. Query MX
            try:
                answers = res.resolve(domain, "MX")
                for rdata in answers:
                    host = str(rdata.exchange).rstrip(".")
                    pref = int(rdata.preference)
                    mx_list.append(self._enrich_mx_record(host, pref))
            except Exception as e:
                logger.debug("MX lookup failed for %s: %s", domain, e)

            # 2. Query A / AAAA
            try:
                for rtype in ["A", "AAAA"]:
                    try:
                        ans = res.resolve(domain, rtype)
                        for rdata in ans:
                            a_list.append(str(rdata))
                    except Exception:
                        pass
            except Exception:
                pass

            # 3. Query NS
            try:
                ns_ans = res.resolve(domain, "NS")
                for rdata in ns_ans:
                    ns_list.append(str(rdata.target).rstrip("."))
            except Exception:
                pass

            # 4. Query SPF (TXT records on root domain)
            try:
                txt_ans = res.resolve(domain, "TXT")
                for rdata in txt_ans:
                    txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                    spf_txt_records.append(txt)
            except Exception:
                pass

            # 5. Query DMARC (_dmarc.<domain> and fallback _dmarc.<registered_domain>)
            for dmarc_target in [f"_dmarc.{domain}", f"_dmarc.{registered_domain}"]:
                try:
                    dmarc_ans = res.resolve(dmarc_target, "TXT")
                    for rdata in dmarc_ans:
                        txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                        if "v=dmarc1" in txt.lower():
                            dmarc_txt_records.append(txt)
                    if dmarc_txt_records:
                        break
                except Exception:
                    pass

            # 6. Query BIMI (default._bimi.<domain>)
            try:
                bimi_ans = res.resolve(f"default._bimi.{domain}", "TXT")
                for rdata in bimi_ans:
                    txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                    bimi_txt_records.append(txt)
            except Exception:
                pass

            # 7. Probe Common DKIM Selectors
            for sel in COMMON_DKIM_SELECTORS:
                dkim_target = f"{sel}._domainkey.{domain}"
                try:
                    dkim_ans = res.resolve(dkim_target, "TXT")
                    for rdata in dkim_ans:
                        txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                        if "v=dkim1" in txt.lower() or "p=" in txt.lower():
                            discovered_dkim.append(self._parse_dkim_txt(sel, dkim_target, txt))
                except Exception:
                    pass

        query_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        has_mx = len(mx_list) > 0

        spf_posture = self._parse_spf(spf_txt_records)
        dmarc_posture = self._parse_dmarc(dmarc_txt_records)
        bimi_posture = self._parse_bimi(bimi_txt_records)

        return DNSAuthPosture(
            domain=domain,
            has_mx=has_mx,
            mx_records=mx_list,
            a_records=a_list,
            ns_records=ns_list,
            spf=spf_posture,
            dmarc=dmarc_posture,
            discovered_dkim=discovered_dkim,
            bimi=bimi_posture,
            dns_query_time_ms=query_time_ms,
            dns_error=dns_error,
        )

    def _enrich_mx_record(self, host: str, preference: int) -> MXRecordInfo:
        """Enrich MX record with trusted partner vendor identification."""
        matches_trusted = False
        trusted_name: Optional[str] = None

        vendors = self.watchlist.get("trusted_partner_vendors", [])
        for vendor in vendors:
            v_name = vendor.get("vendor_name", "Trusted Partner")
            patterns = vendor.get("allowed_mx_patterns", [])
            for pat in patterns:
                # Handle wildcard patterns e.g. *.protection.outlook.com
                regex_pat = "^" + re.escape(pat).replace(r"\*", ".*") + "$"
                if re.match(regex_pat, host, re.IGNORECASE):
                    matches_trusted = True
                    trusted_name = v_name
                    break
            if matches_trusted:
                break

        return MXRecordInfo(
            host=host,
            preference=preference,
            ip_addresses=[],
            matches_trusted_vendor=matches_trusted,
            trusted_vendor_name=trusted_name,
        )

    def _parse_spf(self, txt_records: List[str]) -> SPFPosture:
        """Parse SPF record text into structured posture and strictness rating."""
        spf_records = [t for t in txt_records if t.lower().startswith("v=spf1")]

        if not spf_records:
            return SPFPosture(
                raw_record=None,
                qualifier="missing",
                strictness=SPFStrictness.MISSING,
                mechanisms=[],
                lookup_count=0,
                warnings=["Domain has no SPF record published in DNS TXT records."],
                is_valid=False,
            )

        warnings: List[str] = []
        if len(spf_records) > 1:
            warnings.append(
                f"Multiple SPF records found ({len(spf_records)}). RFC 7208 forbids multiple SPF records (Permanent Error)."
            )

        raw_spf = spf_records[0]
        mechanisms = raw_spf.split()

        qualifier = "neutral"
        strictness = SPFStrictness.NEUTRAL

        # Look for the 'all' qualifier (e.g., -all, ~all, ?all, +all, all)
        all_mech = next((m.lower() for m in mechanisms if m.lower().endswith("all")), None)
        if all_mech:
            if all_mech.startswith("-"):
                qualifier = "-all"
                strictness = SPFStrictness.STRICT
            elif all_mech.startswith("~"):
                qualifier = "~all"
                strictness = SPFStrictness.SOFTFAIL
            elif all_mech.startswith("+") or all_mech == "all":
                qualifier = "+all"
                strictness = SPFStrictness.PERMISSIVE
                warnings.append(
                    "SPF record uses dangerous permissive qualifier (+all / all), allowing any sender IP to spoof."
                )
            elif all_mech.startswith("?"):
                qualifier = "?all"
                strictness = SPFStrictness.NEUTRAL
                warnings.append(
                    "SPF record uses neutral qualifier (?all), offering zero spoofing protection."
                )

        # Estimate DNS mechanism lookup count (RFC limit = 10)
        lookup_types = ("include:", "a", "mx", "ptr", "exists:", "redirect=")
        lookup_count = sum(
            1 for m in mechanisms if any(m.lower().startswith(lt) for lt in lookup_types)
        )
        if lookup_count > 10:
            warnings.append(
                f"SPF record contains {lookup_count} DNS lookups, exceeding RFC 7208 limit of 10."
            )

        return SPFPosture(
            raw_record=raw_spf,
            qualifier=qualifier,
            strictness=strictness if not len(spf_records) > 1 else SPFStrictness.INVALID,
            mechanisms=mechanisms,
            lookup_count=lookup_count,
            warnings=warnings,
            is_valid=len(spf_records) == 1 and strictness != SPFStrictness.PERMISSIVE,
        )

    def _parse_dmarc(self, txt_records: List[str]) -> DMARCPosture:
        """Parse DMARC record and extract policy, reporting, and enforcement posture."""
        dmarc_records = [t for t in txt_records if t.lower().startswith("v=dmarc1")]

        if not dmarc_records:
            return DMARCPosture(
                raw_record=None,
                policy="missing",
                subdomain_policy=None,
                percentage=100,
                rua_uris=[],
                ruf_uris=[],
                enforcement=DMARCEnforcement.MISSING,
                warnings=[
                    "No DMARC record found. Domain is vulnerable to direct address spoofing."
                ],
                is_valid=False,
            )

        raw_dmarc = dmarc_records[0]
        warnings: List[str] = []

        # Parse tags using regex (e.g. p=reject; sp=quarantine; pct=100; rua=mailto:...)
        tags: Dict[str, str] = {}
        for token in raw_dmarc.split(";"):
            token = token.strip()
            if "=" in token:
                k, v = token.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        policy = tags.get("p", "none").lower()
        subdomain_policy = tags.get("sp", policy).lower() if "sp" in tags else None

        try:
            pct = int(tags.get("pct", "100"))
        except ValueError:
            pct = 100

        rua = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
        ruf = [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()]
        adkim = tags.get("adkim", "r").lower()
        aspf = tags.get("aspf", "r").lower()

        if policy == "reject":
            enforcement = DMARCEnforcement.REJECT
        elif policy == "quarantine":
            enforcement = DMARCEnforcement.QUARANTINE
        else:
            enforcement = DMARCEnforcement.NONE
            warnings.append(
                "DMARC policy is set to 'none' (monitoring only); spoofed messages will still be delivered."
            )

        if pct < 100:
            warnings.append(
                f"DMARC enforcement percentage is only {pct}%, leaving {100 - pct}% of traffic unenforced."
            )

        if not rua:
            warnings.append("DMARC record lacks an aggregate reporting URI (rua=).")

        return DMARCPosture(
            raw_record=raw_dmarc,
            policy=policy,
            subdomain_policy=subdomain_policy,
            percentage=pct,
            rua_uris=rua,
            ruf_uris=ruf,
            adkim=adkim,
            aspf=aspf,
            enforcement=enforcement,
            warnings=warnings,
            is_valid=True,
        )

    def _parse_bimi(self, txt_records: List[str]) -> BIMIPosture:
        """Parse BIMI (Brand Indicators for Message Identification) record."""
        bimi_records = [t for t in txt_records if t.lower().startswith("v=bimi1")]
        if not bimi_records:
            return BIMIPosture(raw_record=None, is_valid=False)

        raw = bimi_records[0]
        logo_url = None
        auth_url = None

        for token in raw.split(";"):
            token = token.strip()
            if "=" in token:
                k, v = token.split("=", 1)
                k_l = k.strip().lower()
                if k_l == "l":
                    logo_url = v.strip()
                elif k_l == "a":
                    auth_url = v.strip()

        has_vmc = bool(auth_url and auth_url.startswith("https://"))
        return BIMIPosture(
            raw_record=raw,
            logo_url=logo_url,
            authority_url=auth_url,
            has_vmc=has_vmc,
            is_valid=bool(logo_url),
        )

    def _parse_dkim_txt(self, selector: str, record_name: str, raw_txt: str) -> DKIMDiscovery:
        """Parse discovered DKIM public key record."""
        key_type = "rsa"
        pub_key = ""
        for token in raw_txt.split(";"):
            token = token.strip()
            if "=" in token:
                k, v = token.split("=", 1)
                k_l = k.strip().lower()
                if k_l == "k":
                    key_type = v.strip().lower()
                elif k_l == "p":
                    pub_key = v.strip()

        preview = f"{pub_key[:16]}...{pub_key[-8:]}" if len(pub_key) > 24 else pub_key
        return DKIMDiscovery(
            selector=selector,
            record_name=record_name,
            raw_record=raw_txt,
            key_type=key_type,
            public_key_preview=preview,
            is_valid=bool(pub_key),
        )

    # -------------------------------------------------------------------------
    # Homoglyphs, Brand & Lookalike Detection
    # -------------------------------------------------------------------------

    def _evaluate_brand_risk(
        self,
        registered_domain: str,
        unicode_domain: str,
        original_input: str,
    ) -> Optional[BrandMatchResult]:
        """Evaluate whether target domain mimics a protected brand via typosquatting or homoglyphs."""
        protected_list: List[str] = self.watchlist.get(
            "protected_domains", DEFAULT_PROTECTED_DOMAINS
        )

        has_homoglyphs, homoglyph_chars, transliterated = self._detect_homoglyphs(unicode_domain)
        trans_registered = tldextract.extract(transliterated).domain.lower()
        target_stem = tldextract.extract(registered_domain).domain.lower()

        best_match: Optional[BrandMatchResult] = None
        highest_similarity = 0.0

        for brand in protected_list:
            brand_stem = tldextract.extract(brand).domain.lower()

            # Exact match means it IS the official brand
            if registered_domain.lower() == brand.lower():
                return BrandMatchResult(
                    matched_brand_domain=brand,
                    levenshtein_distance=0,
                    similarity_score=1.0,
                    homoglyphs_detected=[],
                    has_homoglyphs=False,
                    is_cousin_domain=False,
                    risk_indicator="CLEAN",
                )

            # Compute Levenshtein distance on raw stem and transliterated stem
            dist_raw = self._levenshtein_distance(target_stem, brand_stem)
            dist_trans = self._levenshtein_distance(trans_registered, brand_stem)
            effective_dist = min(dist_raw, dist_trans)

            max_len = max(len(target_stem), len(brand_stem), 1)
            sim_score = round(1.0 - (effective_dist / max_len), 3)

            # Check if domain is combosquatted (e.g. acme-security, login-paypal)
            is_combosquat = (
                brand_stem in target_stem
                or target_stem in brand_stem
                or any(
                    target_stem.startswith(f"{brand_stem}-")
                    or target_stem.endswith(f"-{brand_stem}")
                    for _ in [1]
                )
            ) and len(target_stem) != len(brand_stem)

            if has_homoglyphs and (trans_registered == brand_stem or dist_trans <= 1):
                # Critical homoglyph impersonation attack
                return BrandMatchResult(
                    matched_brand_domain=brand,
                    levenshtein_distance=effective_dist,
                    similarity_score=0.95,
                    homoglyphs_detected=homoglyph_chars,
                    has_homoglyphs=True,
                    is_cousin_domain=True,
                    risk_indicator="CRITICAL",
                )

            if effective_dist <= 2 or is_combosquat or sim_score >= 0.75:
                if sim_score > highest_similarity:
                    highest_similarity = sim_score
                    indicator = "CRITICAL" if effective_dist <= 1 else "HIGH_RISK"
                    best_match = BrandMatchResult(
                        matched_brand_domain=brand,
                        levenshtein_distance=effective_dist,
                        similarity_score=sim_score,
                        homoglyphs_detected=homoglyph_chars,
                        has_homoglyphs=has_homoglyphs,
                        is_cousin_domain=True,
                        risk_indicator=indicator,
                    )

        return best_match

    @classmethod
    def _detect_homoglyphs(cls, text: str) -> Tuple[bool, List[str], str]:
        """Detect and transliterate homoglyph characters."""
        found_chars: List[str] = []
        transliterated = []
        for char in text:
            if char in HOMOGLYPH_MAP:
                found_chars.append(f"'{char}' -> '{HOMOGLYPH_MAP[char]}'")
                transliterated.append(HOMOGLYPH_MAP[char])
            else:
                transliterated.append(char)

        return bool(found_chars), found_chars, "".join(transliterated)

    @classmethod
    def _levenshtein_distance(cls, s1: str, s2: str) -> int:
        """Calculate Damerau-Levenshtein edit distance."""
        if len(s1) < len(s2):
            return cls._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev[j + 1] + 1
                deletions = curr[j] + 1
                substitutions = prev[j] + (c1 != c2)
                curr.append(min(insertions, deletions, substitutions))
            prev = curr
        return prev[-1]

    # -------------------------------------------------------------------------
    # Disposable & Freemail Checking
    # -------------------------------------------------------------------------

    @classmethod
    def _check_disposable(cls, domain: str, registered_domain: str) -> Tuple[bool, Optional[str]]:
        """Check if domain belongs to a disposable or temporary email provider."""
        for d in [domain, registered_domain]:
            if d in EXTENDED_DISPOSABLE_DOMAINS:
                return True, f"Known disposable email service: {d}"
        # Heuristic keywords for temporary mailboxes
        disp_keywords = [
            "tempmail",
            "disposable",
            "guerrillamail",
            "10minutemail",
            "fakemail",
            "throwaway",
        ]
        if any(k in domain for k in disp_keywords):
            return True, "Heuristic match for disposable email pattern"
        return False, None

    @classmethod
    def _check_freemail(cls, domain: str, registered_domain: str) -> Tuple[bool, Optional[str]]:
        """Check if domain is a public freemail webmail provider."""
        for d in [domain, registered_domain]:
            if d in FREEMAIL_DOMAINS:
                return True, f"Public webmail provider: {d}"
        return False, None

    @classmethod
    def _classify_domain(
        cls,
        analyzed_domain: str,
        has_mx: bool,
        has_a: bool,
        is_disposable: bool,
        is_freemail: bool,
        is_lookalike: bool,
        tld: str,
    ) -> DomainCategory:
        """Classify domain profile."""
        if is_lookalike:
            return DomainCategory.LOOKALIKE
        if is_disposable:
            return DomainCategory.DISPOSABLE
        if is_freemail:
            return DomainCategory.FREEMAIL
        if tld in {"gov", "mil", "edu", "ac.uk", "gov.uk"}:
            return DomainCategory.GOVERNMENT_EDU
        if not has_mx and not has_a:
            return DomainCategory.UNRESOLVED
        return DomainCategory.CORPORATE

    # -------------------------------------------------------------------------
    # Composite Threat & Reputation Scoring
    # -------------------------------------------------------------------------

    def _compute_osint_risk_score(
        self,
        target_info: Dict[str, Any],
        dns_posture: DNSAuthPosture,
        brand_risk: Optional[BrandMatchResult],
        category: DomainCategory,
        is_disposable: bool,
        is_freemail: bool,
    ) -> Tuple[float, RiskSeverity, List[RiskFactor], str, List[str]]:
        """Compute composite 0-100 OSINT risk score and generate mitigation guidance."""
        factors: List[RiskFactor] = []
        score = 0.0
        remediation: List[str] = []

        # 1. Brand Impersonation & Lookalike Risk
        if brand_risk and brand_risk.risk_indicator == "CRITICAL":
            score += 55.0
            remediation.append(
                f"CRITICAL: Domain appears to spoof protected brand '{brand_risk.matched_brand_domain}'. Add to perimeter DNS blocklist."
            )
            factors.append(
                RiskFactor(
                    vector=RiskVectorType.BEC_SOCIAL_ENGINEERING,
                    name="Brand Impersonation / Homoglyph Attack",
                    score_contribution=55.0,
                    severity="CRITICAL",
                    description=(
                        f"Domain closely mimics '{brand_risk.matched_brand_domain}' (Levenshtein distance: "
                        f"{brand_risk.levenshtein_distance}, Homoglyphs: {brand_risk.homoglyphs_detected})."
                    ),
                )
            )
        elif brand_risk and brand_risk.risk_indicator == "HIGH_RISK":
            score += 35.0
            remediation.append(
                f"HIGH RISK: Typosquatted cousin domain targeting '{brand_risk.matched_brand_domain}'. Enforce strict inbound filtering."
            )
            factors.append(
                RiskFactor(
                    vector=RiskVectorType.BEC_SOCIAL_ENGINEERING,
                    name="Typosquatted Brand Cousin Domain",
                    score_contribution=35.0,
                    severity="HIGH",
                    description=f"Domain is a potential lookalike for '{brand_risk.matched_brand_domain}' (similarity: {brand_risk.similarity_score}).",
                )
            )

        # 2. Disposable Email Service
        if is_disposable:
            score += 40.0
            remediation.append(
                "Block disposable email service domains from account registration and email gateway."
            )
            factors.append(
                RiskFactor(
                    vector=RiskVectorType.AUTHENTICATION,
                    name="Disposable / Temporary Email Service",
                    score_contribution=40.0,
                    severity="HIGH",
                    description="Domain is operated by a temporary/disposable email provider commonly used for abuse.",
                )
            )

        # 3. SPF Posture Evaluation
        spf = dns_posture.spf
        if spf.strictness == SPFStrictness.MISSING:
            score += 15.0
            remediation.append(
                "Publish a valid SPF record with hardfail (`-all`) or softfail (`~all`)."
            )
            factors.append(
                RiskFactor(
                    vector=RiskVectorType.AUTHENTICATION,
                    name="Missing SPF Record",
                    score_contribution=15.0,
                    severity="MEDIUM",
                    description="Domain has no SPF record published, allowing unauthenticated senders to forge headers.",
                )
            )
        elif spf.strictness == SPFStrictness.PERMISSIVE:
            score += 25.0
            remediation.append(
                "Remove dangerous `+all` qualifier from SPF record; replace with `-all`."
            )
            factors.append(
                RiskFactor(
                    vector=RiskVectorType.AUTHENTICATION,
                    name="Dangerous Permissive SPF (+all)",
                    score_contribution=25.0,
                    severity="HIGH",
                    description="SPF record explicitly permits all internet IPs to send on behalf of this domain.",
                )
            )
        elif spf.strictness == SPFStrictness.NEUTRAL:
            score += 10.0
            factors.append(
                RiskFactor(
                    vector=RiskVectorType.AUTHENTICATION,
                    name="Neutral SPF Policy (?all)",
                    score_contribution=10.0,
                    severity="LOW",
                    description="SPF policy is neutral (?all), which offers no recipient rejection enforcement.",
                )
            )

        # 4. DMARC Posture Evaluation
        dmarc = dns_posture.dmarc
        if dmarc.enforcement == DMARCEnforcement.MISSING:
            score += 20.0
            remediation.append(
                "Deploy a DMARC record at `_dmarc.<domain>` starting with `p=quarantine` or `p=reject`."
            )
            factors.append(
                RiskFactor(
                    vector=RiskVectorType.AUTHENTICATION,
                    name="Missing DMARC Policy",
                    score_contribution=20.0,
                    severity="HIGH",
                    description="No DMARC policy found. Domain provides zero protection against direct address spoofing.",
                )
            )
        elif dmarc.enforcement == DMARCEnforcement.NONE:
            score += 10.0
            remediation.append(
                "Upgrade DMARC policy from `p=none` (monitoring) to `p=quarantine` or `p=reject`."
            )
            factors.append(
                RiskFactor(
                    vector=RiskVectorType.AUTHENTICATION,
                    name="DMARC Monitoring Only (p=none)",
                    score_contribution=10.0,
                    severity="LOW",
                    description="DMARC policy is set to 'none', meaning spoofed messages are delivered without rejection.",
                )
            )

        # 5. Mail Routing & MX Presence
        if not dns_posture.has_mx and target_info["is_email_address"]:
            score += 15.0
            remediation.append(
                "Domain has no MX records and cannot receive standard inbound email."
            )
            factors.append(
                RiskFactor(
                    vector=RiskVectorType.AUTHENTICATION,
                    name="No Inbound Mail Servers (Missing MX)",
                    score_contribution=15.0,
                    severity="MEDIUM",
                    description="Target domain has no MX records published, indicating send-only or abandoned domain.",
                )
            )

        # 6. Unresolved / Inactive Domain
        if category == DomainCategory.UNRESOLVED:
            score += 20.0
            factors.append(
                RiskFactor(
                    vector=RiskVectorType.AUTHENTICATION,
                    name="Unresolved / Parked Domain",
                    score_contribution=20.0,
                    severity="MEDIUM",
                    description="Domain lacks both MX and A DNS records.",
                )
            )

        # Cap score between 0.0 and 100.0
        final_score = min(max(round(score, 1), 0.0), 100.0)

        # Assign Risk Severity Tier
        if final_score >= 75.0:
            severity = RiskSeverity.CRITICAL
        elif final_score >= 50.0:
            severity = RiskSeverity.MALICIOUS_HIGH
        elif final_score >= 25.0:
            severity = RiskSeverity.SUSPICIOUS_MEDIUM
        elif final_score > 5.0:
            severity = RiskSeverity.SUSPICIOUS_LOW
        else:
            severity = RiskSeverity.CLEAN

        # Executive Summary synthesis
        if severity in {RiskSeverity.CRITICAL, RiskSeverity.MALICIOUS_HIGH}:
            summary = (
                f"HIGH THREAT: Domain '{target_info['analyzed_domain']}' exhibits high risk signals "
                f"(Score: {final_score}/100, Level: {severity.value}). "
                f"Category: {category.value}."
            )
        elif severity == RiskSeverity.SUSPICIOUS_MEDIUM:
            summary = (
                f"SUSPICIOUS: Domain '{target_info['analyzed_domain']}' has email authentication or policy weaknesses "
                f"(Score: {final_score}/100, Level: {severity.value})."
            )
        else:
            summary = (
                f"LOW RISK / SECURE: Domain '{target_info['analyzed_domain']}' demonstrates healthy authentication "
                f"posture and no active impersonation signals (Score: {final_score}/100)."
            )

        if not remediation:
            remediation.append(
                "Maintain current strict SPF/DMARC policy enforcement and periodic DKIM key rotation."
            )

        return final_score, severity, factors, summary, remediation
