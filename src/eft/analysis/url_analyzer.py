"""Forensic URL Extraction, Defanging, Anchor Mismatch & Homograph Detection Engine.

Extracts all hyperlinks from HTML/plain email bodies, sanitizes them via safe defanging,
identifies deceptive anchor text mismatches, detects Unicode IDN / Punycode homograph
attacks, and flags IP-as-host, shorteners, and suspicious redirect patterns.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import unicodedata
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

import tldextract
from bs4 import BeautifulSoup

from eft.models.canonical import CanonicalEmail, ExtractedURL, URLExtractionReport

# Known popular URL shortener domains
URL_SHORTENER_DOMAINS: Set[str] = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "bit.do",
    "mcaf.ee",
    "su.pr",
    "cutt.ly",
    "shorturl.at",
    "goo.gl",
    "qr.net",
    "v.gd",
    "trib.al",
    "rebrand.ly",
    "tiny.cc",
    "bl.ink",
    "clck.ru",
    "s.id",
    "linktr.ee",
}

# Known high-abuse / free / disposable top-level domains frequently observed in phishing
SUSPICIOUS_TLDS: Set[str] = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "buzz",
    "work",
    "icu",
    "loan",
    "click",
    "fit",
    "rest",
    "surf",
    "gdn",
    "racing",
    "cam",
    "country",
    "stream",
}

# Regex to detect raw URLs in text (RFC 3986 compliant extraction)
URL_REGEX = re.compile(
    r"""(?xi)
    \b
    (?:
      (?:https?|ftp|sftp)://
      |
      www\d{0,3}[.]
    )
    [^\s()<>"'’]+
    (?:\([^\s()<>"'’]+\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])
    """
)

# Open redirect query parameters frequently abused in phishing
OPEN_REDIRECT_PARAMS = {
    "redirect",
    "url",
    "next",
    "dest",
    "target",
    "link",
    "r",
    "goto",
    "out",
    "uri",
}

# Credential phish query parameters commonly containing victim identifiers
PHISH_IDENTITY_PARAMS = {"email", "user", "username", "login", "account", "id", "recipient", "to"}


class URLAnalyzer:
    """Forensic engine for hyperlink analysis, defanging, anchor discrepancy, and homograph detection."""

    def __init__(self) -> None:
        self.tld_extractor = tldextract.TLDExtract()

    def extract_urls(self, email: CanonicalEmail) -> URLExtractionReport:
        """Extract and analyze all URLs from an email's HTML body, plaintext body, and headers.

        Args:
            email: The canonical email to inspect.

        Returns:
            A comprehensive URLExtractionReport.
        """
        extracted_records: List[ExtractedURL] = []
        seen_keys: Set[Tuple[str, str, Optional[str]]] = set()  # (url, source, anchor)

        # 1. Extract from HTML body if present
        if email.body_html:
            html_records = self._extract_from_html(email.body_html)
            for rec in html_records:
                key = (rec.url, rec.source_location, rec.anchor_text)
                if key not in seen_keys:
                    seen_keys.add(key)
                    extracted_records.append(rec)

        # 2. Extract from plaintext body if present
        if email.body_plain:
            plain_records = self._extract_from_plaintext(email.body_plain)
            for rec in plain_records:
                key = (rec.url, rec.source_location, rec.anchor_text)
                if key not in seen_keys:
                    seen_keys.add(key)
                    extracted_records.append(rec)

        # 3. Extract from specific URL headers (e.g. List-Unsubscribe, X-Original-Url)
        header_records = self._extract_from_headers(email.headers)
        for rec in header_records:
            key = (rec.url, rec.source_location, rec.anchor_text)
            if key not in seen_keys:
                seen_keys.add(key)
                extracted_records.append(rec)

        # Synthesize metrics and overall report
        unique_domains = sorted(
            list(
                {
                    rec.domain.lower()
                    for rec in extracted_records
                    if rec.domain and not rec.domain.startswith("mailto:")
                }
            )
        )

        anchor_mismatches = sum(1 for rec in extracted_records if rec.is_anchor_mismatch)
        homographs = sum(1 for rec in extracted_records if rec.is_idn_homograph)
        ip_urls = sum(1 for rec in extracted_records if rec.is_ip_host)
        shorteners = sum(1 for rec in extracted_records if rec.is_shortener)

        global_flags: List[str] = []
        for rec in extracted_records:
            for flag in rec.risk_flags:
                if flag not in global_flags:
                    global_flags.append(flag)

        # Determine overall verdict
        overall_verdict = "CLEAN"
        max_score = max([rec.risk_score for rec in extracted_records], default=0.0)

        if max_score >= 60.0 or anchor_mismatches > 0 or homographs > 0:
            overall_verdict = "MALICIOUS"
        elif max_score >= 20.0 or ip_urls > 0 or shorteners > 0:
            overall_verdict = "SUSPICIOUS"

        report = URLExtractionReport(
            total_urls_found=len(extracted_records),
            unique_domains=unique_domains,
            urls=extracted_records,
            anchor_mismatches_count=anchor_mismatches,
            homographs_count=homographs,
            ip_urls_count=ip_urls,
            shorteners_count=shorteners,
            overall_url_risk=overall_verdict,
            risk_flags=global_flags,
        )

        email.url_report = report
        return report

    @staticmethod
    def _get_str_attr(tag: Any, attr_name: str) -> str:
        """Safely extract a single string attribute from a BeautifulSoup tag."""
        val = tag.get(attr_name, "")
        if isinstance(val, list):
            return " ".join(val).strip()
        if isinstance(val, str):
            return val.strip()
        return ""

    def _extract_from_html(self, html_content: str) -> List[ExtractedURL]:
        """Parse HTML DOM and extract links from elements and text."""
        records: List[ExtractedURL] = []
        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception:
            # Fallback to plaintext regex if HTML parsing fails
            return self._extract_from_plaintext(html_content, source_label="html_unparsed")

        # Extract <a> anchor tags
        for a_tag in soup.find_all("a", href=True):
            href = self._get_str_attr(a_tag, "href")
            if not href or self._is_ignorable_scheme(href):
                continue

            # Anchor display text
            anchor_text = a_tag.get_text(strip=True) or None
            if not anchor_text:
                img = a_tag.find("img")
                if img:
                    img_alt = self._get_str_attr(img, "alt")
                    img_title = self._get_str_attr(img, "title")
                    anchor_text = img_alt or img_title or "[Image Link]"

            rec = self.analyze_single_url(
                raw_url=href,
                anchor_text=anchor_text,
                source_location="html_href",
            )
            records.append(rec)

        # Extract <form action="...">
        for form_tag in soup.find_all("form", action=True):
            action = self._get_str_attr(form_tag, "action")
            if action and not self._is_ignorable_scheme(action):
                rec = self.analyze_single_url(
                    raw_url=action,
                    anchor_text="<form action>",
                    source_location="html_action",
                )
                records.append(rec)

        # Extract <img> src
        for img_tag in soup.find_all("img"):
            src = self._get_str_attr(img_tag, "src") or self._get_str_attr(img_tag, "data-src")
            if src and not self._is_ignorable_scheme(src):
                alt_text = self._get_str_attr(img_tag, "alt") or "<img src>"
                rec = self.analyze_single_url(
                    raw_url=src,
                    anchor_text=alt_text,
                    source_location="html_src",
                )
                records.append(rec)

        # Extract <iframe src="...">
        for iframe_tag in soup.find_all("iframe", src=True):
            src = self._get_str_attr(iframe_tag, "src")
            if src and not self._is_ignorable_scheme(src):
                rec = self.analyze_single_url(
                    raw_url=src,
                    anchor_text="<iframe src>",
                    source_location="html_iframe",
                )
                records.append(rec)

        # Extract any raw unlinked text URLs in HTML text
        text_content = soup.get_text()
        text_matches = URL_REGEX.findall(text_content)
        for match in text_matches:
            cleaned_match = self._clean_regex_url(match)
            if cleaned_match and not self._is_ignorable_scheme(cleaned_match):
                rec = self.analyze_single_url(
                    raw_url=cleaned_match,
                    anchor_text=None,
                    source_location="html_body_text",
                )
                records.append(rec)

        return records

    def _extract_from_plaintext(
        self, text_content: str, source_label: str = "plain_body_text"
    ) -> List[ExtractedURL]:
        """Extract URLs from plaintext body using regex."""
        records: List[ExtractedURL] = []
        matches = URL_REGEX.findall(text_content)
        for match in matches:
            cleaned_match = self._clean_regex_url(match)
            if cleaned_match and not self._is_ignorable_scheme(cleaned_match):
                rec = self.analyze_single_url(
                    raw_url=cleaned_match,
                    anchor_text=None,
                    source_location=source_label,
                )
                records.append(rec)
        return records

    def _extract_from_headers(self, headers: Dict[str, Any]) -> List[ExtractedURL]:
        """Extract URLs from specific email headers."""
        records: List[ExtractedURL] = []
        target_headers = ["list-unsubscribe", "x-original-url", "x-mailer-url"]
        for hdr_name, val in headers.items():
            if hdr_name.lower() in target_headers:
                values = [val] if isinstance(val, str) else val
                for v in values:
                    matches = URL_REGEX.findall(v)
                    for match in matches:
                        cleaned_match = self._clean_regex_url(match)
                        if cleaned_match and not self._is_ignorable_scheme(cleaned_match):
                            rec = self.analyze_single_url(
                                raw_url=cleaned_match,
                                anchor_text=f"Header: {hdr_name}",
                                source_location="header",
                            )
                            records.append(rec)
        return records

    def analyze_single_url(
        self,
        raw_url: str,
        anchor_text: Optional[str] = None,
        source_location: str = "body_text",
    ) -> ExtractedURL:
        """Forensically inspect, defang, and evaluate threat indicators for an extracted URL."""
        # Normalize protocol if starts with www
        normalized_url = raw_url
        if raw_url.lower().startswith("www."):
            normalized_url = "http://" + raw_url

        parsed = urllib.parse.urlparse(normalized_url)
        scheme = parsed.scheme.lower() or "http"
        host = parsed.hostname or ""

        # Safe defanging
        defanged = self.defang_url(raw_url)

        # Heuristic checks
        flags: List[str] = []
        score = 0.0

        # 1. Check IP-as-host
        is_ip, ip_details = self.detect_ip_host(host)
        if is_ip:
            flags.append("IP_HOST_URL")
            score += 35.0

        # 2. Check Unicode IDN / Homograph attack
        is_homograph, punycode, unicode_dom, homoglyphs = self.detect_homographs(host)
        if is_homograph:
            flags.append("IDN_HOMOGRAPH_ATTACK")
            score += 45.0

        # 3. Check Anchor Text Mismatch
        is_mismatch, anchor_dom = self.detect_anchor_mismatch(normalized_url, anchor_text)
        if is_mismatch:
            flags.append("ANCHOR_URL_MISMATCH")
            score += 40.0

        # 4. Check Shortener
        is_shortener = self.detect_shorteners(host)
        if is_shortener:
            flags.append("SUSPICIOUS_SHORTENER")
            score += 20.0

        # 5. Check Suspicious TLD
        is_susp_tld = self.detect_suspicious_tld(host)
        if is_susp_tld:
            flags.append("SUSPICIOUS_TLD")
            score += 15.0

        # 6. Check Suspicious Ports
        if parsed.port and parsed.port not in {80, 443, 8080, 8443}:
            flags.append("SUSPICIOUS_PORT")
            score += 20.0

        # 7. Check Credential Phishing / Open Redirect query parameters
        if parsed.query:
            query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            param_keys = {k.lower() for k in query_params.keys()}

            if param_keys.intersection(PHISH_IDENTITY_PARAMS):
                flags.append("CREDENTIAL_PHISH_PARAM")
                score += 25.0

            if param_keys.intersection(OPEN_REDIRECT_PARAMS):
                flags.append("OPEN_REDIRECT_PARAM")
                score += 15.0

            # Check if query contains base64 encoded email
            if self._has_base64_email(parsed.query):
                flags.append("BASE64_ENCODED_TARGET")
                score += 20.0

        risk_score = min(score, 100.0)

        return ExtractedURL(
            url=raw_url,
            defanged_url=defanged,
            anchor_text=anchor_text,
            source_location=source_location,
            domain=host,
            scheme=scheme,
            is_anchor_mismatch=is_mismatch,
            anchor_domain=anchor_dom,
            is_idn_homograph=is_homograph,
            punycode_domain=punycode,
            unicode_domain=unicode_dom,
            homoglyph_details=homoglyphs,
            is_ip_host=is_ip,
            is_shortener=is_shortener,
            is_suspicious_tld=is_susp_tld,
            risk_flags=flags,
            risk_score=risk_score,
        )

    # -------------------------------------------------------------------------
    # Core Forensic Helper Algorithms
    # -------------------------------------------------------------------------

    @staticmethod
    def defang_url(url: str) -> str:
        """Convert a potentially dangerous URL into a safe defanged indicator.

        Examples:
            https://evil.com/phish -> hxxps[://]evil[.]com/phish
            http://192.168.1.1:8080 -> hxxp[://]192[.]168[.]1[.]1:8080
            ftp://site.org -> fxp[://]site[.]org
        """
        if not url:
            return ""

        result = url

        # 1. Defang protocol
        result = re.sub(r"^https://", "hxxps[://]", result, flags=re.IGNORECASE)
        result = re.sub(r"^http://", "hxxp[://]", result, flags=re.IGNORECASE)
        result = re.sub(r"^ftp://", "fxp[://]", result, flags=re.IGNORECASE)
        result = re.sub(r"^sftp://", "sfxp[://]", result, flags=re.IGNORECASE)

        # 2. Defang dots in the host/authority portion
        if "[://]" in result:
            parts = result.split("[://]", 1)
            proto = parts[0]
            rest = parts[1]

            # Separate host and path/query
            slash_idx = rest.find("/")
            if slash_idx != -1:
                host_part = rest[:slash_idx]
                path_part = rest[slash_idx:]
            else:
                host_part = rest
                path_part = ""

            host_part = host_part.replace(".", "[.]")
            result = f"{proto}[://]{host_part}{path_part}"
        else:
            # If no scheme, split by first slash to only defang host
            slash_idx = result.find("/")
            if slash_idx != -1:
                host_part = result[:slash_idx]
                path_part = result[slash_idx:]
                host_part = host_part.replace(".", "[.]")
                result = f"{host_part}{path_part}"
            else:
                result = result.replace(".", "[.]")

        return result

    @staticmethod
    def refang_url(defanged: str) -> str:
        """Convert a defanged URL back into its original live format."""
        if not defanged:
            return ""

        result = defanged
        result = re.sub(r"^hxxps\[://\]", "https://", result, flags=re.IGNORECASE)
        result = re.sub(r"^hxxp\[://\]", "http://", result, flags=re.IGNORECASE)
        result = re.sub(r"^fxp\[://\]", "ftp://", result, flags=re.IGNORECASE)
        result = re.sub(r"^sfxp\[://\]", "sftp://", result, flags=re.IGNORECASE)
        result = result.replace("[.]", ".")
        result = result.replace("[:]", ":")
        return result

    def detect_anchor_mismatch(
        self, href: str, anchor_text: Optional[str]
    ) -> Tuple[bool, Optional[str]]:
        """Detect if the visible anchor text deceives the user by displaying a different domain.

        Example:
            anchor: "https://login.microsoft.com"
            href: "http://evil-phish.ru/mslogin"
            -> (True, "microsoft.com")
        """
        if not anchor_text:
            return False, None

        anchor_clean = anchor_text.strip()
        # Check if anchor contains a domain or URL pattern
        anchor_match = URL_REGEX.search(anchor_clean)
        extracted_anchor_str = anchor_match.group(0) if anchor_match else anchor_clean

        # Check if anchor looks like a domain / web address
        if not (
            extracted_anchor_str.startswith(("http://", "https://", "www."))
            or ("." in extracted_anchor_str and not extracted_anchor_str.endswith("."))
        ):
            return False, None

        # Extract target domain
        parsed_href = urllib.parse.urlparse(href if "://" in href else "http://" + href)
        href_host = parsed_href.hostname or ""
        if not href_host:
            return False, None

        # Extract anchor domain
        anchor_candidate = extracted_anchor_str
        if not anchor_candidate.startswith(("http://", "https://")):
            anchor_candidate = "http://" + anchor_candidate

        parsed_anchor = urllib.parse.urlparse(anchor_candidate)
        anchor_host = parsed_anchor.hostname or ""
        if not anchor_host or anchor_host.count(".") == 0:
            return False, None

        # Compare registered domains (eTLD+1)
        href_ext = self.tld_extractor(href_host)
        anchor_ext = self.tld_extractor(anchor_host)

        href_reg = self._get_registered_domain(href_ext)
        anchor_reg = self._get_registered_domain(anchor_ext)

        # If both resolve to registered domains and they differ -> Mismatch!
        if href_reg and anchor_reg and href_reg != anchor_reg:
            return True, anchor_reg

        return False, None

    @staticmethod
    def _get_registered_domain(extracted: Any) -> str:
        """Safely extract the registered domain under public suffix without deprecation warnings."""
        if hasattr(extracted, "top_domain_under_public_suffix"):
            return str(extracted.top_domain_under_public_suffix or "").lower()
        if hasattr(extracted, "registered_domain"):
            return str(extracted.registered_domain or "").lower()
        return ""

    def detect_homographs(self, host: str) -> Tuple[bool, Optional[str], Optional[str], List[str]]:
        """Detect Internationalized Domain Name (IDN) and Unicode homograph/confusable attacks.

        Returns:
            (is_homograph, punycode_domain, unicode_domain, homoglyph_details)
        """
        if not host:
            return False, None, None, []

        is_homograph = False
        punycode_domain: Optional[str] = None
        unicode_domain: Optional[str] = None
        details: List[str] = []

        # 1. Check Punycode (starts with xn--)
        if "xn--" in host.lower():
            try:
                unicode_domain = host.encode("ascii").decode("idna")
                punycode_domain = host
                is_homograph = True
                details.append(
                    f"Punycode encoded domain: '{host}' resolves to Unicode: '{unicode_domain}'"
                )
            except Exception:
                pass

        # 2. Check raw Unicode characters in domain
        if not unicode_domain:
            unicode_domain = host

        # Scan for mixed scripts (e.g., Cyrillic/Greek in Latin domain)
        scripts_found: Set[str] = set()
        suspicious_chars: List[Tuple[str, str, str]] = []  # (char, script, codepoint)

        for char in unicode_domain:
            if char in ".-_":
                continue
            try:
                char_name = unicodedata.name(char)
            except ValueError:
                continue

            script = "LATIN"
            if "CYRILLIC" in char_name:
                script = "CYRILLIC"
            elif "GREEK" in char_name:
                script = "GREEK"
            elif "ARABIC" in char_name:
                script = "ARABIC"
            elif "HEBREW" in char_name:
                script = "HEBREW"
            elif "HIRAGANA" in char_name or "KATAKANA" in char_name or "CJK" in char_name:
                script = "CJK"

            scripts_found.add(script)
            if script != "LATIN":
                suspicious_chars.append((char, script, f"U+{ord(char):04X} ({char_name})"))

        if len(scripts_found) > 1 and "LATIN" in scripts_found:
            is_homograph = True
            try:
                punycode_domain = unicode_domain.encode("idna").decode("ascii")
            except Exception:
                pass

            for char, script, code in suspicious_chars[:5]:
                details.append(
                    f"Homoglyph character '{char}' [{script}] {code} mixed with Latin script"
                )

        return is_homograph, punycode_domain, unicode_domain, details

    @staticmethod
    def detect_ip_host(host: str) -> Tuple[bool, Optional[str]]:
        """Check if a URL host is represented as an IPv4/IPv6 address (standard, hex, or dword)."""
        if not host:
            return False, None

        # Clean brackets from IPv6
        clean_host = host.strip("[]")

        # Standard IPv4 or IPv6
        try:
            ip = ipaddress.ip_address(clean_host)
            return True, f"Standard IP: {ip}"
        except ValueError:
            pass

        # Hex / Dword representation (e.g., 0x7f000001 or 2130706433)
        if clean_host.isdigit():
            try:
                dword_val = int(clean_host)
                if 0 <= dword_val <= 4294967295:
                    ip = ipaddress.IPv4Address(dword_val)
                    return True, f"Dword IP representation: {ip}"
            except Exception:
                pass

        if clean_host.lower().startswith("0x"):
            try:
                hex_val = int(clean_host, 16)
                if 0 <= hex_val <= 4294967295:
                    ip = ipaddress.IPv4Address(hex_val)
                    return True, f"Hex IP representation: {ip}"
            except Exception:
                pass

        return False, None

    def detect_shorteners(self, host: str) -> bool:
        """Check if the domain is a known URL shortening service."""
        if not host:
            return False
        extracted = self.tld_extractor(host)
        reg_domain = self._get_registered_domain(extracted)
        return reg_domain in URL_SHORTENER_DOMAINS or host.lower() in URL_SHORTENER_DOMAINS

    def detect_suspicious_tld(self, host: str) -> bool:
        """Check if the top-level domain is on the high-abuse / phishing list."""
        if not host:
            return False
        extracted = self.tld_extractor(host)
        suffix = extracted.suffix.lower()
        return suffix in SUSPICIOUS_TLDS

    @staticmethod
    def _has_base64_email(query_str: str) -> bool:
        """Check if a query string contains a base64-encoded email address."""
        # Look for potential base64 segments
        b64_pattern = re.compile(r"[A-Za-z0-9+/=]{8,}")
        matches = b64_pattern.findall(query_str)
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                if (
                    "@" in decoded
                    and "." in decoded
                    and re.search(r"[\w.-]+@[\w.-]+\.\w+", decoded)
                ):
                    return True
            except Exception:
                continue
        return False

    @staticmethod
    def _is_ignorable_scheme(url: str) -> bool:
        """Filter out non-hyperlink schemes like tel:, javascript:, mailto:, data:."""
        lower = url.lower().strip()
        return lower.startswith(("mailto:", "tel:", "javascript:", "data:", "cid:", "#"))

    @staticmethod
    def _clean_regex_url(url: str) -> str:
        """Trim trailing punctuation often captured by regex at sentence boundaries."""
        cleaned = url.rstrip(".,;:)'\"!?]>")
        return cleaned
