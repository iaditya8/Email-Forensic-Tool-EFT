"""Content Obfuscation, Hidden Text, and Decoded Blob Analysis Engine.

Scans HTML DOM structures and plaintext content for CSS text-hiding techniques,
zero-width Unicode bypasses, embedded Base64/Hex/URL-encoded data blobs, and
inspects decoded payloads for malware commands and LLM prompt injection triggers.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import html
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set

from bs4 import BeautifulSoup, Comment

from eft.models.canonical import (
    CanonicalEmail,
    ContentObfuscationReport,
    DecodedBlobArtifact,
    HiddenContentArtifact,
)

# Zero-width & invisible Unicode codepoint characters
ZERO_WIDTH_CHARS: Dict[str, str] = {
    "\u200b": "Zero-Width Space (U+200B)",
    "\u200c": "Zero-Width Non-Joiner (U+200C)",
    "\u200d": "Zero-Width Joiner (U+200D)",
    "\ufeff": "Zero-Width No-Break Space / BOM (U+FEFF)",
    "\u200e": "Left-to-Right Mark (U+200E)",
    "\u200f": "Right-to-Left Mark (U+200F)",
    "\u202a": "Left-to-Right Embedding (U+202A)",
    "\u202b": "Right-to-Left Embedding (U+202B)",
    "\u202c": "Pop Directional Formatting (U+202C)",
    "\u202d": "Left-to-Right Override (U+202D)",
    "\u202e": "Right-to-Left Override (U+202E)",
}

# Regex patterns for detecting LLM prompt injection attempts
PROMPT_INJECTION_PATTERNS: List[str] = [
    r"(?i)\bignore\s+(?:all\s+)?previous\s+instructions\b",
    r"(?i)\bdisregard\s+(?:all\s+)?prior\s+(?:instructions|prompts)\b",
    r"(?i)\bsystem\s+prompt\s*:\s*",
    r"(?i)\byou\s+are\s+now\s+(?:an?|in|a\s+helpful)\s+(?:DAN|jailbreak|unrestricted)\b",
    r"(?i)\boverride\s+(?:all\s+)?(?:system|developer)\s+instructions\b",
    r"(?i)\bdo\s+not\s+follow\s+earlier\s+rules\b",
    r"(?i)\bprint\s+(?:your\s+)?initial\s+prompt\b",
]

# Regex patterns for script & shell payload commands
SCRIPT_PAYLOAD_PATTERNS: Dict[str, str] = {
    "POWERSHELL_CMD": r"(?i)\bpowershell(?:\.exe)?\s+-[a-zA-Z]",
    "POWERSHELL_IEX": r"(?i)\b(?:iex|invoke-expression)\s*\(",
    "POWERSHELL_DOWNLOAD": r"(?i)\bdownloadstring\s*\(",
    "CMD_EXEC": r"(?i)\bcmd(?:\.exe)?\s+/c\b",
    "CERTUTIL_DOWNLOAD": r"(?i)\bcertutil(?:\.exe)?\s+-urlcache\b",
    "BITSADMIN_DOWNLOAD": r"(?i)\bbitsadmin(?:\.exe)?\s+/transfer\b",
    "JAVASCRIPT_EVAL": r"(?i)\beval\s*\(",
    "JAVASCRIPT_SCRIPT_TAG": r"(?i)<\s*script[^>]*>",
    "DOCUMENT_LOCATION_REDIRECT": r"(?i)\b(?:document|window)\.location\b",
    "EXECUTABLE_HEADER": r"(?i)^MZ[\x00-\xff]{2,}",
}

# General URL extraction regex
URL_REGEX = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"')]+", re.IGNORECASE)


class ContentObfuscationDetector:
    """Forensic analyzer for detecting hidden text, zero-width characters, and decoded obfuscated blobs."""

    def detect(self, email: CanonicalEmail) -> ContentObfuscationReport:
        """Run comprehensive obfuscation, hidden text, and decoded blob forensics.

        Args:
            email: CanonicalEmail evidence model.

        Returns:
            A populated ContentObfuscationReport.
        """
        hidden_artifacts: List[HiddenContentArtifact] = []
        decoded_blobs: List[DecodedBlobArtifact] = []
        flags: List[str] = []

        # 1. Inspect HTML DOM for CSS hidden text and comments
        if email.body_html:
            html_hidden = self._scan_html_hidden_text(email.body_html)
            hidden_artifacts.extend(html_hidden)

        # 2. Inspect for Zero-Width Unicode Characters (HTML + Plaintext)
        all_text = f"{email.body_html or ''}\n{email.body_plain or ''}"
        zw_artifacts = self._scan_zero_width_unicode(all_text)
        hidden_artifacts.extend(zw_artifacts)

        # 3. Extract and decode obfuscated blobs (Base64, Hex, URL-encoded, HTML entities)
        blobs = self._scan_encoded_blobs(email.body_html, email.body_plain)
        decoded_blobs.extend(blobs)

        # 4. Check for prompt injection in hidden text
        has_prompt_injection = False
        has_script_payload = False

        for h_art in hidden_artifacts:
            for pat in PROMPT_INJECTION_PATTERNS:
                if re.search(pat, h_art.hidden_text):
                    has_prompt_injection = True
                    if "PROMPT_INJECTION_TRIGGER" not in flags:
                        flags.append("PROMPT_INJECTION_TRIGGER")
                    break

        for blob in decoded_blobs:
            for ind in blob.suspicious_indicators:
                if "PROMPT_INJECTION" in ind:
                    has_prompt_injection = True
                if any(
                    k in ind for k in ["POWERSHELL", "CMD", "SCRIPT", "JAVASCRIPT", "EXECUTABLE"]
                ):
                    has_script_payload = True
                if ind not in flags:
                    flags.append(ind)

        # Calculate metrics
        total_hidden_chars = sum(h.character_count for h in hidden_artifacts)
        has_zw = any(h.technique == "ZERO_WIDTH_UNICODE" for h in hidden_artifacts)

        if has_zw and "ZERO_WIDTH_CHARACTERS_DETECTED" not in flags:
            flags.append("ZERO_WIDTH_CHARACTERS_DETECTED")

        if any(h.technique.startswith("CSS_") for h in hidden_artifacts):
            if "CSS_HIDDEN_TEXT_DETECTED" not in flags:
                flags.append("CSS_HIDDEN_TEXT_DETECTED")

        if decoded_blobs and "OBFUSCATED_BLOBS_DECODED" not in flags:
            flags.append("OBFUSCATED_BLOBS_DECODED")

        # Threat score calculation
        score = 0.0
        if has_prompt_injection:
            score += 50.0
        if has_script_payload:
            score += 50.0
        if has_zw:
            score += 30.0
        if total_hidden_chars >= 50:
            score += 30.0
        elif total_hidden_chars > 0:
            score += 15.0

        for blob in decoded_blobs:
            if blob.suspicious_indicators:
                score += 25.0
            elif blob.extracted_urls:
                score += 15.0
            else:
                score += 10.0

        risk_score = min(score, 100.0)

        # Determine overall obfuscation verdict
        if risk_score >= 60.0 or has_prompt_injection or has_script_payload:
            overall_risk = "HIGH_RISK_OBFUSCATION"
        elif risk_score >= 20.0 or total_hidden_chars > 0 or has_zw or len(decoded_blobs) > 0:
            overall_risk = "SUSPICIOUS"
        else:
            overall_risk = "CLEAN"

        report = ContentObfuscationReport(
            total_hidden_artifacts=len(hidden_artifacts),
            total_decoded_blobs=len(decoded_blobs),
            hidden_text_char_count=total_hidden_chars,
            has_zero_width_chars=has_zw,
            has_prompt_injection=has_prompt_injection,
            has_script_payload=has_script_payload,
            overall_obfuscation_risk=overall_risk,
            risk_score=risk_score,
            hidden_artifacts=hidden_artifacts,
            decoded_blobs=decoded_blobs,
            flags=flags,
        )

        email.obfuscation_report = report
        return report

    @staticmethod
    def _get_str_attr(tag: Any, attr_name: str) -> str:
        """Safely extract a string attribute from a BeautifulSoup element."""
        val = tag.get(attr_name, "")
        if isinstance(val, list):
            return " ".join(val).strip()
        if isinstance(val, str):
            return val.strip()
        return ""

    def _scan_html_hidden_text(self, html_content: str) -> List[HiddenContentArtifact]:
        """Parse HTML DOM to detect text hidden via CSS styles or HTML attributes."""
        artifacts: List[HiddenContentArtifact] = []
        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception:
            return artifacts

        # 1. HTML Comments with significant text content
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment_text = str(comment).strip()
            if len(comment_text) >= 15 and not comment_text.startswith(("[if ", "<![endif")):
                artifacts.append(
                    HiddenContentArtifact(
                        technique="HTML_COMMENT_PAYLOAD",
                        hidden_text=comment_text,
                        element_tag="comment",
                        raw_style_or_attribute="<!-- comment -->",
                        character_count=len(comment_text),
                        snippet=comment_text[:80],
                    )
                )

        # 2. HTML elements with hidden attributes
        for el in soup.find_all(lambda tag: tag.has_attr("hidden")):
            text = el.get_text(strip=True)
            if text:
                artifacts.append(
                    HiddenContentArtifact(
                        technique="HTML_HIDDEN_ATTRIBUTE",
                        hidden_text=text,
                        element_tag=str(el.name),
                        raw_style_or_attribute="hidden",
                        character_count=len(text),
                        snippet=text[:80],
                    )
                )

        # 3. HTML elements with inline styles hiding text
        for el in soup.find_all(style=True):
            raw_style = self._get_str_attr(el, "style")
            style_str = raw_style.lower()
            text = el.get_text(strip=True)
            if not text:
                continue

            technique = None

            if re.search(r"\bdisplay\s*:\s*none\b", style_str):
                technique = "CSS_DISPLAY_NONE"
            elif re.search(r"\bvisibility\s*:\s*hidden\b", style_str):
                technique = "CSS_VISIBILITY_HIDDEN"
            elif re.search(r"\bfont-size\s*:\s*0(?:px|pt|em|rem|%)?\b", style_str):
                technique = "CSS_ZERO_FONT_SIZE"
            elif re.search(r"\bcolor\s*:\s*transparent\b", style_str) or re.search(
                r"\bcolor\s*:\s*rgba\([^)]*,\s*0(?:\.0+)?\)", style_str
            ):
                technique = "CSS_TRANSPARENT_COLOR"
            elif re.search(r"\bopacity\s*:\s*0(?:\.0+)?\b", style_str):
                technique = "CSS_ZERO_OPACITY"
            elif re.search(
                r"\b(?:left|top|text-indent|margin-left)\s*:\s*-\d{3,}(?:px)?\b", style_str
            ):
                technique = "CSS_OFF_SCREEN_POSITION"
            elif re.search(r"\bmax-height\s*:\s*0(?:px)?\s*;\s*overflow\s*:\s*hidden\b", style_str):
                technique = "CSS_ZERO_HEIGHT_OVERFLOW"
            elif self._is_same_color_background(style_str):
                technique = "CSS_SAME_COLOR_BG"

            if technique:
                artifacts.append(
                    HiddenContentArtifact(
                        technique=technique,
                        hidden_text=text,
                        element_tag=str(el.name),
                        raw_style_or_attribute=raw_style,
                        character_count=len(text),
                        snippet=text[:80],
                    )
                )

        return artifacts

    def _scan_zero_width_unicode(self, text: str) -> List[HiddenContentArtifact]:
        """Detect zero-width spaces and invisible directional override Unicode characters."""
        artifacts: List[HiddenContentArtifact] = []
        if not text:
            return artifacts

        found_counts: Dict[str, int] = {}
        for char, name in ZERO_WIDTH_CHARS.items():
            count = text.count(char)
            if count > 0:
                found_counts[name] = count

        if found_counts:
            total_chars = sum(found_counts.values())
            summary = ", ".join(f"{name}: {cnt}" for name, cnt in found_counts.items())
            artifacts.append(
                HiddenContentArtifact(
                    technique="ZERO_WIDTH_UNICODE",
                    hidden_text=f"Invisible Unicode characters embedded in message: {summary}",
                    element_tag="unicode",
                    raw_style_or_attribute=f"Total count: {total_chars}",
                    character_count=total_chars,
                    snippet=summary,
                )
            )

        return artifacts

    def _scan_encoded_blobs(
        self,
        html_content: Optional[str],
        plain_content: Optional[str],
    ) -> List[DecodedBlobArtifact]:
        """Extract and safely decode Base64, Hex, and URL-encoded data blobs in-memory."""
        blobs: List[DecodedBlobArtifact] = []
        seen_blobs: Set[str] = set()

        combined_text = f"{html_content or ''}\n{plain_content or ''}"

        # 1. Base64 Blobs (e.g. data:text/html;base64,... or raw base64 blocks >= 20 chars)
        b64_pattern = re.compile(r"(?:data:[^;]+;base64,)?([A-Za-z0-9+/=]{24,})")
        for match in b64_pattern.finditer(combined_text):
            raw_candidate = match.group(1)
            if raw_candidate in seen_blobs:
                continue
            seen_blobs.add(raw_candidate)

            decoded_bytes = self._try_base64_decode(raw_candidate)
            if decoded_bytes and len(decoded_bytes) >= 8:
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore").strip()
                # Check if decoded string is readable text
                if self._is_mostly_printable(decoded_str) and len(decoded_str) >= 8:
                    sha256_hash = hashlib.sha256(decoded_bytes).hexdigest()
                    urls = URL_REGEX.findall(decoded_str)
                    indicators = self._inspect_decoded_payload(decoded_str)

                    blobs.append(
                        DecodedBlobArtifact(
                            encoding_type="BASE64",
                            raw_blob=raw_candidate[:100]
                            + ("..." if len(raw_candidate) > 100 else ""),
                            decoded_text=decoded_str,
                            decoded_bytes_sha256=sha256_hash,
                            source_location="body_content",
                            extracted_urls=urls,
                            suspicious_indicators=indicators,
                        )
                    )

        # 2. Hex Escaped Strings (e.g., \x41\x42\x43 or 0x41, 0x42...)
        hex_esc_pattern = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
        for match in hex_esc_pattern.finditer(combined_text):
            raw_candidate = match.group(0)
            if raw_candidate in seen_blobs:
                continue
            seen_blobs.add(raw_candidate)

            hex_clean = raw_candidate.replace("\\x", "")
            try:
                decoded_bytes = bytes.fromhex(hex_clean)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore").strip()
                if self._is_mostly_printable(decoded_str):
                    sha256_hash = hashlib.sha256(decoded_bytes).hexdigest()
                    urls = URL_REGEX.findall(decoded_str)
                    indicators = self._inspect_decoded_payload(decoded_str)

                    blobs.append(
                        DecodedBlobArtifact(
                            encoding_type="HEX",
                            raw_blob=raw_candidate[:100],
                            decoded_text=decoded_str,
                            decoded_bytes_sha256=sha256_hash,
                            source_location="body_content",
                            extracted_urls=urls,
                            suspicious_indicators=indicators,
                        )
                    )
            except Exception:
                pass

        # 3. URL-Encoded Script/Data Blocks (e.g., %3Cscript%3E... or %20%20%3C)
        url_enc_pattern = re.compile(r"(?:%[0-9a-fA-F]{2}[a-zA-Z0-9_()./ -]*){2,}")
        for match in url_enc_pattern.finditer(combined_text):
            raw_candidate = match.group(0).strip()
            if (
                raw_candidate in seen_blobs
                or len(raw_candidate) < 8
                or raw_candidate.count("%") < 2
            ):
                continue
            seen_blobs.add(raw_candidate)

            try:
                decoded_str = urllib.parse.unquote(raw_candidate).strip()
                if self._is_mostly_printable(decoded_str) and decoded_str != raw_candidate:
                    sha256_hash = hashlib.sha256(decoded_str.encode("utf-8")).hexdigest()
                    urls = URL_REGEX.findall(decoded_str)
                    indicators = self._inspect_decoded_payload(decoded_str)

                    blobs.append(
                        DecodedBlobArtifact(
                            encoding_type="URL_ENCODED",
                            raw_blob=raw_candidate[:100],
                            decoded_text=decoded_str,
                            decoded_bytes_sha256=sha256_hash,
                            source_location="body_content",
                            extracted_urls=urls,
                            suspicious_indicators=indicators,
                        )
                    )
            except Exception:
                pass

        # 4. HTML Entity-Encoded Script Blocks (e.g., &#x61;&#x6c;&#x65;&#x72;&#x74;)
        html_entity_pattern = re.compile(r"(?:&#[xX]?[0-9a-fA-F]+;){4,}")
        for match in html_entity_pattern.finditer(combined_text):
            raw_candidate = match.group(0)
            if raw_candidate in seen_blobs:
                continue
            seen_blobs.add(raw_candidate)

            decoded_str = html.unescape(raw_candidate).strip()
            if self._is_mostly_printable(decoded_str) and decoded_str != raw_candidate:
                sha256_hash = hashlib.sha256(decoded_str.encode("utf-8")).hexdigest()
                urls = URL_REGEX.findall(decoded_str)
                indicators = self._inspect_decoded_payload(decoded_str)

                blobs.append(
                    DecodedBlobArtifact(
                        encoding_type="HTML_ENTITIES",
                        raw_blob=raw_candidate[:100],
                        decoded_text=decoded_str,
                        decoded_bytes_sha256=sha256_hash,
                        source_location="body_content",
                        extracted_urls=urls,
                        suspicious_indicators=indicators,
                    )
                )

        return blobs

    def _inspect_decoded_payload(self, text: str) -> List[str]:
        """Analyze decoded text for script payloads, commands, and prompt injection attempts."""
        indicators: List[str] = []

        # Check prompt injection
        for pat in PROMPT_INJECTION_PATTERNS:
            if re.search(pat, text):
                indicators.append("PROMPT_INJECTION_TRIGGER")
                break

        # Check script / command patterns
        for ind_name, pat in SCRIPT_PAYLOAD_PATTERNS.items():
            if re.search(pat, text):
                indicators.append(ind_name)

        return indicators

    @staticmethod
    def _is_same_color_background(style_str: str) -> bool:
        """Check if text color matches background color (e.g. white on white text)."""
        color_match = re.search(r"\bcolor\s*:\s*([^;]+)", style_str)
        bg_match = re.search(r"\bbackground(?:-color)?\s*:\s*([^;]+)", style_str)

        if color_match and bg_match:
            c = color_match.group(1).strip().lower().replace(" ", "")
            bg = bg_match.group(1).strip().lower().replace(" ", "")

            # Normalize white representations
            whites = {"#fff", "#ffffff", "white", "rgb(255,255,255)", "rgba(255,255,255,1)"}
            if c in whites and bg in whites:
                return True

            # Normalize black representations
            blacks = {"#000", "#000000", "black", "rgb(0,0,0)", "rgba(0,0,0,1)"}
            if c in blacks and bg in blacks:
                return True

            if c == bg:
                return True

        return False

    @staticmethod
    def _try_base64_decode(candidate: str) -> Optional[bytes]:
        """Safely attempt to decode a base64 string with padding adjustment."""
        clean = candidate.strip()
        # Add padding if needed
        missing_padding = len(clean) % 4
        if missing_padding:
            clean += "=" * (4 - missing_padding)

        try:
            decoded = base64.b64decode(clean, validate=True)
            return decoded
        except (binascii.Error, ValueError):
            return None

    @staticmethod
    def _is_mostly_printable(s: str) -> bool:
        """Determine if a decoded string consists predominantly of printable characters."""
        if not s:
            return False
        printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
        return (printable / len(s)) >= 0.85
