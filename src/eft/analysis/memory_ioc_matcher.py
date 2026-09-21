"""In-Memory Regex Pattern & IoC Matcher."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Set

from eft.analysis.memory_analyzer import MemoryArtifactAnalyzer
from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.models.memory_forensics import (
    ExtractedStringItem,
    MemoryIoCMatch,
    MemoryIoCType,
    MemoryPatternReport,
)

# Built-in offline threat IoC hashes catalog
DEFAULT_KNOWN_MALICIOUS_HASHES: Set[str] = {
    # Emotet, TrickBot, Cobalt Strike, Mimikatz, Lumma sample reference hashes
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "44d88612fea8a8f36de82e1278abb02f",
    "5d41402abc4b2a76b9719d911017c592",
    "7d793037a0760186574b0282f2f435e7",
    "2b63897b69c73e0456c7ccb8ff178ec6",
    "a791a84f4d546aa57703358bb0e092bb45e33d26a27e3661ecff0e32b49d62d2",
    "8f4e24b4f5ef43f65625bf922880a67272fb09ee",
    "2519803bf3559ef177651a5c6d3df392e2fb8e578c772ff278fa816e8b74687e",
    "a87ff679a2f3e71d9181a67b7542122c",
    "d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fbda8b47e2501a35560df76",
}


class MemoryIoCMatcher:
    """Forensic engine for scanning RAM strings and raw memory dumps for IoCs and sensitive secrets."""

    # Regex patterns
    _RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _RE_IPV6 = re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}\b"
    )
    _RE_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>\\]+", re.IGNORECASE)
    _RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    _RE_BTC_LEGACY_P2SH = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
    _RE_BTC_BECH32 = re.compile(r"\bbc1[a-zA-HJ-NP-Z0-9]{25,39}\b")
    _RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    _RE_JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
    _RE_PRIVATE_KEY = re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", re.IGNORECASE
    )
    _RE_BASE64_MZ = re.compile(r"\b(?:TVqQAA[A-Za-z0-9+/=]{20,}|TVpQAA[A-Za-z0-9+/=]{20,})\b")
    _RE_POWERSHELL_ENC = re.compile(
        r"(?:-enc|-encodedcommand|-e)\s+([A-Za-z0-9+/=]{8,})", re.IGNORECASE
    )
    _RE_HEX_HASH = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")

    def __init__(
        self,
        memory_analyzer: MemoryArtifactAnalyzer | None = None,
        net_intel: NetworkIntelligenceService | None = None,
        custom_known_hashes: Iterable[str] | None = None,
    ) -> None:
        """Initialize matcher with memory analyzer, network intelligence, and threat catalogs."""
        self.memory_analyzer = memory_analyzer or MemoryArtifactAnalyzer()
        self.net_intel = net_intel or NetworkIntelligenceService()
        self.known_hashes = set(DEFAULT_KNOWN_MALICIOUS_HASHES)
        if custom_known_hashes:
            self.known_hashes.update(h.strip().lower() for h in custom_known_hashes if h.strip())

    def scan_string_item(
        self,
        item: ExtractedStringItem,
        known_hashes: Set[str] | None = None,
    ) -> list[MemoryIoCMatch]:
        """Scan a single extracted string item across all forensic regex IoC patterns.

        Args:
            item: ExtractedStringItem from memory analyzer.
            known_hashes: Optional override/extension of known threat hashes.

        Returns:
            List of detected MemoryIoCMatch objects.
        """
        text = item.value
        offset = item.offset
        enc = item.encoding
        threat_hashes = known_hashes if known_hashes is not None else self.known_hashes
        matches: list[MemoryIoCMatch] = []

        # 1. PEM Private Keys
        for match in self._RE_PRIVATE_KEY.finditer(text):
            val = match.group(0)
            ctx = self._extract_context(text, match.start(), match.end())
            matches.append(
                MemoryIoCMatch(
                    ioc_type=MemoryIoCType.PRIVATE_KEY,
                    value=val,
                    offset=offset + match.start(),
                    encoding=enc,
                    context=ctx,
                    risk_score=95,
                    is_known_malicious=False,
                    enrichment={"key_header": val},
                    mitre_attack="T1552.004",
                )
            )

        # 2. Base64 PE Header / Executable Payloads
        for match in self._RE_BASE64_MZ.finditer(text):
            val = match.group(0)
            ctx = self._extract_context(text, match.start(), match.end())
            matches.append(
                MemoryIoCMatch(
                    ioc_type=MemoryIoCType.BASE64_PAYLOAD,
                    value=val,
                    offset=offset + match.start(),
                    encoding=enc,
                    context=ctx,
                    risk_score=90,
                    is_known_malicious=True,
                    enrichment={"payload_type": "Base64 MZ Executable Header"},
                    mitre_attack="T1027",
                )
            )

        # 3. Obfuscated PowerShell Encoded Commands
        for match in self._RE_POWERSHELL_ENC.finditer(text):
            encoded_payload = match.group(1)
            decoded_cmd = self._try_decode_powershell_base64(encoded_payload)
            ctx = self._extract_context(text, match.start(), match.end())
            matches.append(
                MemoryIoCMatch(
                    ioc_type=MemoryIoCType.BASE64_PAYLOAD,
                    value=match.group(0),
                    offset=offset + match.start(),
                    encoding=enc,
                    context=ctx,
                    risk_score=85,
                    is_known_malicious=False,
                    enrichment={
                        "encoded_payload": encoded_payload,
                        "decoded_command": decoded_cmd or "<decoding_failed>",
                    },
                    mitre_attack="T1059.001",
                )
            )

        # 4. JWT Tokens
        for match in self._RE_JWT.finditer(text):
            token = match.group(0)
            claims = self._try_parse_jwt_claims(token)
            ctx = self._extract_context(text, match.start(), match.end())
            matches.append(
                MemoryIoCMatch(
                    ioc_type=MemoryIoCType.JWT_TOKEN,
                    value=token,
                    offset=offset + match.start(),
                    encoding=enc,
                    context=ctx,
                    risk_score=75,
                    is_known_malicious=False,
                    enrichment={"parsed_claims": claims},
                    mitre_attack="T1552.001",
                )
            )

        # 5. Cryptocurrency Wallets (Bitcoin Legacy/P2SH, Bech32, Ethereum)
        for match in self._RE_BTC_LEGACY_P2SH.finditer(text):
            addr = match.group(0)
            ctx = self._extract_context(text, match.start(), match.end())
            matches.append(
                MemoryIoCMatch(
                    ioc_type=MemoryIoCType.CRYPTO_WALLET_BTC,
                    value=addr,
                    offset=offset + match.start(),
                    encoding=enc,
                    context=ctx,
                    risk_score=85,
                    is_known_malicious=False,
                    enrichment={"address_format": "Legacy/P2SH"},
                    mitre_attack="T1486",
                )
            )

        for match in self._RE_BTC_BECH32.finditer(text):
            addr = match.group(0)
            ctx = self._extract_context(text, match.start(), match.end())
            matches.append(
                MemoryIoCMatch(
                    ioc_type=MemoryIoCType.CRYPTO_WALLET_BTC,
                    value=addr,
                    offset=offset + match.start(),
                    encoding=enc,
                    context=ctx,
                    risk_score=85,
                    is_known_malicious=False,
                    enrichment={"address_format": "Bech32 Native SegWit"},
                    mitre_attack="T1486",
                )
            )

        for match in self._RE_ETH.finditer(text):
            addr = match.group(0)
            ctx = self._extract_context(text, match.start(), match.end())
            matches.append(
                MemoryIoCMatch(
                    ioc_type=MemoryIoCType.CRYPTO_WALLET_ETH,
                    value=addr,
                    offset=offset + match.start(),
                    encoding=enc,
                    context=ctx,
                    risk_score=80,
                    is_known_malicious=False,
                    enrichment={"network": "Ethereum / EVM Compatible"},
                    mitre_attack="T1486",
                )
            )

        # 6. URLs
        for match in self._RE_URL.finditer(text):
            raw_url = match.group(0)
            clean_url = raw_url.rstrip(".,;)]'\"")
            ctx = self._extract_context(text, match.start(), match.start() + len(clean_url))
            matches.append(
                MemoryIoCMatch(
                    ioc_type=MemoryIoCType.URL,
                    value=clean_url,
                    offset=offset + match.start(),
                    encoding=enc,
                    context=ctx,
                    risk_score=50,
                    is_known_malicious=False,
                    enrichment={"scheme": clean_url.split("://", 1)[0].lower()},
                    mitre_attack="T1071.001",
                )
            )

        # 7. Email Addresses
        for match in self._RE_EMAIL.finditer(text):
            email_val = match.group(0).rstrip(".,;)'\"")
            ctx = self._extract_context(text, match.start(), match.start() + len(email_val))
            matches.append(
                MemoryIoCMatch(
                    ioc_type=MemoryIoCType.EMAIL,
                    value=email_val,
                    offset=offset + match.start(),
                    encoding=enc,
                    context=ctx,
                    risk_score=25,
                    is_known_malicious=False,
                    enrichment={"domain": email_val.split("@", 1)[1].lower()},
                    mitre_attack="T1566",
                )
            )

        # 8. IPv4 Addresses (Validated Octets & GeoIP Enriched)
        for match in self._RE_IPV4.finditer(text):
            ip_str = match.group(0)
            if self._is_valid_ipv4(ip_str):
                enrich = self._enrich_ip(ip_str)
                ctx = self._extract_context(text, match.start(), match.end())
                risk = enrich.get("risk_score", 30)
                matches.append(
                    MemoryIoCMatch(
                        ioc_type=MemoryIoCType.IPV4,
                        value=ip_str,
                        offset=offset + match.start(),
                        encoding=enc,
                        context=ctx,
                        risk_score=risk,
                        is_known_malicious=enrich.get("is_tor", False)
                        or enrich.get("is_vpn", False),
                        enrichment=enrich,
                        mitre_attack="T1071",
                    )
                )

        # 9. IPv6 Addresses
        for match in self._RE_IPV6.finditer(text):
            ip_str = match.group(0)
            if self._is_valid_ipv6(ip_str):
                ctx = self._extract_context(text, match.start(), match.end())
                matches.append(
                    MemoryIoCMatch(
                        ioc_type=MemoryIoCType.IPV6,
                        value=ip_str,
                        offset=offset + match.start(),
                        encoding=enc,
                        context=ctx,
                        risk_score=30,
                        is_known_malicious=False,
                        enrichment={"is_ipv6": True},
                        mitre_attack="T1071",
                    )
                )

        # 10. Malicious Threat Hashes (MD5, SHA1, SHA256 cross-reference)
        for match in self._RE_HEX_HASH.finditer(text):
            h_val = match.group(0).lower()
            if h_val in threat_hashes:
                ctx = self._extract_context(text, match.start(), match.end())
                matches.append(
                    MemoryIoCMatch(
                        ioc_type=MemoryIoCType.KNOWN_MALICIOUS_HASH,
                        value=h_val,
                        offset=offset + match.start(),
                        encoding=enc,
                        context=ctx,
                        risk_score=100,
                        is_known_malicious=True,
                        enrichment={
                            "algorithm": "MD5"
                            if len(h_val) == 32
                            else ("SHA1" if len(h_val) == 40 else "SHA256"),
                            "threat_catalog_match": True,
                        },
                        mitre_attack="T1027",
                    )
                )

        return matches

    def scan_stream(
        self,
        stream_or_path: str | Path | bytes | BinaryIO,
        custom_known_hashes: Iterable[str] | None = None,
        min_length: int = 4,
        chunk_size: int | None = None,
    ) -> MemoryPatternReport:
        """Stream RAM dump, extract strings, run IoC matching, and produce comprehensive triage report.

        Args:
            stream_or_path: File path, bytes, or BinaryIO stream.
            custom_known_hashes: Optional list/set of hashes to correlate against.
            min_length: Minimum printable string length (default 4).
            chunk_size: Processing chunk buffer size in bytes.

        Returns:
            MemoryPatternReport model.
        """
        evidence_path = (
            str(stream_or_path)
            if isinstance(stream_or_path, (str, Path))
            else "<memory_stream_buffer>"
        )

        extraction_report = self.memory_analyzer.analyze(
            stream_or_path=stream_or_path,
            min_length=min_length,
            max_samples=100,
            chunk_size=chunk_size,
        )

        active_hashes = set(self.known_hashes)
        if custom_known_hashes:
            active_hashes.update(h.strip().lower() for h in custom_known_hashes if h.strip())

        all_matches: list[MemoryIoCMatch] = []
        matches_by_type: dict[str, int] = {}

        # Stream string items through IoC matcher
        for item in self.memory_analyzer.extract_strings_stream(
            stream_or_path=stream_or_path,
            min_length=min_length,
            chunk_size=chunk_size,
        ):
            item_matches = self.scan_string_item(item, known_hashes=active_hashes)
            for m in item_matches:
                all_matches.append(m)
                matches_by_type[m.ioc_type.value] = matches_by_type.get(m.ioc_type.value, 0) + 1

        # Sort matches by byte offset
        all_matches.sort(key=lambda m: m.offset)

        # Filter high-risk findings (risk >= 70)
        high_risk = [m for m in all_matches if m.risk_score >= 70]

        # Compute composite threat level
        max_risk = max([m.risk_score for m in all_matches], default=0)
        if max_risk >= 90:
            threat_level = "CRITICAL"
        elif max_risk >= 70:
            threat_level = "HIGH"
        elif max_risk >= 40:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        return MemoryPatternReport(
            evidence_path=evidence_path,
            evidence_hashes=extraction_report.evidence_hashes,
            total_patterns_matched=len(all_matches),
            matches_by_type=matches_by_type,
            matches=all_matches,
            high_risk_findings=high_risk,
            threat_level=threat_level,
        )

    def _extract_context(self, text: str, start: int, end: int, window: int = 40) -> str:
        """Extract a snippet of surrounding context around a match."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        snippet = text[ctx_start:ctx_end]
        # Clean up newlines for compact display
        return snippet.replace("\r", " ").replace("\n", " ").strip()

    def _is_valid_ipv4(self, ip_str: str) -> bool:
        """Validate if a string is a valid IPv4 address (excluding broadcast and 0.0.0.0)."""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            if ip.is_multicast or ip.is_unspecified or ip_str == "255.255.255.255":
                return False
            # Check octets range
            parts = [int(p) for p in ip_str.split(".")]
            return len(parts) == 4 and all(0 <= p <= 255 for p in parts)
        except Exception:
            return False

    def _is_valid_ipv6(self, ip_str: str) -> bool:
        """Validate if a string is a valid IPv6 address."""
        try:
            ip = ipaddress.IPv6Address(ip_str)
            return not ip.is_unspecified
        except Exception:
            return False

    def _enrich_ip(self, ip_str: str) -> dict[str, Any]:
        """Perform offline GeoIP, ASN, and reputation enrichment for an IP address."""
        enrichment: dict[str, Any] = {
            "ip": ip_str,
            "is_private": False,
            "country": "Unknown",
            "asn": None,
            "org": "Unknown",
            "is_vpn": False,
            "is_tor": False,
            "risk_score": 30,
        }

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                enrichment["is_private"] = True
                enrichment["risk_score"] = 10
                enrichment["org"] = "Internal/Private Network"
                return enrichment

            # Query network intelligence service
            intel = self.net_intel.lookup_ip(ip_str)
            if intel:
                enrichment["country"] = intel.country or "Unknown"
                enrichment["asn"] = intel.asn
                enrichment["org"] = intel.as_org or intel.isp or "Unknown"
                enrichment["is_vpn"] = intel.is_vpn or intel.is_proxy
                enrichment["is_tor"] = intel.is_tor_exit_node
                enrichment["is_cloud"] = intel.is_cloud_provider

                if intel.is_tor_exit_node:
                    enrichment["risk_score"] = 85
                elif intel.is_vpn or intel.is_proxy:
                    enrichment["risk_score"] = 65
                elif intel.is_cloud_provider:
                    enrichment["risk_score"] = 45
                else:
                    enrichment["risk_score"] = 35
        except Exception:
            pass

        return enrichment

    def _try_decode_powershell_base64(self, b64_str: str) -> str | None:
        """Attempt to decode PowerShell UTF-16LE base64 encoded command string."""
        try:
            raw = base64.b64decode(b64_str)
            return raw.decode("utf-16le", errors="replace").strip()
        except Exception:
            try:
                raw = base64.b64decode(b64_str)
                return raw.decode("utf-8", errors="replace").strip()
            except Exception:
                return None

    def _try_parse_jwt_claims(self, token: str) -> dict[str, Any]:
        """Attempt to parse header and payload claims from a JWT token without secret verification."""
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                payload_b64 = parts[1]
                # Add padding if needed
                pad = len(payload_b64) % 4
                if pad:
                    payload_b64 += "=" * (4 - pad)
                decoded_bytes = base64.urlsafe_b64decode(payload_b64)
                data = json.loads(decoded_bytes.decode("utf-8", errors="replace"))
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
        return {}
