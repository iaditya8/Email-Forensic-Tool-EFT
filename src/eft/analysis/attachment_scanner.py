"""Attachment Static Analysis & YARA Rule Scanner Engine.

Provides deep static inspection of email attachments, detecting weaponized VBA macros,
malicious PDF exploit structures, embedded PE executables, dangerous scripts,
and executes built-in and custom DFIR YARA signatures with IoC hash lookup.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from eft.models.canonical import (
    AttachmentAnalysisReport,
    AttachmentThreatAnalysis,
    CanonicalEmail,
    ExtractedAttachment,
    YARAMatchArtifact,
)

# High-risk executable, script, and container file extensions
DANGEROUS_EXTENSIONS: Set[str] = {
    "exe",
    "scr",
    "vbs",
    "vbe",
    "js",
    "jse",
    "hta",
    "wsf",
    "wsh",
    "ps1",
    "psm1",
    "bat",
    "cmd",
    "pif",
    "com",
    "iso",
    "img",
    "vhd",
    "vmdk",
    "jar",
    "docm",
    "xlsm",
    "pptm",
    "dotm",
    "xltm",
    "xlam",
    "reg",
    "lnk",
    "cpl",
    "inf",
    "dll",
    "sys",
}

# Office macro-enabled extensions
MACRO_EXTENSIONS: Set[str] = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam"}

# Built-in DFIR YARA Rule Definitions (Compiled in-memory or executed via fallback engine)
BUILTIN_DFIR_RULES: List[Dict[str, Any]] = [
    {
        "rule_name": "MALICIOUS_OFFICE_VBA_MACRO",
        "severity": "CRITICAL",
        "tags": ["macro", "vba", "office"],
        "meta": {
            "description": "Detects Office documents containing VBA execution hooks and process execution API calls"
        },
        "patterns": [
            (
                r"(?i)\b(?:AutoOpen|Document_Open|Workbook_Open|Auto_Open|Document_Close)\b",
                "VBA_EXEC_HOOK",
            ),
            (
                r"(?i)\b(?:WScript\.Shell|ShellExecute|CreateObject\s*\(\s*[\"']WScript\.Shell|CallByName|URLDownloadToFile)\b",
                "PROCESS_INJECTION_API",
            ),
        ],
        "condition": "any",
    },
    {
        "rule_name": "SUSPICIOUS_WINDOWS_PE_EXECUTABLE",
        "severity": "CRITICAL",
        "tags": ["executable", "pe", "binary"],
        "meta": {
            "description": "Detects Windows Portable Executable (PE) headers or embedded binaries"
        },
        "patterns": [
            (r"^MZ", "DOS_HEADER_MAGIC"),
            (r"PE\x00\x00", "PE_SIGNATURE"),
            (
                r"(?i)\b(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread|IsDebuggerPresent)\b",
                "SUSPICIOUS_API",
            ),
        ],
        "condition": "all",
    },
    {
        "rule_name": "MALICIOUS_PDF_EXPLOIT_OBJECTS",
        "severity": "HIGH",
        "tags": ["pdf", "exploit", "javascript"],
        "meta": {
            "description": "Detects suspicious PDF action objects (JavaScript, Launch, EmbeddedFiles)"
        },
        "patterns": [
            (r"(?i)/(?:JavaScript|JS)\b", "PDF_JAVASCRIPT_STREAM"),
            (r"(?i)/Launch\b", "PDF_LAUNCH_ACTION"),
            (r"(?i)/EmbeddedFiles\b", "PDF_EMBEDDED_FILES"),
            (r"(?i)/(?:XFA|AcroForm)\b", "PDF_FORM_EXPLOIT"),
        ],
        "condition": "any",
    },
    {
        "rule_name": "DANGEROUS_SCRIPT_PAYLOAD",
        "severity": "CRITICAL",
        "tags": ["script", "powershell", "dropper"],
        "meta": {
            "description": "Detects dangerous script execution commands (PowerShell, WScript, CMD)"
        },
        "patterns": [
            (r"(?i)\bpowershell(?:\.exe)?\s+-[a-zA-Z]", "POWERSHELL_FLAG"),
            (r"(?i)\b(?:WScript\.CreateObject|ActiveXObject)\b", "ACTIVEX_OBJECT"),
            (r"(?i)\bmshta(?:\.exe)?\s+http", "MSHTA_URL_EXEC"),
            (r"(?i)\bcmd(?:\.exe)?\s+/c\b", "CMD_EXEC"),
        ],
        "condition": "any",
    },
    {
        "rule_name": "EICAR_STANDARD_AV_TEST_FILE",
        "severity": "CRITICAL",
        "tags": ["eicar", "test_file"],
        "meta": {"description": "Standard EICAR anti-virus test file signature"},
        "patterns": [
            (
                r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*",
                "EICAR_STRING",
            ),
        ],
        "condition": "any",
    },
]


class AttachmentThreatScanner:
    """Forensic static analysis engine and YARA rule scanner for email attachments."""

    def __init__(self, custom_yara_rules: Optional[List[Dict[str, Any]]] = None) -> None:
        self.rules = list(BUILTIN_DFIR_RULES)
        if custom_yara_rules:
            self.rules.extend(custom_yara_rules)

    def scan_email(
        self,
        email: CanonicalEmail,
        known_bad_hashes: Optional[Set[str]] = None,
        custom_rules: Optional[List[Dict[str, Any]]] = None,
    ) -> AttachmentAnalysisReport:
        """Run deep static inspection and YARA scanning across all attachments in a CanonicalEmail.

        Args:
            email: CanonicalEmail containing extracted attachments.
            known_bad_hashes: Optional set of MD5, SHA-1, or SHA-256 threat intelligence IoC hashes.
            custom_rules: Optional list of custom YARA rules to append.

        Returns:
            A populated AttachmentAnalysisReport.
        """
        threat_hashes = {h.lower().strip() for h in (known_bad_hashes or set())}
        analyses: List[AttachmentThreatAnalysis] = []
        global_flags: List[str] = []

        active_rules = list(self.rules)
        if custom_rules:
            active_rules.extend(custom_rules)

        for attachment in email.extracted_attachments:
            # Read bytes from saved_path if present, or attempt fallback
            raw_bytes = self._load_attachment_bytes(attachment)
            analysis = self.scan_attachment(
                attachment=attachment,
                raw_bytes=raw_bytes,
                known_bad_hashes=threat_hashes,
                rules=active_rules,
            )
            attachment.threat_analysis = analysis
            analyses.append(analysis)

            for ind in analysis.threat_indicators:
                if ind not in global_flags:
                    global_flags.append(ind)

        # Calculate aggregated report metrics
        malicious_count = sum(
            1 for a in analyses if a.is_malicious or a.threat_level == "MALICIOUS"
        )
        suspicious_count = sum(1 for a in analyses if a.threat_level == "SUSPICIOUS")
        dangerous_ext_count = sum(1 for a in analyses if a.dangerous_extension)
        total_yara = sum(len(a.yara_matches) for a in analyses)

        max_score = max([a.threat_score for a in analyses], default=0.0)

        if max_score >= 60.0 or malicious_count > 0:
            overall_risk = "MALICIOUS"
        elif max_score >= 20.0 or suspicious_count > 0 or dangerous_ext_count > 0:
            overall_risk = "SUSPICIOUS"
        else:
            overall_risk = "CLEAN"

        report = AttachmentAnalysisReport(
            total_attachments_scanned=len(analyses),
            malicious_attachments_count=malicious_count,
            suspicious_attachments_count=suspicious_count,
            dangerous_extensions_count=dangerous_ext_count,
            total_yara_matches=total_yara,
            overall_attachment_risk=overall_risk,
            threat_score=max_score,
            attachment_analyses=analyses,
            flags=global_flags,
        )

        email.attachment_threat_report = report
        return report

    def scan_attachment(
        self,
        attachment: ExtractedAttachment,
        raw_bytes: bytes,
        known_bad_hashes: Optional[Set[str]] = None,
        rules: Optional[List[Dict[str, Any]]] = None,
    ) -> AttachmentThreatAnalysis:
        """Analyze an individual attachment for static threats, macros, exploits, and YARA matches.

        Args:
            attachment: ExtractedAttachment metadata.
            raw_bytes: Attachment raw payload content.
            known_bad_hashes: Set of IoC threat hashes.
            rules: Active YARA rule set.

        Returns:
            AttachmentThreatAnalysis result.
        """
        threat_hashes = known_bad_hashes or set()
        active_rules = rules or self.rules

        categories: List[str] = []
        indicators: List[str] = []
        matched_iocs: List[str] = []
        extracted_strings: List[str] = []
        score = 0.0

        filename = attachment.filename.lower()
        ext = filename.split(".")[-1] if "." in filename else ""

        # 1. Dangerous Extension Check
        is_dangerous_ext = ext in DANGEROUS_EXTENSIONS
        if is_dangerous_ext:
            categories.append("DANGEROUS_EXTENSION")
            indicators.append(f"DANGEROUS_EXTENSION_{ext.upper()}")
            score += 35.0

        # 2. Extension Mismatch / Spoofing Check (from FileTypeInspection)
        is_ext_mismatch = attachment.file_type_inspection.is_extension_mismatch
        if is_ext_mismatch:
            categories.append("EXTENSION_MAGIC_MISMATCH")
            indicators.append("ATTACHMENT_EXTENSION_SPOOFING")
            score += 40.0

        # 3. Threat Intelligence Hash Matching (MD5, SHA1, SHA256)
        for hash_type, hash_val in attachment.hashes.items():
            if hash_val.lower() in threat_hashes:
                matched_iocs.append(f"{hash_type.upper()}:{hash_val}")
                indicators.append("IOC_THREAT_HASH_MATCH")
                categories.append("KNOWN_THREAT_IOC")
                score += 50.0

        # 4. YARA Rule Execution
        yara_matches = self._run_yara_scan(raw_bytes, active_rules)
        for y_match in yara_matches:
            indicators.append(f"YARA_MATCH_{y_match.rule_name}")
            if "macro" in y_match.tags:
                categories.append("MACRO_VBA")
            elif "executable" in y_match.tags:
                categories.append("EMBEDDED_PE")
            elif "pdf" in y_match.tags:
                categories.append("EXPLOIT_PDF")
            elif "script" in y_match.tags:
                categories.append("SCRIPT_PAYLOAD")

            if y_match.severity == "CRITICAL":
                score += 50.0
            elif y_match.severity == "HIGH":
                score += 35.0
            else:
                score += 20.0

        # 5. Deep Static Payload Inspection
        # A. Office Macro Deep Inspection
        office_threats = self._inspect_office_macros(raw_bytes, ext)
        if office_threats:
            if "MACRO_VBA" not in categories:
                categories.append("MACRO_VBA")
            for t in office_threats:
                if t not in indicators:
                    indicators.append(t)
            score += 35.0

        # B. PDF Object Stream Deep Inspection
        pdf_threats = self._inspect_pdf_threats(raw_bytes, ext)
        if pdf_threats:
            if "EXPLOIT_PDF" not in categories:
                categories.append("EXPLOIT_PDF")
            for t in pdf_threats:
                if t not in indicators:
                    indicators.append(t)
            score += 30.0

        # C. PE Header & Script Deep Inspection
        pe_threats = self._inspect_pe_and_scripts(raw_bytes, ext)
        if pe_threats:
            if "EMBEDDED_PE" not in categories:
                categories.append("EMBEDDED_PE")
            for t in pe_threats:
                if t not in indicators:
                    indicators.append(t)
            score += 45.0

        # Extract notable readable ASCII/UTF-8 strings
        extracted_strings = self._extract_interesting_strings(raw_bytes)

        threat_score = min(score, 100.0)

        # Threat classification
        if threat_score >= 60.0 or "KNOWN_THREAT_IOC" in categories or len(yara_matches) > 0:
            threat_level = "MALICIOUS"
            is_malicious = True
        elif threat_score >= 20.0 or is_dangerous_ext or is_ext_mismatch:
            threat_level = "SUSPICIOUS"
            is_malicious = False
        else:
            threat_level = "BENIGN"
            is_malicious = False

        return AttachmentThreatAnalysis(
            is_malicious=is_malicious,
            threat_level=threat_level,
            threat_score=threat_score,
            threat_categories=categories,
            dangerous_extension=is_dangerous_ext,
            extension_mismatch=is_ext_mismatch,
            yara_matches=yara_matches,
            extracted_strings=extracted_strings,
            ioc_hashes_matched=matched_iocs,
            threat_indicators=indicators,
        )

    # -------------------------------------------------------------------------
    # Core Forensic Scanning Engines
    # -------------------------------------------------------------------------

    def _run_yara_scan(
        self,
        raw_bytes: bytes,
        rules: List[Dict[str, Any]],
    ) -> List[YARAMatchArtifact]:
        """Execute YARA rules against the raw attachment payload."""
        matches: List[YARAMatchArtifact] = []
        if not raw_bytes:
            return matches

        # Try scanning with string/regex pattern rules
        for rule in rules:
            rule_name = rule["rule_name"]
            severity = rule.get("severity", "HIGH")
            tags = rule.get("tags", [])
            meta = rule.get("meta", {})
            patterns = rule.get("patterns", [])
            condition = rule.get("condition", "any")

            matched_strings: List[Tuple[str, str]] = []

            for pattern_str, ident in patterns:
                try:
                    # Search pattern in bytes using regex or binary search
                    compiled_pat = re.compile(pattern_str.encode("latin1"), re.IGNORECASE)
                    match_obj = compiled_pat.search(raw_bytes)
                    if match_obj:
                        snippet = match_obj.group(0).decode("latin1", errors="ignore")[:60]
                        matched_strings.append((ident, snippet))
                except Exception:
                    continue

            # Evaluate condition
            is_matched = False
            if condition == "all":
                is_matched = len(matched_strings) == len(patterns) and len(patterns) > 0
            else:  # any
                is_matched = len(matched_strings) > 0

            if is_matched:
                matches.append(
                    YARAMatchArtifact(
                        rule_name=rule_name,
                        namespace="dfir",
                        tags=tags,
                        meta=meta,
                        matched_strings=matched_strings,
                        severity=severity,
                    )
                )

        return matches

    def _inspect_office_macros(self, raw_bytes: bytes, ext: str) -> List[str]:
        """Detect VBA macro streams, execution hooks, and OLE storage containers."""
        threats: List[str] = []
        if not raw_bytes:
            return threats

        lower_bytes = raw_bytes.lower()

        # Check for OLE header or OpenXML vbaProject.bin
        has_vba_bin = (
            b"vbaproject.bin" in lower_bytes
            or b"_vba_project" in lower_bytes
            or b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" in raw_bytes[:8]
        )

        if has_vba_bin or ext in MACRO_EXTENSIONS:
            # Look for VBA execution hooks
            if re.search(rb"(?i)\b(?:autoopen|document_open|workbook_open|auto_open)\b", raw_bytes):
                threats.append("VBA_MACRO_AUTO_EXECUTION_HOOK")

            # Look for process execution
            if re.search(
                rb"(?i)\b(?:wscript\.shell|shellexecute|createobject|callbyname)\b", raw_bytes
            ):
                threats.append("VBA_MACRO_SHELL_INJECTION")

            # Look for network download
            if re.search(rb"(?i)\b(?:urldownloadtofile|winhttprequest|xmlhttp)\b", raw_bytes):
                threats.append("VBA_MACRO_NETWORK_DOWNLOAD")

        return threats

    def _inspect_pdf_threats(self, raw_bytes: bytes, ext: str) -> List[str]:
        """Inspect PDF object streams for malicious action dictionaries and embedded JavaScript."""
        threats: List[str] = []
        if not raw_bytes or (ext != "pdf" and not raw_bytes.startswith(b"%PDF")):
            return threats

        # Scan for /JavaScript or /JS
        if re.search(rb"(?i)/(?:javascript|js)\b", raw_bytes):
            threats.append("PDF_EMBEDDED_JAVASCRIPT")

        # Scan for /Launch (can execute arbitrary system binaries)
        if re.search(rb"(?i)/launch\b", raw_bytes):
            threats.append("PDF_MALICIOUS_LAUNCH_ACTION")

        # Scan for /EmbeddedFiles
        if re.search(rb"(?i)/embeddedfiles\b", raw_bytes):
            threats.append("PDF_EMBEDDED_FILE_DROFFER")

        # Scan for /OpenAction or /AA (Automatic action on document open)
        if re.search(rb"(?i)/(?:openaction|aa)\b", raw_bytes):
            threats.append("PDF_AUTOMATIC_ACTION_ON_OPEN")

        return threats

    def _inspect_pe_and_scripts(self, raw_bytes: bytes, ext: str) -> List[str]:
        """Inspect raw Windows Portable Executable headers and script droppers."""
        threats: List[str] = []
        if not raw_bytes:
            return threats

        # Check for DOS 'MZ' header
        if raw_bytes.startswith(b"MZ"):
            # Check PE signature at offset
            if len(raw_bytes) >= 0x3C + 4:
                pe_offset = int.from_bytes(raw_bytes[0x3C:0x40], byteorder="little")
                if (
                    0 < pe_offset < len(raw_bytes) - 4
                    and raw_bytes[pe_offset : pe_offset + 4] == b"PE\x00\x00"
                ):
                    threats.append("WINDOWS_PE_EXECUTABLE_HEADER")

        # Check for PowerShell download Cradle
        if re.search(rb"(?i)downloadstring\s*\(", raw_bytes):
            threats.append("POWERSHELL_DOWNLOAD_CRADLE")

        # Check for reflective injection APIs
        if re.search(rb"(?i)\b(?:virtualalloc|createthread|ntunmapviewofsection)\b", raw_bytes):
            threats.append("PROCESS_INJECTION_API_STRINGS")

        return threats

    @staticmethod
    def _extract_interesting_strings(raw_bytes: bytes, max_strings: int = 15) -> List[str]:
        """Extract notable human-readable ASCII/UTF-8 strings from binary payloads."""
        if not raw_bytes:
            return []

        pattern = re.compile(rb"[A-Za-z0-9_./:\\-]{6,}")
        matches = pattern.findall(raw_bytes)
        result: List[str] = []
        for m in matches:
            decoded = m.decode("latin1", errors="ignore").strip()
            if any(
                k in decoded.lower()
                for k in [
                    "http",
                    "powershell",
                    "cmd",
                    "vba",
                    "shell",
                    "exec",
                    "dll",
                    "temp",
                    "win",
                    "kernel",
                ]
            ):
                if decoded not in result:
                    result.append(decoded)
            if len(result) >= max_strings:
                break

        return result

    @staticmethod
    def _load_attachment_bytes(attachment: ExtractedAttachment) -> bytes:
        """Safely load raw bytes for an extracted attachment artifact."""
        if attachment.saved_path and os.path.exists(attachment.saved_path):
            try:
                return Path(attachment.saved_path).read_bytes()
            except Exception:
                pass
        return b""
