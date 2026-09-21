"""Volatile Memory YARA Scanner & Process Anomaly Attribution Engine."""

from __future__ import annotations

import hashlib
import io
import re
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Tuple

from eft.models.memory_forensics import (
    MemoryThreatAttributionReport,
    MemoryThreatFamily,
    MemoryYARAMatch,
)

# Built-in Volatile Memory DFIR Rule Definitions
BUILTIN_MEMORY_YARA_RULES: List[Dict[str, Any]] = [
    {
        "rule_name": "MEMORY_COBALT_STRIKE_BEACON",
        "threat_family": MemoryThreatFamily.COBALT_STRIKE,
        "severity": "CRITICAL",
        "tags": ["c2", "beacon", "cobaltstrike", "post_exploitation"],
        "meta": {
            "description": "Detects Cobalt Strike Beacon memory artifacts, named pipes, and reflective loader stubs",
            "author": "EFT DFIR Core",
            "reference": "MITRE ATT&CK T1071, T1055",
        },
        "patterns": [
            (
                r"(?i)\\\\(\.|\?)\\pipe\\(?:msagent_\w+|status_\w+|MSSE-\w+|postex_\w+|win_select_\w+|beac)",
                "CS_NAMED_PIPE",
            ),
            (
                r"(?i)\b(?:beacon\.dll|beacon\.x64\.dll|beacon\.x86\.dll)\b",
                "CS_DLL_MARKER",
            ),
            (
                r"(?i)\b(?:%s as %s\\%s: %d|I'm sorry!|could not connect to pipe|Started service %s)\b",
                "CS_LOG_FORMATTER",
            ),
        ],
        "condition": "any",
        "risk_score": 95,
        "mitre_attack": "T1071",
    },
    {
        "rule_name": "MEMORY_MIMIKATZ_CREDENTIAL_DUMPER",
        "threat_family": MemoryThreatFamily.MIMIKATZ,
        "severity": "CRITICAL",
        "tags": ["credentials", "mimikatz", "lsass", "privilege_escalation"],
        "meta": {
            "description": "Detects Mimikatz in-memory credential dumping commands and LSASS hooking signatures",
            "author": "EFT DFIR Core",
            "reference": "MITRE ATT&CK T1003.001",
        },
        "patterns": [
            (
                r"(?i)\b(?:sekurlsa::logonpasswords|sekurlsa::wdigest|sekurlsa::minidump|kerberos::tgt|lsadump::sam|privilege::debug)\b",
                "MIMIKATZ_COMMAND",
            ),
            (
                r"(?i)\b(?:gentilkiwi|mimikatz\.exe|lsasrv\.dll|wdigest\.dll|livessp\.dll|mimilib\.dll)\b",
                "MIMIKATZ_STRINGS",
            ),
            (
                r"(?i)\b(?:kuhl_m_sekurlsa_all|kuhl_m_lsadump)\b",
                "MIMIKATZ_SYMBOL",
            ),
        ],
        "condition": "any",
        "risk_score": 95,
        "mitre_attack": "T1003.001",
    },
    {
        "rule_name": "MEMORY_METASPLOIT_METERPRETER",
        "threat_family": MemoryThreatFamily.METERPRETER,
        "severity": "CRITICAL",
        "tags": ["meterpreter", "metasploit", "stager", "c2"],
        "meta": {
            "description": "Detects Metasploit Meterpreter reflective DLLs and command channel signatures",
            "author": "EFT DFIR Core",
            "reference": "MITRE ATT&CK T1055.001",
        },
        "patterns": [
            (
                r"(?i)\b(?:metsrv\.dll|ext_server_stdapi\.dll|ext_server_priv\.dll|ext_server_espia\.dll)\b",
                "METERPRETER_DLL",
            ),
            (
                r"(?i)\b(?:stdapi_sys_process|stdapi_net_config|core_channel_open|core_loadlib)\b",
                "METERPRETER_API",
            ),
            (
                r"(?i)\b(?:MeterpreterSession|metcli\.exe)\b",
                "METERPRETER_SESSION",
            ),
        ],
        "condition": "any",
        "risk_score": 90,
        "mitre_attack": "T1055.001",
    },
    {
        "rule_name": "MEMORY_LUMMA_STEALER_INFO_STEALER",
        "threat_family": MemoryThreatFamily.LUMMA_STEALER,
        "severity": "HIGH",
        "tags": ["stealer", "lumma", "crypto", "infostealer"],
        "meta": {
            "description": "Detects Lumma Stealer and RedLine information stealer strings and wallet targeting hooks",
            "author": "EFT DFIR Core",
            "reference": "MITRE ATT&CK T1555, T1539",
        },
        "patterns": [
            (
                r"(?i)\b(?:LummaC2|lumma\.stub|Lumma Stealer|api\/v1\/lumma)\b",
                "LUMMA_C2_MARKER",
            ),
            (
                r"(?i)\b(?:nkbihfbeogaeaoehlefnkodbefgpgknn|ibnejdfjmmkpcnlpebklmnkoeoihofec|ejbalbakoplchlghecdalmeeeajnimhm)\b",
                "CRYPTO_WALLET_EXT_ID",
            ),
            (
                r"(?i)\b(?:wallets\\metamask|wallets\\atomic|wallets\\exodus|cookies\.sqlite)\b",
                "STEALER_TARGET_PATH",
            ),
        ],
        "condition": "any",
        "risk_score": 85,
        "mitre_attack": "T1555",
    },
    {
        "rule_name": "MEMORY_REFLECTIVE_DLL_INJECTION",
        "threat_family": MemoryThreatFamily.REFLECTIVE_INJECTION,
        "severity": "HIGH",
        "tags": ["injection", "reflective", "hollowing", "stealth"],
        "meta": {
            "description": "Detects in-memory reflective injection, process hollowing, and remote thread manipulation APIs",
            "author": "EFT DFIR Core",
            "reference": "MITRE ATT&CK T1055.002",
        },
        "patterns": [
            (
                r"(?i)\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|QueueUserAPC|NtQueueApcThread)\b",
                "INJECTION_API_COMBO",
            ),
            (
                r"(?i)\b(?:NtUnmapViewOfSection|ZwMapViewOfSection|MapViewOfFile)\b",
                "HOLLOWING_API",
            ),
            (
                r"(?i)\b(?:ProcessHollowing|SetThreadContext|ResumeThread)\b",
                "THREAD_HIJACK_MARKER",
            ),
        ],
        "condition": "any",
        "risk_score": 80,
        "mitre_attack": "T1055.002",
    },
    {
        "rule_name": "MEMORY_RANSOMWARE_ENCRYPTOR",
        "threat_family": MemoryThreatFamily.RANSOMWARE_ENCRYPTOR,
        "severity": "CRITICAL",
        "tags": ["ransomware", "encryptor", "shadow_deletion", "extortion"],
        "meta": {
            "description": "Detects volume shadow copy deletion, recovery disablement, and ransom note markers in memory",
            "author": "EFT DFIR Core",
            "reference": "MITRE ATT&CK T1486, T1490",
        },
        "patterns": [
            (
                r"(?i)\b(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|wbadmin(?:\.exe)?\s+delete\s+catalog)\b",
                "SHADOW_DELETE_COMMAND",
            ),
            (
                r"(?i)\b(?:bcdedit(?:\.exe)?\s+\/set\s+\{default\}\s+bootstatuspolicy\s+ignoreallfailures)\b",
                "BCDEDIT_DISABLE_RECOVERY",
            ),
            (
                r"(?i)\b(?:YOUR FILES ARE ENCRYPTED|ALL YOUR DATA HAS BEEN LOCKED|README_DECRYPT|DECRYPT_NOTE)\b",
                "RANSOM_NOTE_TEMPLATE",
            ),
        ],
        "condition": "any",
        "risk_score": 95,
        "mitre_attack": "T1486",
    },
]


class MemoryYARAScanner:
    """Volatile memory threat actor signature scanner and attribution engine."""

    def __init__(
        self,
        custom_rules: List[Dict[str, Any]] | None = None,
        default_chunk_size: int = 1024 * 1024,
    ) -> None:
        """Initialize scanner with built-in rules and optional custom definitions."""
        self.default_chunk_size = default_chunk_size
        self._rules = list(BUILTIN_MEMORY_YARA_RULES)
        if custom_rules:
            self._rules.extend(custom_rules)

        # Pre-compile regexes for fast streaming evaluation
        self._compiled_rules: List[Dict[str, Any]] = []
        for r in self._rules:
            compiled_patterns: List[Tuple[re.Pattern[bytes], str]] = []
            for pat_str, ident in r.get("patterns", []):
                try:
                    compiled_patterns.append((re.compile(pat_str.encode("utf-8")), ident))
                except Exception:
                    pass

            self._compiled_rules.append(
                {
                    "rule_name": r["rule_name"],
                    "threat_family": r.get("threat_family", MemoryThreatFamily.GENERIC_TROJAN),
                    "severity": r.get("severity", "HIGH"),
                    "tags": r.get("tags", []),
                    "meta": r.get("meta", {}),
                    "compiled_patterns": compiled_patterns,
                    "condition": r.get("condition", "any"),
                    "risk_score": r.get("risk_score", 80),
                    "mitre_attack": r.get("mitre_attack"),
                }
            )

    def scan_bytes(self, data: bytes, base_offset: int = 0) -> list[MemoryYARAMatch]:
        """Scan a binary memory buffer against all compiled memory YARA rules.

        Args:
            data: Raw memory bytes to scan.
            base_offset: Absolute starting byte offset of this block in the memory dump.

        Returns:
            List of matching MemoryYARAMatch findings.
        """
        matches: list[MemoryYARAMatch] = []
        if not data:
            return matches

        for rule in self._compiled_rules:
            matched_strings: list[tuple[int, str, str]] = []
            pattern_matched_count = 0

            for pattern, ident in rule["compiled_patterns"]:
                found_for_pattern = False
                for m in pattern.finditer(data):
                    rel_off = m.start()
                    val_str = m.group(0).decode("utf-8", errors="replace")
                    matched_strings.append((base_offset + rel_off, ident, val_str))
                    found_for_pattern = True

                if found_for_pattern:
                    pattern_matched_count += 1

            # Evaluate match condition
            condition = rule["condition"]
            is_matched = False
            total_patterns = len(rule["compiled_patterns"])

            if condition == "any" and pattern_matched_count > 0:
                is_matched = True
            elif (
                condition == "all"
                and pattern_matched_count == total_patterns
                and total_patterns > 0
            ):
                is_matched = True
            elif isinstance(condition, int) and pattern_matched_count >= condition:
                is_matched = True

            if is_matched:
                matches.append(
                    MemoryYARAMatch(
                        rule_name=rule["rule_name"],
                        threat_family=rule["threat_family"],
                        severity=rule["severity"],
                        tags=rule["tags"],
                        meta=rule["meta"],
                        strings_matched=matched_strings,
                        risk_score=rule["risk_score"],
                        mitre_attack=rule["mitre_attack"],
                    )
                )

        return matches

    def scan_stream(
        self,
        stream_or_path: str | Path | bytes | BinaryIO,
        chunk_size: int | None = None,
    ) -> MemoryThreatAttributionReport:
        """Stream through multi-gigabyte memory images, executing YARA scans and aggregating threat attributions.

        Args:
            stream_or_path: File path, bytes, or BinaryIO stream.
            chunk_size: Processing buffer chunk size (default 1MB).

        Returns:
            MemoryThreatAttributionReport with threat family attributions and composite risk score.
        """
        evidence_path = (
            str(stream_or_path)
            if isinstance(stream_or_path, (str, Path))
            else "<memory_stream_buffer>"
        )

        stream, should_close = self._get_binary_stream(stream_or_path)
        c_size = chunk_size or self.default_chunk_size
        overlap_size = 4096

        md5_hasher = hashlib.md5()
        sha256_hasher = hashlib.sha256()

        all_matches: list[MemoryYARAMatch] = []
        rule_match_map: dict[str, MemoryYARAMatch] = {}
        detected_families: set[MemoryThreatFamily] = set()

        try:
            buffer = bytearray()
            stream_offset = 0

            while True:
                chunk = stream.read(c_size)
                is_eof = len(chunk) == 0

                if chunk:
                    buffer.extend(chunk)
                    md5_hasher.update(chunk)
                    sha256_hasher.update(chunk)

                if not buffer:
                    break

                # Scan the current buffer
                chunk_matches = self.scan_bytes(bytes(buffer), base_offset=stream_offset)
                for cm in chunk_matches:
                    if cm.rule_name not in rule_match_map:
                        rule_match_map[cm.rule_name] = cm
                        all_matches.append(cm)
                    else:
                        # Append new string match locations without duplicating
                        existing = rule_match_map[cm.rule_name]
                        for s_off, s_id, s_val in cm.strings_matched:
                            if not any(
                                ex_off == s_off and ex_id == s_id
                                for ex_off, ex_id, _ in existing.strings_matched
                            ):
                                existing.strings_matched.append((s_off, s_id, s_val))

                    if cm.threat_family != MemoryThreatFamily.BENIGN:
                        detected_families.add(cm.threat_family)

                if is_eof:
                    break

                # Slide forward keeping overlap
                slide_amount = max(0, len(buffer) - overlap_size)
                if slide_amount == 0:
                    slide_amount = len(buffer)

                del buffer[:slide_amount]
                stream_offset += slide_amount

        finally:
            if should_close:
                stream.close()

        evidence_hashes = {
            "md5": md5_hasher.hexdigest(),
            "sha256": sha256_hasher.hexdigest(),
        }

        # Calculate composite threat score
        composite_score = 0
        if all_matches:
            max_score = max(m.risk_score for m in all_matches)
            # Add bonus points for multiple distinct threat families detected
            bonus = min(15, (len(detected_families) - 1) * 5) if len(detected_families) > 1 else 0
            composite_score = min(100, max_score + bonus)

        # Determine overall threat level
        if composite_score >= 90:
            threat_level = "CRITICAL"
        elif composite_score >= 70:
            threat_level = "HIGH"
        elif composite_score >= 40:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        # Executive summary
        if detected_families:
            fam_str = ", ".join(sorted(f.value for f in detected_families))
            attribution_summary = (
                f"Volatile memory scan identified {len(all_matches)} threat signatures. "
                f"Attributed malware/tooling families: {fam_str}."
            )
        else:
            attribution_summary = "No volatile memory threat actor signatures identified."

        return MemoryThreatAttributionReport(
            evidence_path=evidence_path,
            evidence_hashes=evidence_hashes,
            total_yara_matches=len(all_matches),
            threat_families_detected=sorted(list(detected_families), key=lambda f: f.value),
            yara_matches=all_matches,
            composite_threat_score=composite_score,
            threat_level=threat_level,
            attribution_summary=attribution_summary,
        )

    def _get_binary_stream(
        self, stream_or_path: str | Path | bytes | BinaryIO
    ) -> tuple[BinaryIO, bool]:
        """Convert input path, bytes, or stream into a readable binary stream and close flag."""
        if isinstance(stream_or_path, (str, Path)):
            path = Path(stream_or_path)
            if not path.exists():
                raise FileNotFoundError(f"Memory dump file not found: {path}")
            return open(path, "rb"), True
        elif isinstance(stream_or_path, bytes):
            return io.BytesIO(stream_or_path), False
        elif hasattr(stream_or_path, "read"):
            if hasattr(stream_or_path, "seek") and stream_or_path.seekable():
                stream_or_path.seek(0)
            return stream_or_path, False
        else:
            raise ValueError(f"Unsupported memory image input type: {type(stream_or_path)}")
