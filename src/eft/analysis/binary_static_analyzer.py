"""Unified static binary and file artifact forensic analyzer."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Union

from eft.analysis.elf_analyzer import ELFBinaryAnalyzer
from eft.analysis.ole_analyzer import OLEMacroAnalyzer
from eft.analysis.pe_analyzer import PEBinaryAnalyzer, calculate_shannon_entropy, classify_entropy
from eft.models.pe_ole import BinaryStaticReport
from eft.models.threat import RiskSeverity


class BinaryStaticAnalyzer:
    """Master static analyzer for Portable Executables (PE), Linux ELFs, OLE documents, and binary artifacts."""

    def __init__(self) -> None:
        self.pe_analyzer = PEBinaryAnalyzer()
        self.elf_analyzer = ELFBinaryAnalyzer()
        self.ole_analyzer = OLEMacroAnalyzer()

    def analyze(
        self,
        data_or_path: Union[bytes, str, Path],
        filename: Optional[str] = None,
    ) -> BinaryStaticReport:
        """Perform comprehensive static forensic analysis on raw binary bytes or file path."""
        file_path_str: Optional[str] = None
        if isinstance(data_or_path, (str, Path)):
            p = Path(data_or_path)
            file_path_str = str(p.resolve())
            filename = filename or p.name
            with open(p, "rb") as f:
                data = f.read()
        else:
            data = data_or_path
            filename = filename or "evidence.bin"

        size_bytes = len(data)

        # Multi-algorithm cryptographic hashes (ISO/IEC 27037 Evidence Ledger standard)
        hashes: Dict[str, str] = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
        }

        # Shannon Entropy
        overall_entropy = calculate_shannon_entropy(data)
        entropy_tier = classify_entropy(overall_entropy)

        pe_report = None
        elf_report = None
        ole_report = None
        format_category = "Raw Binary / Unknown"
        remediation_advice: List[str] = []

        # Dispatch based on magic signatures
        if data.startswith(b"MZ"):
            format_category = "Windows Portable Executable (PE)"
            pe_report = self.pe_analyzer.analyze(data)
        elif data.startswith(b"\x7fELF"):
            format_category = "Linux / Unix Executable & Linkable Format (ELF)"
            elf_report = self.elf_analyzer.analyze(data)
        elif data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            format_category = "Microsoft OLE Compound Document"
            ole_report = self.ole_analyzer.analyze(data)

        # Threat Assessment Synthesis
        threat_score = 0.0
        is_suspicious = False
        verdict = "BENIGN"

        if pe_report and pe_report.is_valid_pe:
            threat_score = pe_report.threat_score
            verdict = pe_report.verdict
            is_suspicious = verdict in ("SUSPICIOUS", "MALICIOUS")
            if verdict == "MALICIOUS":
                remediation_advice.extend(
                    [
                        "Quarantine binary immediately and block associated hash across EDR agents.",
                        "Inspect endpoints for process injection, anomalous thread creation, or registry persistence.",
                        "Extract and block C2 network endpoints identified in import table.",
                    ]
                )
            elif verdict == "SUSPICIOUS":
                remediation_advice.extend(
                    [
                        "Submit binary artifact to an isolated dynamic malware sandbox for detonation analysis.",
                        "Verify file provenance, code-signing certificate, and distribution channel.",
                    ]
                )
        elif elf_report and elf_report.is_valid_elf:
            threat_score = elf_report.threat_score
            verdict = elf_report.verdict
            is_suspicious = verdict in ("SUSPICIOUS", "MALICIOUS")
            if verdict == "MALICIOUS":
                remediation_advice.extend(
                    [
                        "Quarantine Linux ELF binary and block executable SHA-256 across endpoint agents.",
                        "Check for memory injection, ptrace hooks, or unauthorized outbound socket listeners.",
                    ]
                )
            elif verdict == "SUSPICIOUS":
                remediation_advice.extend(
                    [
                        "Analyze suspicious symbols and binary section permissions in an isolated Linux containment sandbox.",
                    ]
                )
        elif ole_report and ole_report.is_ole_compound_document:
            threat_score = ole_report.threat_score
            verdict = ole_report.verdict
            is_suspicious = verdict in ("SUSPICIOUS", "MALICIOUS")
            if verdict == "MALICIOUS":
                remediation_advice.extend(
                    [
                        "Block incoming email attachment and isolate recipient workstation from network.",
                        "Block extracted external URLs/IPs on corporate perimeter firewalls.",
                        "Disable Office macro execution via Group Policy Object (GPO) across all endpoints.",
                    ]
                )
            elif verdict == "SUSPICIOUS":
                remediation_advice.extend(
                    [
                        "Inspect macro code in isolated sandbox and verify legitimate business requirement for automation.",
                    ]
                )
        else:
            # Generic binary evaluation
            if overall_entropy >= 7.5:
                threat_score = 45.0
                verdict = "SUSPICIOUS"
                is_suspicious = True
                remediation_advice.append(
                    "High entropy suggests encrypted payload or packed binary stream. Perform dynamic triage."
                )

        # Map to RiskSeverity
        if threat_score >= 70.0:
            severity = RiskSeverity.CRITICAL
        elif threat_score >= 45.0:
            severity = RiskSeverity.MALICIOUS_HIGH
        elif threat_score >= 25.0:
            severity = RiskSeverity.SUSPICIOUS_MEDIUM
        elif threat_score > 0.0:
            severity = RiskSeverity.SUSPICIOUS_LOW
        else:
            severity = RiskSeverity.CLEAN

        # Generate summary
        summary_parts = [f"Static binary analysis of '{filename}' ({size_bytes} bytes)."]
        if pe_report and pe_report.is_valid_pe:
            summary_parts.append(
                f"Format: {pe_report.architecture}, Subsystem: {pe_report.subsystem}, Sections: {pe_report.section_count}, "
                f"Entropy: {pe_report.overall_entropy:.2f} ({pe_report.overall_entropy_level.value}), "
                f"Packed: {pe_report.is_packed}, Suspicious APIs: {len(pe_report.suspicious_apis)}."
            )
        elif elf_report and elf_report.is_valid_elf:
            summary_parts.append(
                f"Format: {elf_report.architecture}, Type: {elf_report.file_type}, Sections: {elf_report.section_count}, "
                f"Entropy: {elf_report.overall_entropy:.2f} ({elf_report.overall_entropy_level.value}), "
                f"Packed: {elf_report.is_packed}, Suspicious Symbols: {len(elf_report.suspicious_symbols)}."
            )
        elif ole_report and ole_report.is_ole_compound_document:
            summary_parts.append(
                f"Format: OLE Compound Document, Streams: {len(ole_report.stream_hierarchy)}, "
                f"VBA Macros: {ole_report.has_vba_macros} ({len(ole_report.vba_streams)} modules, {ole_report.total_macro_lines} lines), "
                f"Auto-Exec Triggers: {len(ole_report.all_auto_exec_triggers)}, Obfuscation: {ole_report.has_obfuscation}."
            )
        else:
            summary_parts.append(
                f"Format: {format_category}, Entropy: {overall_entropy:.2f} ({entropy_tier.value})."
            )

        summary_parts.append(
            f"Forensic Verdict: {verdict} (Threat Score: {threat_score}/100, Severity: {severity.value})."
        )
        summary = " ".join(summary_parts)

        return BinaryStaticReport(
            file_path=file_path_str,
            filename=filename,
            size_bytes=size_bytes,
            hashes=hashes,
            format_category=format_category,
            pe_analysis=pe_report,
            elf_analysis=elf_report,
            ole_analysis=ole_report,
            overall_entropy=overall_entropy,
            overall_entropy_level=entropy_tier,
            is_suspicious=is_suspicious,
            threat_severity=severity,
            threat_score=threat_score,
            verdict=verdict,
            summary=summary,
            remediation_advice=remediation_advice,
        )
