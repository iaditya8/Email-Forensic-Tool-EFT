"""Static OLE Compound Document and MS-OVBA Macro Forensics Analyzer."""

from __future__ import annotations

import io
import math
import re
import struct
from pathlib import Path
from typing import List, Set, Union

try:
    import olefile
except ImportError:
    olefile = None  # type: ignore

from eft.models.pe_ole import OLEAnalysisReport, VBAMacroStream

# Regex signatures for Auto-Execution Triggers in VBA
AUTO_EXEC_PATTERNS = [
    re.compile(r"\b(autoopen|auto_open)\b", re.IGNORECASE),
    re.compile(r"\b(autoclose|auto_close)\b", re.IGNORECASE),
    re.compile(r"\b(autoexec|auto_exec|autoexit)\b", re.IGNORECASE),
    re.compile(r"\b(document_open|documentopen|document_close)\b", re.IGNORECASE),
    re.compile(
        r"\b(workbook_open|workbookopen|workbook_activate|workbook_beforeclose)\b", re.IGNORECASE
    ),
    re.compile(r"\b(userform_initialize|userform_activate)\b", re.IGNORECASE),
    re.compile(r"\b(app_workbookopen)\b", re.IGNORECASE),
]

# Regex signatures for Suspicious VBA Functions & System APIs
SUSPICIOUS_VBA_KEYWORDS = [
    (
        re.compile(r"\b(shell|wscript\.shell|shell\.application)\b", re.IGNORECASE),
        "Process / Command Execution Shell",
    ),
    (
        re.compile(r"\b(createobject|getobject)\b", re.IGNORECASE),
        "Dynamic COM Object Instantiation",
    ),
    (
        re.compile(
            r"\b(msxml2\.xmlhttp|msxml2\.serverxmlhttp|winhttp\.winhttprequest)\b", re.IGNORECASE
        ),
        "HTTP Network Client Object",
    ),
    (
        re.compile(r"\b(urldownloadtofile|urldownloadtofilea|urldownloadtofilew)\b", re.IGNORECASE),
        "Direct URL File Downloader",
    ),
    (
        re.compile(r"\b(environ|environ\$)\b", re.IGNORECASE),
        "Environment Variable Inspection (TEMP/APPDATA)",
    ),
    (re.compile(r"\b(callbyname)\b", re.IGNORECASE), "Dynamic Function Invocation (Evasion)"),
    (
        re.compile(
            r"\b(declare\s+(ptrsafe\s+)?sub|declare\s+(ptrsafe\s+)?function)\b", re.IGNORECASE
        ),
        "Native Win32 API Declaration",
    ),
    (
        re.compile(r'\blib\s+"(kernel32|urlmon|shell32|user32|advapi32)"\b', re.IGNORECASE),
        "Native DLL Import Binding",
    ),
    (re.compile(r"\b(macscript|applescript)\b", re.IGNORECASE), "macOS Script Execution"),
    (
        re.compile(r"\b(kill|filecopy|open\s+.*\s+for\s+binary)\b", re.IGNORECASE),
        "Direct File System Mutation",
    ),
]

# Obfuscation signatures
OBFUSCATION_PATTERNS = [
    (re.compile(r"(?:chr|chrw|chrb)\s*\(\s*\d+\s*\)", re.IGNORECASE), "Chr() ASCII Concatenation"),
    (re.compile(r"\bstrreverse\s*\(", re.IGNORECASE), "String Reversal Evasion"),
    (
        re.compile(
            r"(?:&\s*[\"'][\"']\s*&|[\"'][a-zA-Z0-9]{1,3}[\"']\s*&\s*[\"'][a-zA-Z0-9]{1,3}[\"'])",
            re.IGNORECASE,
        ),
        "Fragmented String Concatenation",
    ),
    (re.compile(r"\bxor\s+(?:&h[0-9a-f]+|\d+)\b", re.IGNORECASE), "XOR Bitwise Encryption Loop"),
    (re.compile(r"\b(?:hex|oct|asc|ascw)\s*\(", re.IGNORECASE), "Encoding Conversion Routine"),
]

# IoC Extraction Patterns
URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9_\-\.\:\/%#\?=&]+", re.IGNORECASE)
IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
COMMAND_PATTERN = re.compile(
    r"\b(powershell(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?)\b",
    re.IGNORECASE,
)


def decompress_ms_ovba(data: bytes) -> str:
    """Decompress Microsoft MS-OVBA compressed VBA stream (RFC Section 2.4.1.3.1)."""
    if not data:
        return ""

    # Check for MS-OVBA compressed container signature (byte 0x01)
    sig_offset = data.find(b"\x01")
    if sig_offset == -1:
        # Fallback: attempt to decode raw text directly
        return data.decode("latin-1", errors="replace")

    pos = sig_offset + 1
    decompressed: List[int] = []

    while pos + 2 <= len(data):
        chunk_header = struct.unpack_from("<H", data, pos)[0]
        pos += 2

        if chunk_header == 0:
            break

        chunk_size = (chunk_header & 0x0FFF) + 3
        is_compressed = bool(chunk_header & 0x8000)
        chunk_end = min(len(data), pos + chunk_size - 2)

        if not is_compressed:
            # Uncompressed raw chunk
            decompressed.extend(data[pos:chunk_end])
            pos = chunk_end
            continue

        # Compressed chunk parsing
        chunk_decomp: List[int] = []
        chunk_pos = pos

        while chunk_pos < chunk_end:
            flag_byte = data[chunk_pos]
            chunk_pos += 1

            for bit in range(8):
                if chunk_pos >= chunk_end:
                    break

                is_copy_token = bool((flag_byte >> bit) & 1)

                if not is_copy_token:
                    # Literal token: 1 byte
                    chunk_decomp.append(data[chunk_pos])
                    chunk_pos += 1
                else:
                    # Copy token: 2 bytes
                    if chunk_pos + 2 > len(data):
                        break
                    copy_token = struct.unpack_from("<H", data, chunk_pos)[0]
                    chunk_pos += 2

                    decomp_len = len(chunk_decomp)
                    bit_count = 4
                    if decomp_len > 0:
                        bit_count = max(4, math.ceil(math.log2(decomp_len + 1)))
                    bit_count = min(12, max(4, bit_count))

                    length_mask = (1 << (16 - bit_count)) - 1
                    offset_mask = (~length_mask) & 0xFFFF

                    length = (copy_token & length_mask) + 3
                    offset = ((copy_token & offset_mask) >> (16 - bit_count)) + 1

                    copy_start = len(chunk_decomp) - offset
                    for _ in range(length):
                        if 0 <= copy_start < len(chunk_decomp):
                            chunk_decomp.append(chunk_decomp[copy_start])
                            copy_start += 1
                        else:
                            chunk_decomp.append(0)

        decompressed.extend(chunk_decomp)
        pos = chunk_end

    raw_bytes = bytes(decompressed)
    return raw_bytes.decode("latin-1", errors="replace")


class OLEMacroAnalyzer:
    """Forensic analyzer for OLE compound documents and embedded VBA macros."""

    OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

    def is_ole(self, data: bytes) -> bool:
        """Check if binary begins with OLE2 compound document magic header."""
        return data.startswith(self.OLE_MAGIC)

    def analyze(self, data_or_path: Union[bytes, str, Path]) -> OLEAnalysisReport:
        """Analyze an OLE compound document for streams, VBA macros, and malicious heuristics."""
        if isinstance(data_or_path, (str, Path)):
            with open(data_or_path, "rb") as f:
                data = f.read()
        else:
            data = data_or_path

        if not self.is_ole(data):
            return OLEAnalysisReport(
                is_ole_compound_document=False,
                forensic_alerts=[
                    "File is not an OLE Compound Document (missing \\xd0\\xcf\\x11\\xe0 magic header)"
                ],
                threat_score=0.0,
                verdict="BENIGN",
            )

        stream_hierarchy: List[str] = []
        vba_streams: List[VBAMacroStream] = []
        all_auto_execs: Set[str] = set()
        all_susp_keywords: Set[str] = set()
        all_urls: Set[str] = set()
        all_ips: Set[str] = set()
        all_commands: Set[str] = set()
        has_obfuscation = False
        forensic_alerts: List[str] = []

        if olefile is not None:
            try:
                ole = olefile.OleFileIO(io.BytesIO(data))
                for entry in ole.listdir():
                    path_str = "/".join(entry)
                    stream_hierarchy.append(path_str)

                    # Identify VBA project streams
                    # Standard VBA paths: 'Macros/VBA/...', 'VBA/...', '_VBA_PROJECT_CUR/VBA/...'
                    norm_path = path_str.lower()
                    if (
                        "vba" in norm_path
                        and not norm_path.endswith("dir")
                        and not norm_path.endswith("_vba_project")
                    ):
                        try:
                            stream_bytes = ole.openstream(entry).read()
                            decomp_code = decompress_ms_ovba(stream_bytes)
                            if decomp_code.strip():
                                vba_obj = self._analyze_vba_code(
                                    path_str, stream_bytes, decomp_code
                                )
                                vba_streams.append(vba_obj)
                        except Exception as e:
                            forensic_alerts.append(
                                f"Error extracting stream '{path_str}': {str(e)}"
                            )
                ole.close()
            except Exception as e:
                forensic_alerts.append(f"Error parsing OLE compound structure: {str(e)}")

        # Fallback stream detection if olefile was not able to extract or for raw OLE slices
        if not vba_streams:
            # Scan for embedded VBA module signatures or Attribut / Sub markers
            vba_signatures = [
                b"Attribute VB_Name",
                b"Sub AutoOpen",
                b"Sub Document_Open",
                b"Sub Workbook_Open",
            ]
            for sig in vba_signatures:
                idx = 0
                while True:
                    idx = data.find(sig, idx)
                    if idx == -1:
                        break
                    # Extract surrounding block
                    block = data[idx : idx + 4096]
                    code_str = block.decode("latin-1", errors="replace")
                    vba_obj = self._analyze_vba_code("Embedded_VBA_Fragment", block, code_str)
                    vba_streams.append(vba_obj)
                    idx += len(sig) + 100

        # Aggregate indicators across all extracted streams
        total_macro_lines = 0
        for stream in vba_streams:
            total_macro_lines += len(stream.source_code.splitlines())
            all_auto_execs.update(stream.auto_exec_triggers)
            all_susp_keywords.update(stream.suspicious_keywords)
            all_urls.update(stream.extracted_urls)
            all_ips.update(stream.extracted_ips)
            all_commands.update(stream.extracted_commands)
            if stream.is_obfuscated:
                has_obfuscation = True

        has_macros = len(vba_streams) > 0

        # Threat Scoring & Verdict
        threat_score = 0.0

        if has_macros:
            threat_score += 15.0
            forensic_alerts.append(
                f"Embedded VBA macros detected ({len(vba_streams)} module streams, {total_macro_lines} lines)"
            )

        if all_auto_execs:
            threat_score += 25.0
            forensic_alerts.append(
                f"Auto-execution macro triggers identified: {', '.join(sorted(all_auto_execs))}"
            )

        if all_commands:
            threat_score += 30.0
            forensic_alerts.append(
                f"External process execution commands found: {', '.join(sorted(all_commands))}"
            )

        if all_urls or all_ips:
            threat_score += 20.0
            forensic_alerts.append(
                f"Network C2 indicators extracted from macros ({len(all_urls)} URLs, {len(all_ips)} IPs)"
            )

        if has_obfuscation:
            threat_score += 20.0
            forensic_alerts.append(
                "VBA macro code obfuscation detected (Chr concatenation, string reversal, XOR encryption)"
            )

        # Evaluate suspicious keywords
        for kw in all_susp_keywords:
            if "Shell" in kw or "Process" in kw:
                threat_score += 15.0
            elif "HTTP" in kw or "Downloader" in kw:
                threat_score += 15.0
            elif "Native" in kw:
                threat_score += 10.0
            else:
                threat_score += 5.0

        threat_score = min(100.0, round(threat_score, 1))

        verdict = "BENIGN"
        if threat_score >= 60.0:
            verdict = "MALICIOUS"
        elif threat_score >= 30.0:
            verdict = "SUSPICIOUS"

        return OLEAnalysisReport(
            is_ole_compound_document=True,
            stream_hierarchy=stream_hierarchy,
            has_vba_macros=has_macros,
            vba_streams=vba_streams,
            total_macro_lines=total_macro_lines,
            all_auto_exec_triggers=sorted(list(all_auto_execs)),
            all_suspicious_keywords=sorted(list(all_susp_keywords)),
            all_extracted_urls=sorted(list(all_urls)),
            all_extracted_ips=sorted(list(all_ips)),
            all_extracted_commands=sorted(list(all_commands)),
            has_obfuscation=has_obfuscation,
            forensic_alerts=forensic_alerts,
            threat_score=threat_score,
            verdict=verdict,
        )

    def _analyze_vba_code(self, stream_name: str, raw_bytes: bytes, code: str) -> VBAMacroStream:
        """Inspect decompressed VBA source code for malicious heuristics and IoCs."""
        auto_execs: List[str] = []
        susp_kws: List[str] = []
        obfusc_inds: List[str] = []

        # Auto-Exec scan
        for pat in AUTO_EXEC_PATTERNS:
            matches = pat.findall(code)
            for m in matches:
                auto_execs.append(m.strip())

        # Suspicious keywords scan
        for pat, desc in SUSPICIOUS_VBA_KEYWORDS:
            if pat.search(code):
                susp_kws.append(desc)

        # Obfuscation scan
        for pat, desc in OBFUSCATION_PATTERNS:
            matches = pat.findall(code)
            if len(matches) > 3 or (len(matches) > 0 and "XOR" in desc):
                obfusc_inds.append(f"{desc} (count: {len(matches)})")

        is_obf = len(obfusc_inds) > 0

        # IoCs extraction
        urls = list(set(URL_PATTERN.findall(code)))
        raw_ips = list(set(IPV4_PATTERN.findall(code)))
        valid_ips = [ip for ip in raw_ips if not ip.startswith("127.") and not ip.startswith("0.")]
        cmds = list(set(COMMAND_PATTERN.findall(code)))

        return VBAMacroStream(
            stream_name=stream_name,
            code_size_bytes=len(raw_bytes),
            source_code=code,
            auto_exec_triggers=sorted(list(set(auto_execs))),
            suspicious_keywords=sorted(list(set(susp_kws))),
            extracted_urls=sorted(urls),
            extracted_ips=sorted(valid_ips),
            extracted_commands=sorted(cmds),
            is_obfuscated=is_obf,
            obfuscation_indicators=obfusc_inds,
        )
