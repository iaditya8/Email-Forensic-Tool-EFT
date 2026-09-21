"""Static Windows Portable Executable (PE32/PE32+) Binary Forensics Analyzer."""

from __future__ import annotations

import math
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from eft.models.pe_ole import (
    EntropyLevel,
    PEAnalysisReport,
    PEExportedFunction,
    PEImportedDLL,
    PEImportedFunction,
    PESectionAnalysis,
    SuspiciousAPICategory,
)
from eft.models.threat import RiskSeverity

# MITRE ATT&CK & DFIR Signature Map for Suspicious Windows API Calls
SUSPICIOUS_WINDOWS_APIS: Dict[str, Tuple[SuspiciousAPICategory, RiskSeverity, str]] = {
    # Process Injection / Hollowing / Memory Execution
    "virtualalloc": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.MALICIOUS_HIGH,
        "Allocates executable memory region",
    ),
    "virtualallocex": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.CRITICAL,
        "Allocates memory in a remote process (injection indicator)",
    ),
    "virtualprotect": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.MALICIOUS_HIGH,
        "Modifies memory page protection to executable (PAGE_EXECUTE_READWRITE)",
    ),
    "virtualprotectex": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.CRITICAL,
        "Modifies memory protection in a remote process",
    ),
    "writeprocessmemory": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.CRITICAL,
        "Writes payload directly into foreign process address space",
    ),
    "readprocessmemory": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.MALICIOUS_HIGH,
        "Reads foreign process memory (credential dumping/inspection)",
    ),
    "createremotethread": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.CRITICAL,
        "Executes thread inside a remote process (process injection)",
    ),
    "createremotethreadex": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.CRITICAL,
        "Executes remote thread with extended security attributes",
    ),
    "ntcreatethreadex": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.CRITICAL,
        "Low-level native API for unhooked remote thread creation",
    ),
    "queueuserapc": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.CRITICAL,
        "Queues APC to target thread (Early Bird / APC injection)",
    ),
    "setthreadcontext": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.CRITICAL,
        "Hijacks thread execution context / instruction pointer (process hollowing)",
    ),
    "getthreadcontext": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.MALICIOUS_HIGH,
        "Reads thread registers before context manipulation",
    ),
    "resumethread": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.MALICIOUS_HIGH,
        "Resumes suspended target process after payload injection",
    ),
    "ntunmapviewofsection": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.CRITICAL,
        "Unmaps original image from hollowed process space",
    ),
    "zwunmapviewofsection": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.CRITICAL,
        "Kernel unmap routine for process hollowing",
    ),
    "ntwritevirtualmemory": (
        SuspiciousAPICategory.PROCESS_INJECTION,
        RiskSeverity.CRITICAL,
        "Native kernel routine for writing into foreign memory",
    ),
    # Keylogging / Input Monitoring / Window Hooking
    "setwindowshookexa": (
        SuspiciousAPICategory.KEYLOGGING_HOOK,
        RiskSeverity.MALICIOUS_HIGH,
        "Installs system-wide keyboard/mouse hook (keylogger indicator)",
    ),
    "setwindowshookexw": (
        SuspiciousAPICategory.KEYLOGGING_HOOK,
        RiskSeverity.MALICIOUS_HIGH,
        "Installs system-wide keyboard/mouse hook (Unicode)",
    ),
    "getasynckeystate": (
        SuspiciousAPICategory.KEYLOGGING_HOOK,
        RiskSeverity.MALICIOUS_HIGH,
        "Polls keyboard state asynchronously (polling keylogger)",
    ),
    "getkeystate": (
        SuspiciousAPICategory.KEYLOGGING_HOOK,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Reads status of specific virtual key",
    ),
    "registerhotkey": (
        SuspiciousAPICategory.KEYLOGGING_HOOK,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Registers global system key combinations",
    ),
    "attachthreadinput": (
        SuspiciousAPICategory.KEYLOGGING_HOOK,
        RiskSeverity.MALICIOUS_HIGH,
        "Attaches input processing mechanism across threads",
    ),
    # Anti-Debugging / Sandbox Evasion
    "isdebuggerpresent": (
        SuspiciousAPICategory.ANTI_DEBUG_EVASION,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Checks PEB BeingDebugged flag to evade analysis",
    ),
    "checkremotedebuggerpresent": (
        SuspiciousAPICategory.ANTI_DEBUG_EVASION,
        RiskSeverity.MALICIOUS_HIGH,
        "Checks kernel debugger attachment via ProcessDebugPort",
    ),
    "ntqueryinformationprocess": (
        SuspiciousAPICategory.ANTI_DEBUG_EVASION,
        RiskSeverity.MALICIOUS_HIGH,
        "Queries ProcessDebugPort / ProcessDebugFlags / ProcessDebugObjectHandle",
    ),
    "outputdebugstringa": (
        SuspiciousAPICategory.ANTI_DEBUG_EVASION,
        RiskSeverity.SUSPICIOUS_LOW,
        "Sends debug string / probes for active debugger exception handling",
    ),
    "outputdebugstringw": (
        SuspiciousAPICategory.ANTI_DEBUG_EVASION,
        RiskSeverity.SUSPICIOUS_LOW,
        "Sends debug string (Unicode)",
    ),
    "findwindowa": (
        SuspiciousAPICategory.ANTI_DEBUG_EVASION,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Searches for known forensic tool windows (Wireshark, x64dbg, IDA)",
    ),
    "findwindoww": (
        SuspiciousAPICategory.ANTI_DEBUG_EVASION,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Searches for analysis tools (Unicode)",
    ),
    "gettickcount": (
        SuspiciousAPICategory.ANTI_DEBUG_EVASION,
        RiskSeverity.SUSPICIOUS_LOW,
        "Calculates elapsed time to detect human analyst stepping",
    ),
    "queryperformancecounter": (
        SuspiciousAPICategory.ANTI_DEBUG_EVASION,
        RiskSeverity.SUSPICIOUS_LOW,
        "High-resolution timer used for anti-emulation sleeps",
    ),
    "timegettime": (
        SuspiciousAPICategory.ANTI_DEBUG_EVASION,
        RiskSeverity.SUSPICIOUS_LOW,
        "Multimedia timer used for sandbox sleep acceleration evasion",
    ),
    # Execution / Dropper Payloads
    "winexec": (
        SuspiciousAPICategory.EXECUTION_DROPPER,
        RiskSeverity.MALICIOUS_HIGH,
        "Legacy Win32 API to execute command lines and dropped payloads",
    ),
    "shellexecutea": (
        SuspiciousAPICategory.EXECUTION_DROPPER,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Executes external application or document",
    ),
    "shellexecutew": (
        SuspiciousAPICategory.EXECUTION_DROPPER,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Executes application (Unicode)",
    ),
    "shellexecuteexa": (
        SuspiciousAPICategory.EXECUTION_DROPPER,
        RiskSeverity.MALICIOUS_HIGH,
        "Executes application with elevated UAC privileges",
    ),
    "shellexecuteexw": (
        SuspiciousAPICategory.EXECUTION_DROPPER,
        RiskSeverity.MALICIOUS_HIGH,
        "Executes application with elevated privileges (Unicode)",
    ),
    "createprocessa": (
        SuspiciousAPICategory.EXECUTION_DROPPER,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Creates child process in suspended or active state",
    ),
    "createprocessw": (
        SuspiciousAPICategory.EXECUTION_DROPPER,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Creates child process (Unicode)",
    ),
    "createprocessasusera": (
        SuspiciousAPICategory.EXECUTION_DROPPER,
        RiskSeverity.MALICIOUS_HIGH,
        "Spawns child process in another user's security token context",
    ),
    "createprocessasuserw": (
        SuspiciousAPICategory.EXECUTION_DROPPER,
        RiskSeverity.MALICIOUS_HIGH,
        "Spawns process under another security token (Unicode)",
    ),
    # Network / C2 Communication / Downloader
    "internetopena": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.MALICIOUS_HIGH,
        "Initializes WinINet HTTP/FTP session for C2 communication",
    ),
    "internetopenw": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.MALICIOUS_HIGH,
        "Initializes WinINet session (Unicode)",
    ),
    "internetopenurla": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.MALICIOUS_HIGH,
        "Connects to remote URL to fetch secondary payload",
    ),
    "internetopenurlw": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.MALICIOUS_HIGH,
        "Connects to URL to fetch payload (Unicode)",
    ),
    "httpopenrequesta": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.MALICIOUS_HIGH,
        "Creates HTTP request for beaconing or exfiltration",
    ),
    "httpopenrequestw": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.MALICIOUS_HIGH,
        "Creates HTTP request (Unicode)",
    ),
    "httpsendrequesta": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.MALICIOUS_HIGH,
        "Transmits HTTP payload to remote C2 server",
    ),
    "httpsendrequestw": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.MALICIOUS_HIGH,
        "Transmits HTTP request (Unicode)",
    ),
    "urldownloadtofilea": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.CRITICAL,
        "Downloads remote executable file directly to local disk (dropper)",
    ),
    "urldownloadtofilew": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.CRITICAL,
        "Downloads remote file to disk (Unicode dropper)",
    ),
    "wsastartup": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Initializes Winsock network subsystem",
    ),
    "socket": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Creates raw network socket for C2 channel",
    ),
    "connect": (
        SuspiciousAPICategory.NETWORK_C2,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Establishes socket connection to remote IP",
    ),
    # Persistence / Privilege Escalation
    "regsetvalueexa": (
        SuspiciousAPICategory.PERSISTENCE_PRIVILEGE,
        RiskSeverity.MALICIOUS_HIGH,
        "Modifies registry run keys for persistence (HKLM/HKCU Run)",
    ),
    "regsetvalueexw": (
        SuspiciousAPICategory.PERSISTENCE_PRIVILEGE,
        RiskSeverity.MALICIOUS_HIGH,
        "Modifies registry persistence keys (Unicode)",
    ),
    "regcreatekeyexa": (
        SuspiciousAPICategory.PERSISTENCE_PRIVILEGE,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Creates new registry subkeys",
    ),
    "regcreatekeyexw": (
        SuspiciousAPICategory.PERSISTENCE_PRIVILEGE,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Creates registry keys (Unicode)",
    ),
    "openscmanagera": (
        SuspiciousAPICategory.PERSISTENCE_PRIVILEGE,
        RiskSeverity.MALICIOUS_HIGH,
        "Connects to Windows Service Control Manager to install persistence services",
    ),
    "createservicea": (
        SuspiciousAPICategory.PERSISTENCE_PRIVILEGE,
        RiskSeverity.CRITICAL,
        "Creates Windows system service (rootkit/persistence indicator)",
    ),
    "createservicew": (
        SuspiciousAPICategory.PERSISTENCE_PRIVILEGE,
        RiskSeverity.CRITICAL,
        "Creates Windows system service (Unicode)",
    ),
    "adjusttokenprivileges": (
        SuspiciousAPICategory.PERSISTENCE_PRIVILEGE,
        RiskSeverity.MALICIOUS_HIGH,
        "Enables sensitive token privileges (SeDebugPrivilege / SeShutdownPrivilege)",
    ),
    "lookupprivilegevaluea": (
        SuspiciousAPICategory.PERSISTENCE_PRIVILEGE,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Resolves LUID for privilege escalation",
    ),
    "lookupprivilegevaluew": (
        SuspiciousAPICategory.PERSISTENCE_PRIVILEGE,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Resolves privilege LUID (Unicode)",
    ),
    # Ransomware / Cryptography
    "cryptencrypt": (
        SuspiciousAPICategory.RANSOMWARE_CRYPTO,
        RiskSeverity.MALICIOUS_HIGH,
        "Encrypts data blocks (potential ransomware encryption loop)",
    ),
    "cryptdecrypt": (
        SuspiciousAPICategory.RANSOMWARE_CRYPTO,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Decrypts encrypted configuration or payload",
    ),
    "cryptgenkey": (
        SuspiciousAPICategory.RANSOMWARE_CRYPTO,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Generates cryptographic key pair for file encryption",
    ),
    "cryptacquirecontexta": (
        SuspiciousAPICategory.RANSOMWARE_CRYPTO,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Initializes CryptoAPI Cryptographic Service Provider (CSP)",
    ),
    "cryptacquirecontextw": (
        SuspiciousAPICategory.RANSOMWARE_CRYPTO,
        RiskSeverity.SUSPICIOUS_MEDIUM,
        "Initializes CryptoAPI CSP (Unicode)",
    ),
    "bcryptencrypt": (
        SuspiciousAPICategory.RANSOMWARE_CRYPTO,
        RiskSeverity.MALICIOUS_HIGH,
        "CNG modern API to encrypt data stream (ransomware indicator)",
    ),
}

KNOWN_PACKER_SECTION_NAMES = {
    "upx0",
    "upx1",
    "upx2",
    ".aspack",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    ".themida",
    ".enigma",
    ".petite",
    ".pack",
    "pecompact2",
    "fsg!",
    ".mpress1",
    ".mpress2",
    "mew",
    ".ndata",
    "nsp0",
    "nsp1",
    "pec1",
    "pec2",
    "tsu",
    ".ccg",
    "yoda",
    "packman",
}


def calculate_shannon_entropy(data: bytes) -> float:
    r"""Compute Shannon entropy $H = -\sum p(x) \log_2 p(x)$ for a byte stream."""
    if not data:
        return 0.0
    total = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1

    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def classify_entropy(entropy: float) -> EntropyLevel:
    """Classify entropy value into standard forensic density tiers."""
    if entropy < 5.0:
        return EntropyLevel.VERY_LOW
    if entropy <= 6.8:
        return EntropyLevel.NORMAL
    if entropy <= 7.2:
        return EntropyLevel.HIGH
    return EntropyLevel.PACKED_OR_ENCRYPTED


class PEBinaryAnalyzer:
    """Pure-Python Windows PE32 / PE32+ static binary forensics analyzer."""

    MACHINE_TYPES: Dict[int, str] = {
        0x014C: "PE32 (32-bit x86)",
        0x8664: "PE32+ (64-bit AMD64)",
        0x01C0: "ARM Little-Endian",
        0xAA64: "ARM64 Little-Endian",
        0x0200: "Intel Itanium (IA-64)",
        0x5032: "RISC-V 32-bit",
        0x5064: "RISC-V 64-bit",
    }

    SUBSYSTEM_MAP: Dict[int, str] = {
        1: "Native / Device Driver",
        2: "Windows GUI",
        3: "Windows CUI (Console Application)",
        7: "POSIX CUI",
        9: "Windows CE GUI",
        10: "EFI Application",
        11: "EFI Boot Service Driver",
        12: "EFI Runtime Driver",
        13: "EFI ROM",
        14: "Xbox",
    }

    def analyze(self, data_or_path: Union[bytes, str, Path]) -> PEAnalysisReport:
        """Perform deep static inspection of a Windows PE binary."""
        if isinstance(data_or_path, (str, Path)):
            with open(data_or_path, "rb") as f:
                data = f.read()
        else:
            data = data_or_path

        if len(data) < 64:
            return PEAnalysisReport(
                is_valid_pe=False,
                forensic_alerts=["File size smaller than minimum DOS header (64 bytes)"],
                threat_score=0.0,
                verdict="BENIGN",
            )

        # Check DOS magic
        if data[:2] != b"MZ":
            return PEAnalysisReport(
                is_valid_pe=False,
                forensic_alerts=["Missing DOS signature (b'MZ') at offset 0x0"],
                threat_score=0.0,
                verdict="BENIGN",
            )

        # Read e_lfanew offset to PE Header
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data):
            return PEAnalysisReport(
                is_valid_pe=False,
                forensic_alerts=[
                    f"Invalid e_lfanew offset ({hex(e_lfanew)}) pointing beyond file bounds"
                ],
                threat_score=20.0,
                verdict="SUSPICIOUS",
            )

        # Verify PE Signature (PE\0\0)
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return PEAnalysisReport(
                is_valid_pe=False,
                forensic_alerts=[f"Missing PE signature (b'PE\\0\\0') at offset {hex(e_lfanew)}"],
                threat_score=15.0,
                verdict="SUSPICIOUS",
            )

        # Parse COFF File Header (20 bytes at e_lfanew + 4)
        coff_offset = e_lfanew + 4
        (
            machine,
            num_sections,
            time_date_stamp,
            _ptr_sym,
            _num_sym,
            size_opt_hdr,
            characteristics,
        ) = struct.unpack_from("<HHIIIHH", data, coff_offset)

        arch_name = self.MACHINE_TYPES.get(machine, f"Unknown Architecture ({hex(machine)})")
        is_dll = bool(characteristics & 0x2000)

        # Timestamp Parsing & Forensic Anomaly Check
        comp_time = None
        is_timestamp_suspicious = False
        forensic_alerts: List[str] = []

        try:
            comp_time = datetime.fromtimestamp(time_date_stamp, tz=timezone.utc)
            now_year = datetime.now(timezone.utc).year
            if comp_time.year < 1980 or comp_time.year > now_year + 1:
                is_timestamp_suspicious = True
                forensic_alerts.append(
                    f"Suspicious compilation timestamp: {comp_time.isoformat()} (timestomping indicator)"
                )
        except (ValueError, OSError, OverflowError):
            is_timestamp_suspicious = True
            forensic_alerts.append(
                f"Invalid/corrupt compilation timestamp epoch value ({time_date_stamp})"
            )

        # Parse Optional Header
        opt_hdr_offset = coff_offset + 20
        is_64bit = False
        entry_point_rva = 0
        image_base = 0
        subsystem_id = 0
        dll_characteristics = 0
        data_dirs: List[Tuple[int, int]] = []  # (RVA, Size)

        if size_opt_hdr >= 2:
            opt_magic = struct.unpack_from("<H", data, opt_hdr_offset)[0]
            if opt_magic == 0x20B:  # PE32+ (64-bit)
                is_64bit = True
                arch_name = "PE32+ (64-bit AMD64)" if machine == 0x8664 else arch_name
                if size_opt_hdr >= 112:
                    entry_point_rva = struct.unpack_from("<I", data, opt_hdr_offset + 16)[0]
                    image_base = struct.unpack_from("<Q", data, opt_hdr_offset + 24)[0]
                    subsystem_id = struct.unpack_from("<H", data, opt_hdr_offset + 68)[0]
                    dll_characteristics = struct.unpack_from("<H", data, opt_hdr_offset + 70)[0]
                    num_rvas = struct.unpack_from("<I", data, opt_hdr_offset + 108)[0]
                    dd_offset = opt_hdr_offset + 112
                    for i in range(min(num_rvas, 16)):
                        if dd_offset + (i * 8) + 8 <= len(data):
                            rva, sz = struct.unpack_from("<II", data, dd_offset + (i * 8))
                            data_dirs.append((rva, sz))
            elif opt_magic == 0x10B:  # PE32 (32-bit)
                is_64bit = False
                arch_name = "PE32 (32-bit x86)" if machine == 0x014C else arch_name
                if size_opt_hdr >= 96:
                    entry_point_rva = struct.unpack_from("<I", data, opt_hdr_offset + 16)[0]
                    image_base = struct.unpack_from("<I", data, opt_hdr_offset + 28)[0]
                    subsystem_id = struct.unpack_from("<H", data, opt_hdr_offset + 68)[0]
                    dll_characteristics = struct.unpack_from("<H", data, opt_hdr_offset + 70)[0]
                    num_rvas = struct.unpack_from("<I", data, opt_hdr_offset + 92)[0]
                    dd_offset = opt_hdr_offset + 96
                    for i in range(min(num_rvas, 16)):
                        if dd_offset + (i * 8) + 8 <= len(data):
                            rva, sz = struct.unpack_from("<II", data, dd_offset + (i * 8))
                            data_dirs.append((rva, sz))

        subsystem_str = self.SUBSYSTEM_MAP.get(subsystem_id, f"Unknown Subsystem ({subsystem_id})")
        is_driver = subsystem_id == 1

        # Mitigations
        has_aslr = bool(dll_characteristics & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        has_dep_nx = bool(dll_characteristics & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        has_cfg = bool(dll_characteristics & 0x4000)  # IMAGE_DLLCHARACTERISTICS_GUARD_CF
        has_seh = not bool(dll_characteristics & 0x0400)  # IMAGE_DLLCHARACTERISTICS_NO_SEH

        # Digital Signature Check (Data Directory index 4 = Security/Certificate Table)
        has_digital_signature = False
        signature_size = 0
        if len(data_dirs) > 4:
            _cert_offset, cert_size = data_dirs[4]
            if cert_size > 0:
                has_digital_signature = True
                signature_size = cert_size

        # .NET Check (Data Directory index 14 = CLR Runtime Header)
        is_dotnet = False
        if len(data_dirs) > 14:
            clr_rva, clr_size = data_dirs[14]
            if clr_rva > 0 and clr_size > 0:
                is_dotnet = True

        # Parse Section Headers (40 bytes each)
        section_tbl_offset = opt_hdr_offset + size_opt_hdr
        sections: List[PESectionAnalysis] = []
        packing_reasons: List[str] = []
        detected_packers: List[str] = []

        for i in range(num_sections):
            sec_offset = section_tbl_offset + (i * 40)
            if sec_offset + 40 > len(data):
                forensic_alerts.append(f"Section table truncated at index {i}")
                break

            name_raw = data[sec_offset : sec_offset + 8]
            name_str = name_raw.split(b"\x00")[0].decode("latin-1", errors="replace").strip()

            (
                virt_size,
                virt_addr,
                raw_size,
                raw_offset,
                _ptr_reloc,
                _ptr_line,
                _num_reloc,
                _num_line,
                sec_char,
            ) = struct.unpack_from("<IIIIIIHHI", data, sec_offset + 8)

            # Extract raw section slice & calculate Shannon entropy
            sec_slice = data[
                raw_offset : raw_offset + min(raw_size, max(0, len(data) - raw_offset))
            ]
            sec_entropy = calculate_shannon_entropy(sec_slice)
            sec_entropy_tier = classify_entropy(sec_entropy)

            is_exec = bool(sec_char & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
            is_read = bool(sec_char & 0x40000000)  # IMAGE_SCN_MEM_READ
            is_write = bool(sec_char & 0x80000000)  # IMAGE_SCN_MEM_WRITE
            is_uninit = bool(sec_char & 0x00000080)  # IMAGE_SCN_CNT_UNINITIALIZED_DATA
            is_wx = is_exec and is_write

            sec_suspicious_flags: List[str] = []
            if is_wx:
                sec_suspicious_flags.append("WX (Writable & Executable) memory section detected")
                forensic_alerts.append(
                    f"Section '{name_str}' is WX (Writable + Executable) - possible unpacking stub or payload injection"
                )

            if sec_entropy >= 7.2:
                sec_suspicious_flags.append(
                    f"High entropy ({sec_entropy:.2f}) indicates encrypted or compressed code/data"
                )

            # Known packer section name check
            norm_name = name_str.lower().strip()
            if norm_name in KNOWN_PACKER_SECTION_NAMES:
                packer_tag = "UPX" if "upx" in norm_name else norm_name.upper()
                if packer_tag not in detected_packers:
                    detected_packers.append(packer_tag)
                packing_reasons.append(f"Identified known packer section name: '{name_str}'")

            # Virtual size >> Raw size heuristic (e.g. UPX0 section with raw_size=0, virt_size > 0)
            if virt_size > 0 and raw_size == 0 and is_exec:
                packing_reasons.append(
                    f"Section '{name_str}' has 0 raw bytes on disk but expands to {virt_size} bytes in memory"
                )

            sections.append(
                PESectionAnalysis(
                    name=name_str,
                    virtual_address=virt_addr,
                    virtual_size=virt_size,
                    raw_data_offset=raw_offset,
                    raw_data_size=raw_size,
                    entropy=sec_entropy,
                    entropy_level=sec_entropy_tier,
                    is_executable=is_exec,
                    is_readable=is_read,
                    is_writable=is_write,
                    is_wx=is_wx,
                    is_uninitialized_data=is_uninit,
                    suspicious_flags=sec_suspicious_flags,
                )
            )

        # Calculate Overall File Entropy
        overall_entropy = calculate_shannon_entropy(data)
        overall_entropy_tier = classify_entropy(overall_entropy)

        if overall_entropy >= 7.2 and not detected_packers:
            packing_reasons.append(
                f"Overall binary Shannon entropy ({overall_entropy:.2f}) exceeds packed/encrypted threshold (7.2)"
            )

        is_packed = len(packing_reasons) > 0 or len(detected_packers) > 0

        # Helper function to map RVA to File Offset
        def rva_to_file_offset(rva: int) -> Optional[int]:
            for sec in sections:
                if (
                    sec.virtual_address
                    <= rva
                    < sec.virtual_address + max(sec.virtual_size, sec.raw_data_size)
                ):
                    offset = sec.raw_data_offset + (rva - sec.virtual_address)
                    if 0 <= offset < len(data):
                        return offset
            return None

        # Helper to read null-terminated ASCII string
        def read_cstring(offset: int, max_len: int = 256) -> str:
            end = data.find(b"\x00", offset, offset + max_len)
            if end == -1:
                end = min(len(data), offset + max_len)
            return data[offset:end].decode("latin-1", errors="replace")

        # Parse Import Table (Data Directory index 1 = Import Table)
        imported_dlls: List[PEImportedDLL] = []
        suspicious_apis: List[PEImportedFunction] = []

        if len(data_dirs) > 1:
            import_rva, import_size = data_dirs[1]
            if import_rva > 0:
                import_offset = rva_to_file_offset(import_rva)
                if import_offset is not None:
                    curr_desc_offset = import_offset
                    while curr_desc_offset + 20 <= len(data):
                        (
                            orig_first_thunk,
                            _time_stamp,
                            _fwd_chain,
                            name_rva,
                            first_thunk,
                        ) = struct.unpack_from("<IIIII", data, curr_desc_offset)

                        if orig_first_thunk == 0 and first_thunk == 0 and name_rva == 0:
                            break  # End of import descriptor array

                        curr_desc_offset += 20
                        dll_name_offset = rva_to_file_offset(name_rva)
                        if dll_name_offset is None:
                            continue

                        dll_name = read_cstring(dll_name_offset)
                        thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
                        thunk_offset = rva_to_file_offset(thunk_rva)
                        if thunk_offset is None:
                            continue

                        dll_funcs: List[PEImportedFunction] = []
                        curr_thunk = thunk_offset

                        while True:
                            if is_64bit:
                                if curr_thunk + 8 > len(data):
                                    break
                                thunk_val = struct.unpack_from("<Q", data, curr_thunk)[0]
                                curr_thunk += 8
                                if thunk_val == 0:
                                    break
                                is_ordinal = bool(thunk_val & 0x8000000000000000)
                                fn_ordinal = thunk_val & 0xFFFF if is_ordinal else None
                                fn_name_rva = (
                                    thunk_val & 0x7FFFFFFFFFFFFFFF if not is_ordinal else 0
                                )
                            else:
                                if curr_thunk + 4 > len(data):
                                    break
                                thunk_val = struct.unpack_from("<I", data, curr_thunk)[0]
                                curr_thunk += 4
                                if thunk_val == 0:
                                    break
                                is_ordinal = bool(thunk_val & 0x80000000)
                                fn_ordinal = thunk_val & 0xFFFF if is_ordinal else None
                                fn_name_rva = thunk_val & 0x7FFFFFFF if not is_ordinal else 0

                            func_name = ""
                            if is_ordinal:
                                func_name = f"Ordinal_{fn_ordinal}"
                            else:
                                ib_offset = rva_to_file_offset(fn_name_rva)
                                if ib_offset is not None and ib_offset + 2 < len(data):
                                    func_name = read_cstring(ib_offset + 2)

                            if func_name:
                                norm_fn = func_name.lower().strip()
                                is_susp = norm_fn in SUSPICIOUS_WINDOWS_APIS
                                susp_cat = None
                                threat_sev = RiskSeverity.CLEAN
                                desc = None

                                if is_susp:
                                    susp_cat, threat_sev, desc = SUSPICIOUS_WINDOWS_APIS[norm_fn]

                                imported_fn = PEImportedFunction(
                                    function_name=func_name,
                                    ordinal=fn_ordinal,
                                    dll_name=dll_name,
                                    is_suspicious=is_susp,
                                    suspicious_category=susp_cat,
                                    threat_severity=threat_sev,
                                    description=desc,
                                )
                                dll_funcs.append(imported_fn)
                                if is_susp:
                                    suspicious_apis.append(imported_fn)

                        susp_count = sum(1 for f in dll_funcs if f.is_suspicious)
                        imported_dlls.append(
                            PEImportedDLL(
                                dll_name=dll_name,
                                functions=dll_funcs,
                                suspicious_function_count=susp_count,
                            )
                        )

        # Parse Export Table (Data Directory index 0 = Export Table)
        exports: List[PEExportedFunction] = []
        exported_dll_name = None

        if len(data_dirs) > 0:
            export_rva, _export_size = data_dirs[0]
            if export_rva > 0:
                export_offset = rva_to_file_offset(export_rva)
                if export_offset is not None and export_offset + 40 <= len(data):
                    (
                        _exp_char,
                        _exp_time,
                        _exp_maj,
                        _exp_min,
                        exp_name_rva,
                        exp_base,
                        _num_funcs,
                        num_names,
                        _funcs_rva,
                        names_rva,
                        ordinals_rva,
                    ) = struct.unpack_from("<IIHHIIIIIII", data, export_offset)

                    name_off = rva_to_file_offset(exp_name_rva)
                    if name_off is not None:
                        exported_dll_name = read_cstring(name_off)

                    names_offset = rva_to_file_offset(names_rva)
                    ordinals_offset = rva_to_file_offset(ordinals_rva)

                    if names_offset is not None and ordinals_offset is not None:
                        for idx in range(min(num_names, 256)):
                            if names_offset + (idx * 4) + 4 <= len(data) and ordinals_offset + (
                                idx * 2
                            ) + 2 <= len(data):
                                fn_name_rva = struct.unpack_from(
                                    "<I", data, names_offset + (idx * 4)
                                )[0]
                                fn_ord = (
                                    struct.unpack_from("<H", data, ordinals_offset + (idx * 2))[0]
                                    + exp_base
                                )
                                fn_str_offset = rva_to_file_offset(fn_name_rva)
                                fn_name = (
                                    read_cstring(fn_str_offset)
                                    if fn_str_offset is not None
                                    else f"Export_{fn_ord}"
                                )
                                exports.append(
                                    PEExportedFunction(
                                        function_name=fn_name,
                                        ordinal=fn_ord,
                                        rva=fn_name_rva,
                                    )
                                )

        # Threat Scoring & Heuristic Verdict
        threat_score = 0.0

        if is_packed:
            threat_score += 35.0
            forensic_alerts.append(
                f"Binary detected as packed or crypter-obfuscated ({', '.join(detected_packers or ['High Entropy'])})"
            )

        # Flag WX Sections
        wx_count = sum(1 for s in sections if s.is_wx)
        if wx_count > 0:
            threat_score += 25.0

        # Suspicious API threat accumulation
        seen_categories = set()
        for api in suspicious_apis:
            if api.suspicious_category:
                seen_categories.add(api.suspicious_category)
            if api.threat_severity == RiskSeverity.CRITICAL:
                threat_score += 15.0
            elif api.threat_severity == RiskSeverity.MALICIOUS_HIGH:
                threat_score += 8.0
            elif api.threat_severity == RiskSeverity.SUSPICIOUS_MEDIUM:
                threat_score += 4.0

        if SuspiciousAPICategory.PROCESS_INJECTION in seen_categories:
            threat_score += 15.0
            forensic_alerts.append(
                "Process Injection / Hollowing API capabilities detected (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)"
            )

        if SuspiciousAPICategory.KEYLOGGING_HOOK in seen_categories:
            threat_score += 12.0
            forensic_alerts.append(
                "Keylogging / Input capture APIs detected (SetWindowsHookEx, GetAsyncKeyState)"
            )

        if (
            SuspiciousAPICategory.NETWORK_C2 in seen_categories
            and SuspiciousAPICategory.EXECUTION_DROPPER in seen_categories
        ):
            threat_score += 15.0
            forensic_alerts.append("Combined Network C2 + Execution Dropper capabilities detected")

        if is_timestamp_suspicious:
            threat_score += 10.0

        # Absence of modern mitigations (ASLR / DEP) on non-driver binaries
        if not is_driver and not has_aslr and not has_dep_nx:
            threat_score += 10.0
            forensic_alerts.append(
                "Binary lacks modern exploit mitigations (Missing ASLR and DEP/NX)"
            )

        # Low import anomaly (classic packer behavior)
        if (
            len(imported_dlls) == 1
            and len(imported_dlls[0].functions) <= 3
            and overall_entropy > 6.5
        ):
            threat_score += 15.0
            forensic_alerts.append(
                "Anomalously sparse import table with high entropy (classic packer import stub)"
            )

        threat_score = min(100.0, round(threat_score, 1))

        verdict = "BENIGN"
        if threat_score >= 65.0:
            verdict = "MALICIOUS"
        elif threat_score >= 30.0:
            verdict = "SUSPICIOUS"

        return PEAnalysisReport(
            is_valid_pe=True,
            architecture=arch_name,
            machine_type_hex=hex(machine),
            compilation_timestamp=comp_time,
            is_timestamp_suspicious=is_timestamp_suspicious,
            entry_point_rva=entry_point_rva,
            image_base=image_base,
            subsystem=subsystem_str,
            is_dll=is_dll,
            is_driver=is_driver,
            is_dotnet=is_dotnet,
            has_aslr=has_aslr,
            has_dep_nx=has_dep_nx,
            has_cfg=has_cfg,
            has_seh=has_seh,
            has_digital_signature=has_digital_signature,
            signature_size=signature_size,
            section_count=len(sections),
            sections=sections,
            overall_entropy=overall_entropy,
            overall_entropy_level=overall_entropy_tier,
            is_packed=is_packed,
            packing_reasons=packing_reasons,
            detected_packers=detected_packers,
            imports=imported_dlls,
            suspicious_apis=suspicious_apis,
            exports=exports,
            exported_dll_name=exported_dll_name,
            forensic_alerts=forensic_alerts,
            threat_score=threat_score,
            verdict=verdict,
        )
