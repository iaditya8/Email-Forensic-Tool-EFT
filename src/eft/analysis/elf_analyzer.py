"""Static Linux/Unix ELF (Executable and Linkable Format) Binary Forensics Analyzer."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from eft.analysis.pe_analyzer import calculate_shannon_entropy, classify_entropy
from eft.models.pe_ole import (
    ELFAnalysisReport,
    ELFSectionAnalysis,
)
from eft.models.threat import RiskSeverity

# ELF OS ABI mappings
ELF_OSABI_MAP: Dict[int, str] = {
    0: "UNIX - System V",
    1: "HP-UX",
    2: "NetBSD",
    3: "Linux",
    6: "Solaris",
    7: "AIX",
    8: "IRIX",
    9: "FreeBSD",
    12: "OpenBSD",
}

# ELF Machine Architecture mappings
ELF_MACHINE_MAP: Dict[int, str] = {
    0x00: "No specific instruction set",
    0x02: "SPARC",
    0x03: "x86 (Intel 80386)",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x16: "IBM S/390",
    0x28: "ARM (32-bit)",
    0x2A: "SuperH",
    0x32: "IA-64 (Intel Itanium)",
    0x3E: "AMD64 / x86-64",
    0xB7: "AArch64 / ARM64",
    0xF3: "RISC-V",
}

# ELF File Type mappings
ELF_TYPE_MAP: Dict[int, str] = {
    1: "Relocatable file (ET_REL)",
    2: "Executable binary (ET_EXEC)",
    3: "Shared object / Dynamic library (ET_DYN)",
    4: "Core dump file (ET_CORE)",
}

# Section Type mappings
ELF_SHT_MAP: Dict[int, str] = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    10: "SHLIB",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    0x6FFFFFF6: "GNU_HASH",
    0x6FFFFFFE: "GNU_verneed",
    0x6FFFFFFF: "GNU_versym",
}

# Suspicious Linux APIs for DFIR threat scoring
SUSPICIOUS_LINUX_SYMBOLS: Dict[str, Tuple[str, RiskSeverity, float]] = {
    "ptrace": ("Anti-debugging / Process injection hook", RiskSeverity.MALICIOUS_HIGH, 25.0),
    "process_vm_writev": ("Cross-process memory injection", RiskSeverity.CRITICAL, 35.0),
    "process_vm_readv": ("Cross-process memory inspection", RiskSeverity.MALICIOUS_HIGH, 20.0),
    "mprotect": ("Memory page permission alteration (W+X)", RiskSeverity.SUSPICIOUS_MEDIUM, 15.0),
    "memfd_create": ("Fileless anonymous memory payload execution", RiskSeverity.CRITICAL, 35.0),
    "execve": ("Direct process spawning / payload execution", RiskSeverity.SUSPICIOUS_MEDIUM, 15.0),
    "execveat": ("Descriptor-based payload execution", RiskSeverity.MALICIOUS_HIGH, 20.0),
    "system": ("Command shell execution", RiskSeverity.SUSPICIOUS_MEDIUM, 15.0),
    "socket": ("Network socket creation", RiskSeverity.CLEAN, 5.0),
    "connect": ("Remote network socket connection", RiskSeverity.CLEAN, 5.0),
    "bind": ("Network socket port listening / backdoor", RiskSeverity.SUSPICIOUS_MEDIUM, 10.0),
    "fork": ("Process replication / daemonization", RiskSeverity.CLEAN, 5.0),
    "clone": ("Thread / process container creation", RiskSeverity.CLEAN, 5.0),
    "dlopen": ("Dynamic library runtime loading (evasion)", RiskSeverity.SUSPICIOUS_MEDIUM, 10.0),
    "dlsym": ("Dynamic symbol lookup (evasion)", RiskSeverity.SUSPICIOUS_MEDIUM, 10.0),
}


class ELFBinaryAnalyzer:
    """Pure Python Linux & Unix Executable and Linkable Format (ELF32/ELF64) Static Analyzer."""

    def analyze(
        self,
        data_or_path: Union[bytes, str, Path],
    ) -> ELFAnalysisReport:
        """Perform deep static inspection on ELF binary bytes or file path."""
        if isinstance(data_or_path, (str, Path)):
            with open(data_or_path, "rb") as f:
                data = f.read()
        else:
            data = data_or_path

        if not data.startswith(b"\x7fELF") or len(data) < 52:
            return ELFAnalysisReport(
                is_valid_elf=False,
                architecture="Invalid / Non-ELF Binary",
                threat_score=0.0,
                verdict="BENIGN",
            )

        ei_class_byte = data[4]
        is_64bit = ei_class_byte == 2
        ei_class_str = "64-bit" if is_64bit else "32-bit"

        ei_data_byte = data[5]
        is_little_endian = ei_data_byte == 1
        endian = "<" if is_little_endian else ">"
        endian_str = "Little-Endian" if is_little_endian else "Big-Endian"

        os_abi_byte = data[7]
        os_abi_str = ELF_OSABI_MAP.get(os_abi_byte, f"Unknown (0x{os_abi_byte:02X})")

        # Unpack ELF Header
        try:
            if is_64bit:
                if len(data) < 64:
                    raise ValueError("ELF data truncated for 64-bit header")
                (
                    e_type,
                    e_machine,
                    e_version,
                    e_entry,
                    e_phoff,
                    e_shoff,
                    e_flags,
                    e_ehsize,
                    e_phentsize,
                    e_phnum,
                    e_shentsize,
                    e_shnum,
                    e_shstrndx,
                ) = struct.unpack_from(f"{endian}HHIQQQIHHHHHH", data, 16)
            else:
                (
                    e_type,
                    e_machine,
                    e_version,
                    e_entry,
                    e_phoff,
                    e_shoff,
                    e_flags,
                    e_ehsize,
                    e_phentsize,
                    e_phnum,
                    e_shentsize,
                    e_shnum,
                    e_shstrndx,
                ) = struct.unpack_from(f"{endian}HHIIIIIHHHHHH", data, 16)
        except Exception:
            return ELFAnalysisReport(
                is_valid_elf=False,
                architecture=f"Corrupted ELF ({ei_class_str})",
                threat_score=30.0,
                verdict="SUSPICIOUS",
                forensic_alerts=["Malformed or truncated ELF header structure"],
            )

        machine_name = ELF_MACHINE_MAP.get(e_machine, f"Machine 0x{e_machine:04X}")
        file_type_str = ELF_TYPE_MAP.get(e_type, f"Type 0x{e_type:04X}")
        arch_str = f"ELF{64 if is_64bit else 32} ({machine_name})"

        # Overall entropy
        overall_entropy = calculate_shannon_entropy(data)
        overall_entropy_level = classify_entropy(overall_entropy)

        forensic_alerts: List[str] = []
        detected_packers: List[str] = []
        is_packed = False
        threat_score = 0.0

        # Read Section Headers and Section Header String Table
        sections: List[ELFSectionAnalysis] = []
        shstrtab_data = b""

        # Extract shstrtab data if valid
        if 0 <= e_shstrndx < e_shnum and e_shoff > 0 and e_shentsize > 0:
            strtab_hdr_offset = e_shoff + e_shstrndx * e_shentsize
            if strtab_hdr_offset + e_shentsize <= len(data):
                if is_64bit:
                    _, _, _, _, strtab_offset, strtab_size, _, _, _, _ = struct.unpack_from(
                        f"{endian}IIQQQQIIQQ", data, strtab_hdr_offset
                    )
                else:
                    _, _, _, _, strtab_offset, strtab_size, _, _, _, _ = struct.unpack_from(
                        f"{endian}IIIIIIIIII", data, strtab_hdr_offset
                    )
                if strtab_offset + strtab_size <= len(data):
                    shstrtab_data = data[strtab_offset : strtab_offset + strtab_size]

        def get_sh_name(name_offset: int) -> str:
            if not shstrtab_data or name_offset >= len(shstrtab_data):
                return ""
            end = shstrtab_data.find(b"\x00", name_offset)
            if end == -1:
                end = len(shstrtab_data)
            return shstrtab_data[name_offset:end].decode("latin-1", errors="replace")

        # Parse Sections
        if e_shoff > 0 and e_shentsize > 0 and e_shnum > 0:
            for i in range(e_shnum):
                sec_offset = e_shoff + i * e_shentsize
                if sec_offset + e_shentsize > len(data):
                    break
                if is_64bit:
                    (
                        sh_name_idx,
                        sh_type,
                        sh_flags,
                        sh_addr,
                        sh_offset,
                        sh_size,
                        sh_link,
                        sh_info,
                        sh_addralign,
                        sh_entsize,
                    ) = struct.unpack_from(f"{endian}IIQQQQIIQQ", data, sec_offset)
                else:
                    (
                        sh_name_idx,
                        sh_type,
                        sh_flags,
                        sh_addr,
                        sh_offset,
                        sh_size,
                        sh_link,
                        sh_info,
                        sh_addralign,
                        sh_entsize,
                    ) = struct.unpack_from(f"{endian}IIIIIIIIII", data, sec_offset)

                sec_name = get_sh_name(sh_name_idx) or f"section_{i}"
                type_name = ELF_SHT_MAP.get(sh_type, f"0x{sh_type:08X}")

                is_writable = bool(sh_flags & 0x1)  # SHF_WRITE
                is_alloc = bool(sh_flags & 0x2)  # SHF_ALLOC
                is_exec = bool(sh_flags & 0x4)  # SHF_EXECINSTR
                is_wx = is_writable and is_exec

                # Calculate Section Entropy
                sec_entropy = 0.0
                if sh_type != 8 and sh_size > 0 and sh_offset + sh_size <= len(data):  # Not NOBITS
                    sec_bytes = data[sh_offset : sh_offset + sh_size]
                    sec_entropy = calculate_shannon_entropy(sec_bytes)

                sec_ent_level = classify_entropy(sec_entropy)

                if "UPX" in sec_name.upper():
                    is_packed = True
                    if "UPX" not in detected_packers:
                        detected_packers.append("UPX (Ultimate Packer for eXecutables)")

                if is_wx:
                    forensic_alerts.append(
                        f"Section '{sec_name}' has Writable + Executable (W+X) permissions (Self-modifying / unpacker anomaly)"
                    )
                    threat_score += 35.0

                if sec_entropy > 7.4 and is_alloc and sh_size > 1024:
                    forensic_alerts.append(
                        f"High entropy ({sec_entropy:.2f}) in section '{sec_name}' suggests encrypted payload or compressed code"
                    )
                    threat_score += 15.0

                sec_analysis = ELFSectionAnalysis(
                    name=sec_name,
                    section_type=type_name,
                    virtual_address=sh_addr,
                    raw_data_offset=sh_offset,
                    raw_data_size=sh_size,
                    entropy=round(sec_entropy, 3),
                    entropy_level=sec_ent_level,
                    is_executable=is_exec,
                    is_writable=is_writable,
                    is_readable=True,
                    is_wx=is_wx,
                    flags_hex=f"0x{sh_flags:X}",
                )
                sections.append(sec_analysis)

        # Program Headers (PT_INTERP, PT_GNU_STACK, PT_DYNAMIC)
        interpreter: Optional[str] = None
        has_nx_stack = True

        if e_phoff > 0 and e_phentsize > 0 and e_phnum > 0:
            for p in range(e_phnum):
                ph_offset = e_phoff + p * e_phentsize
                if ph_offset + e_phentsize > len(data):
                    break
                if is_64bit:
                    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = (
                        struct.unpack_from(f"{endian}IIQQQQQQ", data, ph_offset)
                    )
                else:
                    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = (
                        struct.unpack_from(f"{endian}IIIIIIII", data, ph_offset)
                    )

                if p_type == 3:  # PT_INTERP
                    if p_offset + p_filesz <= len(data):
                        interp_bytes = data[p_offset : p_offset + p_filesz]
                        interpreter = interp_bytes.split(b"\x00", 1)[0].decode(
                            "utf-8", errors="replace"
                        )
                elif p_type == 0x6474E551:  # PT_GNU_STACK
                    # PF_X = 1
                    if p_flags & 1:
                        has_nx_stack = False
                        forensic_alerts.append(
                            "PT_GNU_STACK marked Executable — Non-Executable (NX) stack protection is DISABLED"
                        )
                        threat_score += 30.0

        # Extract imported shared libraries (DT_NEEDED) & symbols
        imported_libraries: List[str] = []
        imported_symbols: List[str] = []
        suspicious_symbols: List[str] = []

        # Scan for known dynamic library strings and API symbols in string table or entire binary
        for sym_name, (desc, _sev, pts) in SUSPICIOUS_LINUX_SYMBOLS.items():
            sym_bytes = sym_name.encode("ascii")
            if sym_bytes in data:
                suspicious_symbols.append(f"{sym_name} ({desc})")
                threat_score += pts

        # Detect common shared libraries in binary
        for lib in [
            "libc.so.6",
            "libpthread.so.0",
            "libdl.so.2",
            "libm.so.6",
            "libcrypto.so",
            "libssl.so",
            "libcurl.so",
        ]:
            if lib.encode("ascii") in data and lib not in imported_libraries:
                imported_libraries.append(lib)

        if is_packed:
            forensic_alerts.append(
                f"Executable packing signature detected: {', '.join(detected_packers)}"
            )
            threat_score += 40.0

        if overall_entropy >= 7.3:
            threat_score += 25.0

        threat_score = min(100.0, threat_score)

        if threat_score >= 60.0:
            verdict = "MALICIOUS"
        elif threat_score >= 25.0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"

        return ELFAnalysisReport(
            is_valid_elf=True,
            architecture=arch_str,
            ei_class=ei_class_str,
            endianness=endian_str,
            os_abi=os_abi_str,
            file_type=file_type_str,
            machine=machine_name,
            entry_point=e_entry,
            section_count=len(sections),
            program_header_count=e_phnum,
            sections=sections,
            imported_libraries=imported_libraries,
            imported_symbols=imported_symbols,
            suspicious_symbols=suspicious_symbols,
            interpreter=interpreter,
            has_nx_stack=has_nx_stack,
            overall_entropy=round(overall_entropy, 3),
            overall_entropy_level=overall_entropy_level,
            is_packed=is_packed,
            detected_packers=detected_packers,
            forensic_alerts=forensic_alerts,
            threat_score=round(threat_score, 1),
            verdict=verdict,
        )
