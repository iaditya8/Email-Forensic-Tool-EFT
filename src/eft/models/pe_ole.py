"""Forensic data models for static PE binary and OLE macro inspection."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from eft.models.threat import RiskSeverity


class EntropyLevel(str, Enum):
    """Categorization of Shannon entropy scores for binary data."""

    VERY_LOW = "Very Low (< 5.0)"
    NORMAL = "Normal Code / Structured Data (5.0 - 6.8)"
    HIGH = "High Density / Compressed Data (6.8 - 7.2)"
    PACKED_OR_ENCRYPTED = "Packed / Encrypted / Obfuscated (> 7.2)"


class SuspiciousAPICategory(str, Enum):
    """MITRE ATT&CK & DFIR categorization of suspicious Windows API calls."""

    PROCESS_INJECTION = "Process Injection / Hollowing"
    KEYLOGGING_HOOK = "Keylogging / Window Hooking"
    ANTI_DEBUG_EVASION = "Anti-Debugging / Evasion"
    EXECUTION_DROPPER = "Execution / Dropper"
    NETWORK_C2 = "Network / C2 Communication"
    PERSISTENCE_PRIVILEGE = "Persistence / Privilege Escalation"
    RANSOMWARE_CRYPTO = "Ransomware / Cryptography"
    MEMORY_MANIPULATION = "Direct Memory Manipulation"


class PESectionAnalysis(BaseModel):
    """Forensic analysis of an individual Windows PE section."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    virtual_address: int
    virtual_size: int
    raw_data_offset: int
    raw_data_size: int
    entropy: float = Field(default=0.0, ge=0.0, le=8.0)
    entropy_level: EntropyLevel = EntropyLevel.NORMAL

    # Section Characteristics Flags
    is_executable: bool = False
    is_readable: bool = True
    is_writable: bool = False
    is_wx: bool = False  # Writable and Executable (self-modifying/unpacking anomaly)
    is_uninitialized_data: bool = False
    suspicious_flags: List[str] = Field(default_factory=list)


class PEImportedFunction(BaseModel):
    """Representation of an imported Windows API symbol."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    function_name: str
    ordinal: Optional[int] = None
    dll_name: str
    is_suspicious: bool = False
    suspicious_category: Optional[SuspiciousAPICategory] = None
    threat_severity: RiskSeverity = RiskSeverity.CLEAN
    description: Optional[str] = None


class PEImportedDLL(BaseModel):
    """DLL container grouping imported functions."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    dll_name: str
    functions: List[PEImportedFunction] = Field(default_factory=list)
    suspicious_function_count: int = 0


class PEExportedFunction(BaseModel):
    """Representation of an exported symbol in a DLL or executable."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    function_name: Optional[str] = None
    ordinal: int
    rva: int
    forwarder_name: Optional[str] = None


class PEAnalysisReport(BaseModel):
    """Detailed forensic report for a Windows Portable Executable (PE32/PE32+)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    is_valid_pe: bool = True
    architecture: str = "Unknown"  # "PE32 (32-bit x86)", "PE32+ (64-bit AMD64)", "ARM64", etc.
    machine_type_hex: str = "0x0"
    compilation_timestamp: Optional[datetime] = None
    is_timestamp_suspicious: bool = False

    # Optional Header & Execution Context
    entry_point_rva: int = 0
    image_base: int = 0
    subsystem: str = "Unknown"
    is_dll: bool = False
    is_driver: bool = False
    is_dotnet: bool = False

    # Security Mitigations (DllCharacteristics)
    has_aslr: bool = False
    has_dep_nx: bool = False
    has_cfg: bool = False
    has_seh: bool = True

    # Digital Signature
    has_digital_signature: bool = False
    signature_size: int = 0

    # Sections & Entropy
    section_count: int = 0
    sections: List[PESectionAnalysis] = Field(default_factory=list)
    overall_entropy: float = Field(default=0.0, ge=0.0, le=8.0)
    overall_entropy_level: EntropyLevel = EntropyLevel.NORMAL

    # Packing / Crypter Attribution
    is_packed: bool = False
    packing_reasons: List[str] = Field(default_factory=list)
    detected_packers: List[str] = Field(default_factory=list)

    # Imports, Exports, and Threat APIs
    imports: List[PEImportedDLL] = Field(default_factory=list)
    suspicious_apis: List[PEImportedFunction] = Field(default_factory=list)
    exports: List[PEExportedFunction] = Field(default_factory=list)
    exported_dll_name: Optional[str] = None

    # Forensic Threat Assessment
    forensic_alerts: List[str] = Field(default_factory=list)
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    verdict: str = "BENIGN"  # BENIGN, SUSPICIOUS, MALICIOUS


class VBAMacroStream(BaseModel):
    """Decompressed VBA macro module stream from an OLE compound document."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    stream_name: str
    code_size_bytes: int = 0
    source_code: str = ""
    auto_exec_triggers: List[str] = Field(default_factory=list)
    suspicious_keywords: List[str] = Field(default_factory=list)
    extracted_urls: List[str] = Field(default_factory=list)
    extracted_ips: List[str] = Field(default_factory=list)
    extracted_commands: List[str] = Field(default_factory=list)
    is_obfuscated: bool = False
    obfuscation_indicators: List[str] = Field(default_factory=list)


class OLEAnalysisReport(BaseModel):
    """Detailed forensic report for an OLE Compound Document and its VBA macros."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    is_ole_compound_document: bool = True
    stream_hierarchy: List[str] = Field(default_factory=list)
    has_vba_macros: bool = False
    vba_streams: List[VBAMacroStream] = Field(default_factory=list)
    total_macro_lines: int = 0

    # Aggregate Macro Indicators
    all_auto_exec_triggers: List[str] = Field(default_factory=list)
    all_suspicious_keywords: List[str] = Field(default_factory=list)
    all_extracted_urls: List[str] = Field(default_factory=list)
    all_extracted_ips: List[str] = Field(default_factory=list)
    all_extracted_commands: List[str] = Field(default_factory=list)
    has_obfuscation: bool = False

    forensic_alerts: List[str] = Field(default_factory=list)
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    verdict: str = "BENIGN"  # BENIGN, SUSPICIOUS, MALICIOUS


class ELFSectionAnalysis(BaseModel):
    """Forensic analysis of an individual Linux/Unix ELF section."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    section_type: str = "PROGBITS"
    virtual_address: int = 0
    raw_data_offset: int = 0
    raw_data_size: int = 0
    entropy: float = Field(default=0.0, ge=0.0, le=8.0)
    entropy_level: EntropyLevel = EntropyLevel.NORMAL

    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = True
    is_wx: bool = False
    flags_hex: str = "0x0"


class ELFAnalysisReport(BaseModel):
    """Detailed forensic report for a Linux/Unix Executable and Linkable Format (ELF) binary."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    is_valid_elf: bool = True
    architecture: str = (
        "Unknown"  # "ELF64 (x86-64)", "ELF32 (i386)", "ELF64 (ARM64 / AArch64)", etc.
    )
    ei_class: str = "64-bit"
    endianness: str = "Little-Endian"
    os_abi: str = "UNIX - System V"
    file_type: str = "Executable (ET_EXEC)"
    machine: str = "Advanced Micro Devices X86-64"
    entry_point: int = 0
    section_count: int = 0
    program_header_count: int = 0
    sections: List[ELFSectionAnalysis] = Field(default_factory=list)
    imported_libraries: List[str] = Field(default_factory=list)  # e.g., libc.so.6, libpthread.so.0
    imported_symbols: List[str] = Field(default_factory=list)
    suspicious_symbols: List[str] = Field(default_factory=list)
    interpreter: Optional[str] = None
    has_nx_stack: bool = True
    overall_entropy: float = Field(default=0.0, ge=0.0, le=8.0)
    overall_entropy_level: EntropyLevel = EntropyLevel.NORMAL
    is_packed: bool = False
    detected_packers: List[str] = Field(default_factory=list)
    forensic_alerts: List[str] = Field(default_factory=list)
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    verdict: str = "BENIGN"  # BENIGN, SUSPICIOUS, MALICIOUS


class BinaryStaticReport(BaseModel):
    """Master forensic report for static PE, ELF, OLE, and binary file artifact analysis."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    file_path: Optional[str] = None
    filename: str
    size_bytes: int
    hashes: Dict[str, str] = Field(default_factory=dict)  # md5, sha1, sha256, sha512
    format_category: str = "Unknown"

    pe_analysis: Optional[PEAnalysisReport] = None
    elf_analysis: Optional[ELFAnalysisReport] = None
    ole_analysis: Optional[OLEAnalysisReport] = None

    overall_entropy: float = Field(default=0.0, ge=0.0, le=8.0)
    overall_entropy_level: EntropyLevel = EntropyLevel.NORMAL

    # Unified Threat Assessment
    is_suspicious: bool = False
    threat_severity: RiskSeverity = RiskSeverity.CLEAN
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    verdict: str = "BENIGN"
    summary: str = ""
    remediation_advice: List[str] = Field(default_factory=list)

    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to a JSON-compatible Python dictionary."""
        return self.model_dump(mode="json")
