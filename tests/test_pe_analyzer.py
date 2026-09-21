"""Comprehensive unit test suite for Static PE Binary Forensics Analyzer."""

import struct
from datetime import datetime, timezone

from eft.analysis.pe_analyzer import (
    PEBinaryAnalyzer,
    calculate_shannon_entropy,
    classify_entropy,
)
from eft.models.pe_ole import (
    EntropyLevel,
    SuspiciousAPICategory,
)


def build_synthetic_pe32plus(
    machine: int = 0x8664,  # x64
    timestamp: int = 1680000000,
    characteristics: int = 0x0022,  # Executable | Large address aware
    dll_characteristics: int = 0x0140,  # DYNAMIC_BASE (ASLR) | NX_COMPAT (DEP)
    subsystem: int = 3,  # Windows CUI
    sections_spec=None,
    imports_spec=None,
    exports_spec=None,
    has_signature: bool = False,
    is_dotnet: bool = False,
) -> bytes:
    """Construct a structurally valid synthetic PE32+ (64-bit) binary in bytes."""
    if sections_spec is None:
        sections_spec = [
            (".text", 0x1000, 0x1000, 0x20000020, b"\x90" * 0x1000),  # Executable + Code
            (".data", 0x2000, 0x0800, 0xC0000040, b"\x00" * 0x0800),  # Read + Write + InitData
        ]

    # DOS Header (64 bytes)
    dos_header = bytearray(0x80)
    dos_header[:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)  # e_lfanew = 0x80

    # PE Signature
    pe_sig = b"PE\x00\x00"

    num_sections = len(sections_spec)
    size_of_optional_header = 0xF0  # Standard PE32+ optional header size (240 bytes)

    coff_header = struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        timestamp,
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        size_of_optional_header,
        characteristics,
    )

    # Optional Header (PE32+ 64-bit)
    opt_magic = 0x20B
    entry_point_rva = 0x1000
    image_base = 0x0000000140000000
    section_alignment = 0x1000
    file_alignment = 0x200
    num_rva_and_sizes = 16

    opt_header_fixed = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        opt_magic,
        14,
        0,  # Linker Version
        0x1000,  # SizeOfCode
        0x1000,  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
        entry_point_rva,
        0x1000,  # BaseOfCode
        image_base,
        section_alignment,
        file_alignment,
        6,
        0,  # OS Version
        0,
        0,  # Image Version
        6,
        0,  # Subsystem Version
        0,  # Win32VersionValue
        0x3000,  # SizeOfImage
        0x400,  # SizeOfHeaders
        0,  # CheckSum
        subsystem,
        dll_characteristics,
        0x100000,
        0x1000,  # Stack Reserve / Commit
        0x100000,
        0x1000,  # Heap Reserve / Commit
        0,  # LoaderFlags
        num_rva_and_sizes,
    )

    # Data directories (16 entries * 8 bytes = 128 bytes)
    data_directories = bytearray(16 * 8)

    export_rva = 0x2400 if exports_spec else 0
    export_size = 0x100 if exports_spec else 0
    import_rva = 0x2000 if imports_spec else 0
    import_size = 0x100 if imports_spec else 0
    cert_offset = 0x3000 if has_signature else 0
    cert_size = 0x200 if has_signature else 0
    clr_rva = 0x2800 if is_dotnet else 0
    clr_size = 0x48 if is_dotnet else 0

    struct.pack_into("<II", data_directories, 0 * 8, export_rva, export_size)  # Export
    struct.pack_into("<II", data_directories, 1 * 8, import_rva, import_size)  # Import
    struct.pack_into("<II", data_directories, 4 * 8, cert_offset, cert_size)  # Security / Cert
    struct.pack_into("<II", data_directories, 14 * 8, clr_rva, clr_size)  # CLR (.NET)

    # Section Headers (40 bytes each)
    section_headers = bytearray()
    raw_offset_cursor = 0x400

    section_buffers = []
    for name, virt_addr, virt_size, charact, content in sections_spec:
        name_bytes = name.encode("latin-1")[:8].ljust(8, b"\x00")
        raw_size = len(content)
        sec_hdr = struct.pack(
            "<8sIIIIIIHHI",
            name_bytes,
            virt_size,
            virt_addr,
            raw_size,
            raw_offset_cursor if raw_size > 0 else 0,
            0,
            0,
            0,
            0,  # Relocations & Linenumbers
            charact,
        )
        section_headers.extend(sec_hdr)
        section_buffers.append((raw_offset_cursor, content))
        raw_offset_cursor += raw_size

    # Assemble complete binary
    pe_data = bytearray(dos_header)
    pe_data.extend(pe_sig)
    pe_data.extend(coff_header)
    pe_data.extend(opt_header_fixed)
    pe_data.extend(data_directories)
    pe_data.extend(section_headers)

    # Pad up to first section raw offset (0x400)
    if len(pe_data) < 0x400:
        pe_data.extend(b"\x00" * (0x400 - len(pe_data)))

    # Write section data
    for _offset, content in section_buffers:
        pe_data.extend(content)

    # Build Imports inside section data if requested
    if imports_spec:
        # We will write imports into the second section (RVA 0x2000, raw offset 0x400 + section 0 size)
        import_raw_offset = 0x400 + len(sections_spec[0][4])
        # Write descriptor for each DLL + terminating NULL descriptor
        # Layout in section:
        # [Import Descriptors...] (20 bytes each)
        # [Thunk ILT...] (8 bytes each)
        # [Thunk IAT...] (8 bytes each)
        # [Strings: DLL Name, Function Names...]
        desc_size = (len(imports_spec) + 1) * 20
        curr_str_offset = import_raw_offset + desc_size + 128
        curr_thunk_offset = import_raw_offset + desc_size

        for i, (dll_name, func_names) in enumerate(imports_spec):
            dll_name_bytes = dll_name.encode("ascii") + b"\x00"
            dll_name_rva = 0x2000 + (curr_str_offset - import_raw_offset)
            # Write DLL name string
            if curr_str_offset + len(dll_name_bytes) > len(pe_data):
                pe_data.extend(
                    b"\x00" * (curr_str_offset + len(dll_name_bytes) - len(pe_data) + 32)
                )
            pe_data[curr_str_offset : curr_str_offset + len(dll_name_bytes)] = dll_name_bytes
            curr_str_offset += len(dll_name_bytes)

            thunk_rva = 0x2000 + (curr_thunk_offset - import_raw_offset)

            # Write import descriptor
            struct.pack_into(
                "<IIIII",
                pe_data,
                import_raw_offset + (i * 20),
                thunk_rva,  # OriginalFirstThunk
                0,
                0,
                dll_name_rva,  # NameRVA
                thunk_rva,  # FirstThunk
            )

            # Write Thunk entries
            for fn in func_names:
                fn_bytes = struct.pack("<H", 0) + fn.encode("ascii") + b"\x00"
                fn_rva = 0x2000 + (curr_str_offset - import_raw_offset)
                if curr_str_offset + len(fn_bytes) > len(pe_data):
                    pe_data.extend(b"\x00" * (curr_str_offset + len(fn_bytes) - len(pe_data) + 32))
                pe_data[curr_str_offset : curr_str_offset + len(fn_bytes)] = fn_bytes
                curr_str_offset += len(fn_bytes)

                # Write 64-bit thunk value (RVA to Hint/Name)
                if curr_thunk_offset + 8 > len(pe_data):
                    pe_data.extend(b"\x00" * 32)
                struct.pack_into("<Q", pe_data, curr_thunk_offset, fn_rva)
                curr_thunk_offset += 8

            # Terminate thunk with 0
            if curr_thunk_offset + 8 > len(pe_data):
                pe_data.extend(b"\x00" * 32)
            struct.pack_into("<Q", pe_data, curr_thunk_offset, 0)
            curr_thunk_offset += 8

    # Build Exports inside section if requested
    if exports_spec:
        exp_dll_name, exp_funcs = exports_spec
        exp_raw_offset = 0x400 + len(sections_spec[0][4]) + 0x400
        if exp_raw_offset + 256 > len(pe_data):
            pe_data.extend(b"\x00" * 512)

        name_str_rva = 0x2400 + 100
        pe_data[exp_raw_offset + 100 : exp_raw_offset + 100 + len(exp_dll_name) + 1] = (
            exp_dll_name.encode("ascii") + b"\x00"
        )

        # Export directory (40 bytes)
        struct.pack_into(
            "<IIHHIIIIIII",
            pe_data,
            exp_raw_offset,
            0,
            timestamp,
            1,
            0,
            name_str_rva,  # Name RVA
            1,  # Base
            len(exp_funcs),
            len(exp_funcs),
            0x2400 + 50,  # AddressOfFunctions
            0x2400 + 60,  # AddressOfNames
            0x2400 + 70,  # AddressOfNameOrdinals
        )

    return bytes(pe_data)


def test_shannon_entropy_calculation():
    """Verify Shannon entropy mathematics and classification tiers."""
    # Zero entropy on all identical bytes
    zeros = b"\x00" * 1000
    assert calculate_shannon_entropy(zeros) == 0.0
    assert classify_entropy(0.0) == EntropyLevel.VERY_LOW

    # Low entropy on repetitive structured text
    ascii_text = b"Email Forensic Tool EFT Digital Forensics Evidence Ledger ISO 27037 " * 20
    text_entropy = calculate_shannon_entropy(ascii_text)
    assert 3.0 < text_entropy < 5.0
    assert classify_entropy(text_entropy) == EntropyLevel.VERY_LOW

    # High / Random entropy on uniform 256-byte distribution
    uniform_bytes = bytes(range(256)) * 10
    max_entropy = calculate_shannon_entropy(uniform_bytes)
    assert 7.9 <= max_entropy <= 8.0
    assert classify_entropy(max_entropy) == EntropyLevel.PACKED_OR_ENCRYPTED


def test_invalid_pe_detection():
    """Verify graceful handling of non-PE, short, and corrupted files."""
    analyzer = PEBinaryAnalyzer()

    # Short file (< 64 bytes)
    res_short = analyzer.analyze(b"MZ12345")
    assert not res_short.is_valid_pe
    assert "smaller than minimum DOS header" in res_short.forensic_alerts[0]

    # Non-MZ file
    res_non_mz = analyzer.analyze(b"GIF89a" + b"\x00" * 100)
    assert not res_non_mz.is_valid_pe
    assert "Missing DOS signature" in res_non_mz.forensic_alerts[0]

    # Invalid e_lfanew offset
    corrupt_dos = bytearray(b"MZ" + b"\x00" * 62)
    struct.pack_into("<I", corrupt_dos, 0x3C, 0x999999)
    res_corrupt = analyzer.analyze(bytes(corrupt_dos))
    assert not res_corrupt.is_valid_pe
    assert "Invalid e_lfanew offset" in res_corrupt.forensic_alerts[0]


def test_benign_pe64_parsing():
    """Verify parsing of clean 64-bit Windows executable."""
    pe_bytes = build_synthetic_pe32plus(
        machine=0x8664,
        timestamp=int(datetime(2023, 5, 10, 12, 0, 0, tzinfo=timezone.utc).timestamp()),
        characteristics=0x0022,
        dll_characteristics=0x0140,  # ASLR + DEP
        subsystem=2,  # Windows GUI
        sections_spec=[
            (".text", 0x1000, 0x1000, 0x60000020, b"\x90\xcc\x48\x89\x5c\x24" * 100),
            (".rdata", 0x2000, 0x0800, 0x40000040, b"Clean Application String Data\x00" * 20),
            (".data", 0x3000, 0x0800, 0xC0000040, b"\x00" * 200),
        ],
        imports_spec=[
            ("KERNEL32.dll", ["GetModuleHandleA", "GetLastError", "ExitProcess"]),
            ("USER32.dll", ["MessageBoxA"]),
        ],
        has_signature=True,
    )

    analyzer = PEBinaryAnalyzer()
    report = analyzer.analyze(pe_bytes)

    assert report.is_valid_pe
    assert report.architecture == "PE32+ (64-bit AMD64)"
    assert report.subsystem == "Windows GUI"
    assert report.has_aslr is True
    assert report.has_dep_nx is True
    assert report.has_digital_signature is True
    assert report.is_packed is False
    assert len(report.sections) == 3
    assert len(report.imports) == 2
    assert len(report.suspicious_apis) == 0
    assert report.threat_score < 30.0
    assert report.verdict == "BENIGN"


def test_malicious_process_injection_pe():
    """Verify detection of process injection, hooking, and dropper APIs."""
    pe_bytes = build_synthetic_pe32plus(
        machine=0x8664,
        characteristics=0x0022,
        dll_characteristics=0x0000,  # No ASLR, No DEP
        sections_spec=[
            (
                ".text",
                0x1000,
                0x1000,
                0xE0000020,
                b"\x90\x90\x90\x90" * 100,
            ),  # WX: Executable + Writable!
            (".data", 0x2000, 0x1000, 0xC0000040, b"\x00" * 500),
        ],
        imports_spec=[
            (
                "KERNEL32.dll",
                [
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "SetThreadContext",
                    "ResumeThread",
                    "IsDebuggerPresent",
                ],
            ),
            (
                "USER32.dll",
                [
                    "SetWindowsHookExA",
                    "GetAsyncKeyState",
                ],
            ),
            (
                "URLMON.dll",
                [
                    "URLDownloadToFileA",
                ],
            ),
        ],
    )

    analyzer = PEBinaryAnalyzer()
    report = analyzer.analyze(pe_bytes)

    assert report.is_valid_pe
    assert len(report.suspicious_apis) >= 8

    # Verify suspicious API classifications
    api_names = [a.function_name for a in report.suspicious_apis]
    assert "VirtualAllocEx" in api_names
    assert "WriteProcessMemory" in api_names
    assert "CreateRemoteThread" in api_names
    assert "SetWindowsHookExA" in api_names
    assert "URLDownloadToFileA" in api_names

    # Check categories
    categories = {a.suspicious_category for a in report.suspicious_apis}
    assert SuspiciousAPICategory.PROCESS_INJECTION in categories
    assert SuspiciousAPICategory.KEYLOGGING_HOOK in categories
    assert SuspiciousAPICategory.NETWORK_C2 in categories
    assert SuspiciousAPICategory.ANTI_DEBUG_EVASION in categories

    # WX section should be flagged
    wx_sections = [s for s in report.sections if s.is_wx]
    assert len(wx_sections) == 1

    assert report.threat_score >= 70.0
    assert report.verdict == "MALICIOUS"


def test_packed_upx_binary_detection():
    """Verify heuristic attribution for UPX packed executables."""
    # Build UPX structure with UPX0 (raw size 0, virt size > 0) and UPX1 (high entropy)
    high_entropy_bytes = bytes([i % 256 for i in range(1024)])
    pe_bytes = build_synthetic_pe32plus(
        machine=0x8664,
        sections_spec=[
            ("UPX0", 0x1000, 0x5000, 0xE0000020, b""),  # Raw size 0, expands in memory
            ("UPX1", 0x6000, 0x1000, 0xE0000020, high_entropy_bytes),
            (".rsrc", 0x7000, 0x0400, 0x40000040, b"\x00" * 0x400),
        ],
        imports_spec=[
            ("KERNEL32.dll", ["LoadLibraryA", "GetProcAddress"]),
        ],
    )

    analyzer = PEBinaryAnalyzer()
    report = analyzer.analyze(pe_bytes)

    assert report.is_valid_pe
    assert report.is_packed is True
    assert "UPX" in report.detected_packers
    assert any("UPX" in reason for reason in report.packing_reasons)
    assert report.threat_score >= 35.0
    assert report.verdict in ("SUSPICIOUS", "MALICIOUS")


def test_anachronistic_timestamp_detection():
    """Verify detection of suspicious timestomped PE headers."""
    # Pre-1980 compilation timestamp (e.g. year 1970)
    pe_bytes = build_synthetic_pe32plus(
        timestamp=0,  # 1970-01-01 00:00:00 UTC
    )

    analyzer = PEBinaryAnalyzer()
    report = analyzer.analyze(pe_bytes)

    assert report.is_valid_pe
    assert report.is_timestamp_suspicious is True
    assert any("timestomping indicator" in alert for alert in report.forensic_alerts)
