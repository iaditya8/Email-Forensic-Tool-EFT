import struct

from eft.analysis.binary_static_analyzer import BinaryStaticAnalyzer
from eft.analysis.elf_analyzer import ELFBinaryAnalyzer
from eft.models.pe_ole import ELFAnalysisReport


def build_synthetic_elf64(
    has_suspicious_apis: bool = False,
    is_packed: bool = False,
) -> bytes:
    """Construct valid synthetic 64-bit ELF binary structure for unit testing."""
    endian = "<"

    # Section string table contents
    sec_names = [b"\x00", b".text\x00", b".shstrtab\x00"]
    if is_packed:
        sec_names.insert(2, b"UPX0\x00")

    shstrtab = b"".join(sec_names)
    text_code = b"\x90\x90\x90\xc3"
    if has_suspicious_apis:
        text_code += b"ptrace\x00process_vm_writev\x00memfd_create\x00libc.so.6\x00"

    header_size = 64
    ph_size = 56
    ph_num = 1
    sh_size = 64
    sh_num = 3 if not is_packed else 4
    shstrndx = sh_num - 1

    e_phoff = header_size
    text_offset = header_size + (ph_size * ph_num)
    shstrtab_offset = text_offset + len(text_code)
    e_shoff = shstrtab_offset + len(shstrtab)

    # 1. ELF Header (64 bytes)
    elf_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    elf_hdr = elf_ident + struct.pack(
        f"{endian}HHIQQQIHHHHHH",
        2,  # e_type: ET_EXEC
        0x3E,  # e_machine: x86-64
        1,  # e_version
        0x401000,  # e_entry
        e_phoff,  # e_phoff
        e_shoff,  # e_shoff
        0,  # e_flags
        header_size,  # e_ehsize
        ph_size,  # e_phentsize
        ph_num,  # e_phnum
        sh_size,  # e_shentsize
        sh_num,  # e_shnum
        shstrndx,  # e_shstrndx
    )

    # 2. Program Header (PT_LOAD)
    ph_entry = struct.pack(
        f"{endian}IIQQQQQQ",
        1,  # p_type: PT_LOAD
        5,  # p_flags: PF_R | PF_X
        0,  # p_offset
        0x400000,  # p_vaddr
        0x400000,  # p_paddr
        0x1000,  # p_filesz
        0x1000,  # p_memsz
        0x1000,  # p_align
    )

    # 3. Section Headers
    # Null section
    sh_null = b"\x00" * sh_size

    # .text section
    name_idx_text = shstrtab.find(b".text")
    sh_text = struct.pack(
        f"{endian}IIQQQQIIQQ",
        name_idx_text,  # sh_name
        1,  # sh_type: PROGBITS
        6,  # sh_flags: SHF_ALLOC | SHF_EXECINSTR
        0x401000,  # sh_addr
        text_offset,  # sh_offset
        len(text_code),  # sh_size
        0,  # sh_link
        0,  # sh_info
        16,  # sh_addralign
        0,  # sh_entsize
    )

    # Optional UPX section
    sh_upx = b""
    if is_packed:
        name_idx_upx = shstrtab.find(b"UPX0")
        sh_upx = struct.pack(
            f"{endian}IIQQQQIIQQ",
            name_idx_upx,
            1,
            7,  # SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR (W+X)
            0x402000,
            text_offset,
            len(text_code),
            0,
            0,
            16,
            0,
        )

    # .shstrtab section
    name_idx_strtab = shstrtab.find(b".shstrtab")
    sh_strtab = struct.pack(
        f"{endian}IIQQQQIIQQ",
        name_idx_strtab,
        3,  # sh_type: STRTAB
        0,  # sh_flags
        0,  # sh_addr
        shstrtab_offset,  # sh_offset
        len(shstrtab),  # sh_size
        0,
        0,
        1,
        0,
    )

    return (
        elf_hdr
        + ph_entry
        + text_code
        + shstrtab
        + sh_null
        + sh_text
        + (sh_upx if is_packed else b"")
        + sh_strtab
    )


def test_elf_analyzer_clean_binary():
    """Verify ELF parser accurately processes clean 64-bit ELF executable."""
    elf_bytes = build_synthetic_elf64(has_suspicious_apis=False)
    analyzer = ELFBinaryAnalyzer()
    report = analyzer.analyze(elf_bytes)

    assert isinstance(report, ELFAnalysisReport)
    assert report.is_valid_elf is True
    assert "x86-64" in report.architecture
    assert report.ei_class == "64-bit"
    assert report.endianness == "Little-Endian"
    assert report.section_count >= 2
    assert report.entry_point == 0x401000
    assert report.verdict == "BENIGN"
    assert report.is_packed is False


def test_elf_analyzer_suspicious_apis_and_packed():
    """Verify threat scoring on packed ELF binary with process injection APIs."""
    elf_bytes = build_synthetic_elf64(has_suspicious_apis=True, is_packed=True)
    analyzer = ELFBinaryAnalyzer()
    report = analyzer.analyze(elf_bytes)

    assert report.is_valid_elf is True
    assert report.is_packed is True
    assert any("UPX" in p for p in report.detected_packers)
    assert len(report.suspicious_symbols) >= 3
    assert any("ptrace" in sym for sym in report.suspicious_symbols)
    assert any("process_vm_writev" in sym for sym in report.suspicious_symbols)
    assert report.threat_score >= 50.0
    assert report.verdict in ("SUSPICIOUS", "MALICIOUS")
    assert "libc.so.6" in report.imported_libraries


def test_binary_static_analyzer_elf_dispatch():
    """Verify unified BinaryStaticAnalyzer dispatches ELF binaries correctly."""
    elf_bytes = build_synthetic_elf64(has_suspicious_apis=True, is_packed=True)
    analyzer = BinaryStaticAnalyzer()
    report = analyzer.analyze(elf_bytes, filename="malware.elf")

    assert report.format_category == "Linux / Unix Executable & Linkable Format (ELF)"
    assert report.elf_analysis is not None
    assert report.pe_analysis is None
    assert report.ole_analysis is None
    assert report.elf_analysis.is_valid_elf is True
    assert report.verdict in ("SUSPICIOUS", "MALICIOUS")
    assert len(report.remediation_advice) > 0
