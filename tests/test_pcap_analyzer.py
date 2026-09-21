"""Comprehensive unit test suite for offline PCAP and PCAPNG Stream Parser."""

import socket
import struct
import tempfile
from pathlib import Path

from eft.analysis.pcap_analyzer import NetworkPCAPAnalyzer, decode_dns_name
from eft.models.pcap import (
    AppProtocol,
    PCAPAnalysisReport,
    TransportProtocol,
)


def build_ethernet_ipv4_tcp_packet(
    src_mac: str = "00:11:22:33:44:55",
    dst_mac: str = "66:77:88:99:aa:bb",
    src_ip: str = "192.168.1.100",
    dst_ip: str = "1.1.1.1",
    src_port: int = 54321,
    dst_port: int = 443,
    seq: int = 1000,
    ack: int = 0,
    flags: int = 0x02,  # SYN
    payload: bytes = b"",
) -> bytes:
    """Build raw Ethernet II + IPv4 + TCP packet."""
    # Ethernet Header (14 bytes)
    dst_mac_b = bytes.fromhex(dst_mac.replace(":", ""))
    src_mac_b = bytes.fromhex(src_mac.replace(":", ""))
    eth_hdr = dst_mac_b + src_mac_b + struct.pack(">H", 0x0800)  # EtherType IPv4

    # TCP Header (20 bytes)
    tcp_hdr = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        (5 << 4),  # Data Offset = 5 (20 bytes)
        flags,
        64240,  # Window size
        0,  # Checksum
        0,  # Urgent pointer
    )

    # IPv4 Header (20 bytes)
    total_len = 20 + len(tcp_hdr) + len(payload)
    src_ip_b = socket.inet_aton(src_ip)
    dst_ip_b = socket.inet_aton(dst_ip)
    ip_hdr = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,  # Version 4, IHL 5
        0,  # DSCP/ECN
        total_len,
        12345,  # Identification
        0x4000,  # Flags (Don't Fragment)
        64,  # TTL
        6,  # Protocol (TCP)
        0,  # Header Checksum
        src_ip_b,
        dst_ip_b,
    )

    return eth_hdr + ip_hdr + tcp_hdr + payload


def build_ethernet_ipv4_udp_dns_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "8.8.8.8",
    src_port: int = 53123,
    dst_port: int = 53,
    tx_id: int = 0x1234,
    qname: str = "malicious-c2.test",
    qtype: int = 1,  # A
    is_response: bool = False,
    answer_ip: str = "185.220.101.5",  # Tor exit node
) -> bytes:
    """Build raw Ethernet II + IPv4 + UDP + DNS packet."""
    eth_hdr = (
        bytes.fromhex("66778899aabb") + bytes.fromhex("001122334455") + struct.pack(">H", 0x0800)
    )

    # Encode DNS Query Name
    qname_parts = qname.split(".")
    dns_qname_bytes = bytearray()
    for part in qname_parts:
        dns_qname_bytes.append(len(part))
        dns_qname_bytes.extend(part.encode("latin-1"))
    dns_qname_bytes.append(0)  # Null terminator

    flags = 0x8180 if is_response else 0x0100  # Standard query / Standard response
    qdcount = 1
    ancount = 1 if is_response else 0

    dns_payload = struct.pack(">HHHHHH", tx_id, flags, qdcount, ancount, 0, 0)
    dns_payload += dns_qname_bytes + struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS IN

    if is_response:
        # Answer RR: Name pointer 0xC00C, Type A (1), Class IN (1), TTL 300, RDLength 4
        dns_payload += struct.pack(">HHHIH", 0xC00C, 1, 1, 300, 4)
        dns_payload += socket.inet_aton(answer_ip)

    udp_len = 8 + len(dns_payload)
    udp_hdr = struct.pack(">HHHH", src_port, dst_port, udp_len, 0)

    total_ip_len = 20 + udp_len
    ip_hdr = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total_ip_len,
        54321,
        0,
        64,
        17,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    return eth_hdr + ip_hdr + udp_hdr + dns_payload


def build_tls_client_hello_payload(sni: str = "secure.bank.com") -> bytes:
    """Build a TLS 1.2 Record containing a Client Hello handshake with SNI extension."""
    sni_bytes = sni.encode("latin-1")
    sni_ext_data = struct.pack(">HBH", len(sni_bytes) + 3, 0, len(sni_bytes)) + sni_bytes
    ext_block = struct.pack(">HH", 0x0000, len(sni_ext_data)) + sni_ext_data

    # Add Supported Versions extension (0x002B) with TLS 1.3 (0x0304)
    sup_ver_ext = struct.pack(">HH", 0x002B, 3) + struct.pack(">BH", 2, 0x0304)
    ext_block += sup_ver_ext

    # Ciphers (TLS_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    ciphers = struct.pack(">HHH", 4, 0x1301, 0xC02F)

    # Handshake body
    client_random = b"\x11" * 32
    session_id = b"\x00"  # 0 length
    compression = b"\x01\x00"  # 1 method: null
    extensions_total = struct.pack(">H", len(ext_block)) + ext_block

    client_hello_body = (
        struct.pack(">H", 0x0303)  # Client Version TLS 1.2
        + client_random
        + session_id
        + ciphers
        + compression
        + extensions_total
    )

    handshake_hdr = struct.pack(
        ">BBH", 1, 0, len(client_hello_body)
    )  # Client Hello (1), Length 24-bit
    record_hdr = struct.pack(">BHH", 22, 0x0303, len(handshake_hdr) + len(client_hello_body))

    return record_hdr + handshake_hdr + client_hello_body


def create_synthetic_pcap(packet_list: list) -> bytes:
    """Assemble a classic libpcap file in bytes."""
    # Global Header (24 bytes): Magic 0xA1B2C3D4 (Little-Endian writes \xd4\xc3\xb2\xa1)
    global_hdr = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        1,  # LINKTYPE_ETHERNET
    )

    pcap_data = bytearray(global_hdr)
    for ts_float, raw_pkt in packet_list:
        sec = int(ts_float)
        usec = int((ts_float - sec) * 1_000_000)
        wire_len = len(raw_pkt)
        cap_len = wire_len
        pkt_hdr = struct.pack("<IIII", sec, usec, cap_len, wire_len)
        pcap_data.extend(pkt_hdr)
        pcap_data.extend(raw_pkt)

    return bytes(pcap_data)


def create_synthetic_pcapng(packet_list: list) -> bytes:
    """Assemble a modern PCAPNG file in bytes with SHB, IDB, and EPB blocks."""
    out = bytearray()

    # 1. Section Header Block (SHB: 28 bytes)
    shb_len = 28
    shb = struct.pack(
        "<IIIHHQ",
        0x0A0D0D0A,  # Block Type
        shb_len,  # Block Total Length
        0x1A2B3C4D,  # Byte Order Magic
        1,
        0,  # Major, Minor
        0xFFFFFFFFFFFFFFFF,  # Section Length (64-bit unspecified)
    )
    shb += struct.pack("<I", shb_len)  # Trailing length
    out.extend(shb)

    # 2. Interface Description Block (IDB)
    idb_len = 20
    idb = struct.pack(
        "<IIHHI",
        0x00000001,  # Block Type (IDB)
        idb_len,
        1,  # LinkType: Ethernet
        0,  # Reserved
        65535,  # SnapLen
    )
    idb += struct.pack("<I", idb_len)
    out.extend(idb)

    # 3. Enhanced Packet Blocks (EPB)
    for ts_float, raw_pkt in packet_list:
        cap_len = len(raw_pkt)
        wire_len = cap_len
        pad_len = (4 - (cap_len % 4)) % 4
        epb_len = 32 + cap_len + pad_len
        ts_usec = int(ts_float * 1_000_000)
        ts_high = (ts_usec >> 32) & 0xFFFFFFFF
        ts_low = ts_usec & 0xFFFFFFFF

        epb_hdr = struct.pack(
            "<IIIIIII",
            0x00000006,  # EPB
            epb_len,
            0,  # Interface ID
            ts_high,
            ts_low,
            cap_len,
            wire_len,
        )
        out.extend(epb_hdr)
        out.extend(raw_pkt)
        if pad_len > 0:
            out.extend(b"\x00" * pad_len)
        out.extend(struct.pack("<I", epb_len))

    return bytes(out)


def test_dns_name_decoder():
    """Verify RFC 1035 DNS name decompression."""
    # Plain labels: \x06google\x03com\x00
    msg = b"\x00" * 12 + b"\x06google\x03com\x00"
    name, off = decode_dns_name(msg, 12)
    assert name == "google.com"
    assert off == 12 + 12

    # Compressed pointer: \x03www\xC0\x0C (pointing to google.com at offset 12)
    msg2 = msg + b"\x03www\xc0\x0c"
    name2, off2 = decode_dns_name(msg2, 24)
    assert name2 == "www.google.com"


def test_classic_pcap_http_and_tcp_stream():
    """Verify parsing a classic .pcap stream with TCP 3-way handshake and HTTP conversation."""
    base_ts = 1700000000.0

    # 1. TCP SYN
    p1 = build_ethernet_ipv4_tcp_packet(
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
        src_port=49152,
        dst_port=80,
        seq=100,
        flags=0x02,
    )
    # 2. TCP SYN-ACK
    p2 = build_ethernet_ipv4_tcp_packet(
        src_ip="93.184.216.34",
        dst_ip="192.168.1.50",
        src_port=80,
        dst_port=49152,
        seq=500,
        ack=101,
        flags=0x12,
    )
    # 3. TCP ACK
    p3 = build_ethernet_ipv4_tcp_packet(
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
        src_port=49152,
        dst_port=80,
        seq=101,
        ack=501,
        flags=0x10,
    )
    # 4. HTTP GET Request
    http_req_payload = (
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: EFT-Forensic-Client\r\n\r\n"
    )
    p4 = build_ethernet_ipv4_tcp_packet(
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
        src_port=49152,
        dst_port=80,
        seq=101,
        ack=501,
        flags=0x18,
        payload=http_req_payload,
    )
    # 5. HTTP 200 OK Response
    http_resp_payload = b"HTTP/1.1 200 OK\r\nServer: ECS\r\nContent-Type: text/html\r\n\r\n<h1>Forensic Evidence Captured</h1>"
    p5 = build_ethernet_ipv4_tcp_packet(
        src_ip="93.184.216.34",
        dst_ip="192.168.1.50",
        src_port=80,
        dst_port=49152,
        seq=501,
        ack=len(p4),
        flags=0x18,
        payload=http_resp_payload,
    )

    pcap_bytes = create_synthetic_pcap(
        [
            (base_ts + 0.000, p1),
            (base_ts + 0.025, p2),
            (base_ts + 0.026, p3),
            (base_ts + 0.030, p4),
            (base_ts + 0.055, p5),
        ]
    )

    analyzer = NetworkPCAPAnalyzer()
    report = analyzer.analyze(pcap_bytes, filename="http_session.pcap")

    assert isinstance(report, PCAPAnalysisReport)
    assert report.file_format == "PCAP"
    assert report.total_packets == 5
    assert report.total_bytes > 0
    assert report.http_requests_count == 1
    assert "example.com" in report.unique_dns_domains
    assert len(report.flows) >= 1

    # Verify flow latency and conversation metrics
    flow = report.flows[0]
    assert flow.client_ip == "192.168.1.50"
    assert flow.client_port == 49152
    assert flow.server_ip == "93.184.216.34"
    assert flow.server_port == 80
    assert flow.protocol == TransportProtocol.TCP
    assert flow.app_protocol == AppProtocol.HTTP
    assert flow.handshake_rtt_seconds is not None
    assert 0.020 <= flow.handshake_rtt_seconds <= 0.030
    assert flow.http_host == "example.com"


def test_pcapng_dns_and_tls_dissection():
    """Verify PCAPNG parsing with DNS resolution and TLS SNI client hello."""
    base_ts = 1700000100.0

    # 1. DNS Query for c2 domain
    p_dns_q = build_ethernet_ipv4_udp_dns_packet(
        src_ip="10.0.0.15",
        dst_ip="8.8.8.8",
        tx_id=0xAAAA,
        qname="c2.attacker-infrastructure.net",
        is_response=False,
    )
    # 2. DNS Response with Tor Exit node IP (185.220.101.5)
    p_dns_r = build_ethernet_ipv4_udp_dns_packet(
        src_ip="8.8.8.8",
        dst_ip="10.0.0.15",
        tx_id=0xAAAA,
        qname="c2.attacker-infrastructure.net",
        is_response=True,
        answer_ip="185.220.101.5",
    )
    # 3. TLS Client Hello with SNI to Cloudflare
    tls_payload = build_tls_client_hello_payload(sni="api.cloudflare.com")
    p_tls = build_ethernet_ipv4_tcp_packet(
        src_ip="10.0.0.15",
        dst_ip="1.1.1.1",
        src_port=58999,
        dst_port=443,
        flags=0x18,
        payload=tls_payload,
    )

    pcapng_bytes = create_synthetic_pcapng(
        [
            (base_ts + 0.00, p_dns_q),
            (base_ts + 0.02, p_dns_r),
            (base_ts + 0.05, p_tls),
        ]
    )

    analyzer = NetworkPCAPAnalyzer()
    report = analyzer.analyze(pcapng_bytes, filename="tls_and_dns.pcapng")

    assert report.file_format == "PCAPNG"
    assert report.total_packets == 3
    assert report.dns_queries_count >= 1
    assert report.tls_handshakes_count >= 1
    assert "c2.attacker-infrastructure.net" in report.unique_dns_domains
    assert "api.cloudflare.com" in report.unique_snis

    # Verify GeoIP / Cloud enrichment for Cloudflare 1.1.1.1 and Tor IP 185.220.101.5
    assert len(report.geoip_summary) > 0
    # Tor exit node or suspicious alerts
    assert any(
        "Tor Exit Node" in alert or "infrastructure" in alert for alert in report.forensic_alerts
    )
    assert report.threat_score >= 35.0


def test_corrupted_and_truncated_pcap():
    """Verify robust handling of short, corrupted, and invalid files."""
    analyzer = NetworkPCAPAnalyzer()

    # Short file (< 24 bytes)
    res_short = analyzer.analyze(b"\xd4\xc3\xb2\xa1\x02\x00")
    assert res_short.file_format == "Corrupt"
    assert "smaller than minimum PCAP header" in res_short.forensic_alerts[0]

    # Non-PCAP file
    res_non_pcap = analyzer.analyze(b"GIF89a" + b"\x00" * 50)
    assert res_non_pcap.file_format == "Unknown"
    assert any("Unrecognized" in alert for alert in res_non_pcap.forensic_alerts)


def test_file_path_ingestion_and_json_serialization():
    """Verify reading PCAP file from filesystem path and serializing to JSON dict."""
    p_tcp = build_ethernet_ipv4_tcp_packet(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=80
    )
    pcap_data = create_synthetic_pcap([(1700000000.0, p_tcp)])

    with tempfile.TemporaryDirectory() as tmp_dir:
        pcap_file = Path(tmp_dir) / "evidence_stream.pcap"
        pcap_file.write_bytes(pcap_data)

        analyzer = NetworkPCAPAnalyzer()
        report = analyzer.analyze(pcap_file)

        assert report.file_path == str(pcap_file.resolve())
        assert report.filename == "evidence_stream.pcap"
        assert report.total_packets == 1

        # Test to_dict() serialization
        r_dict = report.to_dict()
        assert r_dict["filename"] == "evidence_stream.pcap"
        assert r_dict["file_format"] == "PCAP"
        assert len(r_dict["flows"]) == 1
        assert r_dict["flows"][0]["client_ip"] == "10.0.0.1"
