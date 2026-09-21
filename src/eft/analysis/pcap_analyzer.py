"""High-performance offline PCAP and PCAPNG network stream parser and protocol dissector."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.models.pcap import (
    AppProtocol,
    DNSPacketInfo,
    DNSResourceRecord,
    HTTPRequestInfo,
    HTTPResponseInfo,
    NetworkFlow,
    PacketRecord,
    PCAPAnalysisReport,
    TLSHandshakeInfo,
    TransportProtocol,
)

# DNS Resource Record Type Mapping (RFC 1035 / RFC 3596)
DNS_TYPE_MAP: Dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

DNS_RCODE_MAP: Dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

# TLS Cipher Suite Hex Mapping
TLS_CIPHER_SUITES: Dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
}

TLS_VERSION_MAP: Dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def decode_dns_name(msg: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    """Decode compressed DNS domain name with pointer resolution (RFC 1035)."""
    if depth > 10 or offset >= len(msg):
        return "", offset + 1

    labels: List[str] = []
    orig_offset = offset
    jumped = False

    while offset < len(msg):
        length = msg[offset]
        if length == 0:
            offset += 1
            break

        # Check for DNS pointer compression (top 2 bits set 0xC0)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(msg):
                break
            ptr = ((length & 0x3F) << 8) | msg[offset + 1]
            if not jumped:
                orig_offset = offset + 2
                jumped = True
            sub_name, _ = decode_dns_name(msg, ptr, depth + 1)
            if sub_name:
                labels.append(sub_name)
            break

        offset += 1
        if offset + length > len(msg):
            break
        label_bytes = msg[offset : offset + length]
        labels.append(label_bytes.decode("latin-1", errors="replace"))
        offset += length

    domain_name = ".".join(labels).strip(".")
    return domain_name, (orig_offset if jumped else offset)


class NetworkPCAPAnalyzer:
    """Pure-Python offline PCAP and PCAPNG stream parser and protocol dissector."""

    def __init__(self, net_intel: Optional[NetworkIntelligenceService] = None) -> None:
        self.net_intel = net_intel or NetworkIntelligenceService()
        self.last_parsed_packets: List[PacketRecord] = []

    def extract_packet_records(
        self, data_or_path: Union[bytes, str, Path], filename: Optional[str] = None
    ) -> List[PacketRecord]:
        """Parse capture and return dissected PacketRecord instances."""
        self.analyze(data_or_path, filename=filename)
        return self.last_parsed_packets

    def analyze(
        self, data_or_path: Union[bytes, str, Path], filename: Optional[str] = None
    ) -> PCAPAnalysisReport:
        """Parse packet capture and generate comprehensive forensic analysis report."""
        file_path_str: Optional[str] = None
        if isinstance(data_or_path, (str, Path)):
            p = Path(data_or_path)
            file_path_str = str(p.resolve())
            filename = filename or p.name
            with open(p, "rb") as f:
                data = f.read()
        else:
            data = data_or_path
            filename = filename or "capture.pcap"

        size_bytes = len(data)

        # Multi-algorithm cryptographic hashes (ISO/IEC 27037 Evidence Ledger)
        hashes: Dict[str, str] = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
        }

        forensic_alerts: List[str] = []

        if len(data) < 24:
            return PCAPAnalysisReport(
                file_path=file_path_str,
                filename=filename,
                size_bytes=size_bytes,
                hashes=hashes,
                file_format="Corrupt",
                forensic_alerts=["File size is smaller than minimum PCAP header (24 bytes)"],
                threat_score=0.0,
                verdict="BENIGN",
            )

        # Detect container format & extract raw packet frames: List of (ts_datetime, link_type, wire_len, cap_len, raw_pkt_bytes)
        raw_packets: List[Tuple[datetime, str, int, int, bytes]] = []
        file_format = "PCAP"

        # Check PCAPNG Section Header Block magic (0x0A0D0D0A)
        if data[:4] == b"\x0a\x0d\x0d\x0a":
            file_format = "PCAPNG"
            raw_packets = self._parse_pcapng(data, forensic_alerts)
        elif data[:4] in (
            b"\xa1\xb2\xc3\xd4",
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
            b"\x4d\x3c\xb2\xa1",
        ):
            file_format = "PCAP"
            raw_packets = self._parse_classic_pcap(data, forensic_alerts)
        else:
            forensic_alerts.append(
                f"Unrecognized packet capture container header magic: {data[:4].hex()}"
            )
            return PCAPAnalysisReport(
                file_path=file_path_str,
                filename=filename,
                size_bytes=size_bytes,
                hashes=hashes,
                file_format="Unknown",
                forensic_alerts=forensic_alerts,
                threat_score=20.0,
                verdict="SUSPICIOUS",
            )

        # Dissect packets and populate records
        packet_records: List[PacketRecord] = []
        packets_by_proto: Dict[str, int] = {}
        ip_talker_bytes: Dict[str, int] = {}
        ip_talker_pkts: Dict[str, int] = {}
        port_talker_pkts: Dict[int, int] = {}

        # Conversation flows: flow_key -> dict of flow stats
        flows_dict: Dict[Tuple[str, str, int, str, int], Dict[str, Any]] = {}
        unique_snis: Set[str] = set()
        unique_domains: Set[str] = set()
        unique_external_ips: Set[str] = set()

        dns_count = 0
        http_count = 0
        tls_count = 0

        for pkt_idx, (ts_dt, link_type_str, wire_len, cap_len, pkt_bytes) in enumerate(
            raw_packets, start=1
        ):
            pkt_rec = self._dissect_packet(
                pkt_idx, ts_dt, link_type_str, wire_len, cap_len, pkt_bytes
            )
            packet_records.append(pkt_rec)

            proto_name = pkt_rec.transport_protocol.value
            packets_by_proto[proto_name] = packets_by_proto.get(proto_name, 0) + 1

            # Top talkers metrics
            if pkt_rec.src_ip:
                ip_talker_bytes[pkt_rec.src_ip] = ip_talker_bytes.get(pkt_rec.src_ip, 0) + wire_len
                ip_talker_pkts[pkt_rec.src_ip] = ip_talker_pkts.get(pkt_rec.src_ip, 0) + 1
            if pkt_rec.dst_ip:
                ip_talker_bytes[pkt_rec.dst_ip] = ip_talker_bytes.get(pkt_rec.dst_ip, 0) + wire_len
                ip_talker_pkts[pkt_rec.dst_ip] = ip_talker_pkts.get(pkt_rec.dst_ip, 0) + 1

            if pkt_rec.src_port:
                port_talker_pkts[pkt_rec.src_port] = port_talker_pkts.get(pkt_rec.src_port, 0) + 1
            if pkt_rec.dst_port:
                port_talker_pkts[pkt_rec.dst_port] = port_talker_pkts.get(pkt_rec.dst_port, 0) + 1

            # L7 metrics
            if pkt_rec.dns_info:
                dns_count += 1
                for q in pkt_rec.dns_info.questions:
                    if q.name:
                        unique_domains.add(q.name)
                for a in pkt_rec.dns_info.answers:
                    if a.name:
                        unique_domains.add(a.name)
                    if a.record_type == "A" and a.rdata:
                        unique_external_ips.add(a.rdata)

            if pkt_rec.http_request:
                http_count += 1
                if pkt_rec.http_request.host:
                    unique_domains.add(pkt_rec.http_request.host.split(":")[0])

            if pkt_rec.tls_info:
                tls_count += 1
                if pkt_rec.tls_info.server_name:
                    unique_snis.add(pkt_rec.tls_info.server_name)
                    unique_domains.add(pkt_rec.tls_info.server_name)

            # Flow tracking (IP1:Port1 <-> IP2:Port2)
            if pkt_rec.src_ip and pkt_rec.dst_ip and pkt_rec.src_port and pkt_rec.dst_port:
                ip1, port1 = pkt_rec.src_ip, pkt_rec.src_port
                ip2, port2 = pkt_rec.dst_ip, pkt_rec.dst_port

                # Check external IPs
                for ip_str in (ip1, ip2):
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        if not ip_obj.is_private and not ip_obj.is_loopback:
                            unique_external_ips.add(ip_str)
                    except ValueError:
                        pass

                # Canonical flow key: sorted endpoints
                if (ip1, port1) <= (ip2, port2):
                    c_ip, c_port, s_ip, s_port = ip1, port1, ip2, port2
                    is_forward = True
                else:
                    c_ip, c_port, s_ip, s_port = ip2, port2, ip1, port1
                    is_forward = False

                flow_key = (pkt_rec.transport_protocol.value, c_ip, c_port, s_ip, s_port)

                if flow_key not in flows_dict:
                    flows_dict[flow_key] = {
                        "protocol": pkt_rec.transport_protocol,
                        "client_ip": ip1,
                        "client_port": port1,
                        "server_ip": ip2,
                        "server_port": port2,
                        "start_time": ts_dt,
                        "end_time": ts_dt,
                        "total_packets": 0,
                        "forward_packets": 0,
                        "reverse_packets": 0,
                        "total_bytes": 0,
                        "forward_bytes": 0,
                        "reverse_bytes": 0,
                        "app_protocol": pkt_rec.app_protocol,
                        "sni": pkt_rec.tls_info.server_name if pkt_rec.tls_info else None,
                        "http_host": pkt_rec.http_request.host if pkt_rec.http_request else None,
                        "dns_domain": pkt_rec.dns_info.questions[0].name
                        if (pkt_rec.dns_info and pkt_rec.dns_info.questions)
                        else None,
                        "syn_time": ts_dt
                        if "SYN" in pkt_rec.tcp_flags and "ACK" not in pkt_rec.tcp_flags
                        else None,
                        "syn_ack_time": None,
                        "rtt": None,
                        "tcp_state": "SYN_SENT" if "SYN" in pkt_rec.tcp_flags else "ESTABLISHED",
                    }

                f_data = flows_dict[flow_key]
                f_data["total_packets"] += 1
                f_data["total_bytes"] += wire_len
                f_data["end_time"] = ts_dt

                if is_forward:
                    f_data["forward_packets"] += 1
                    f_data["forward_bytes"] += wire_len
                else:
                    f_data["reverse_packets"] += 1
                    f_data["reverse_bytes"] += wire_len

                # Update L7 metadata in flow
                if pkt_rec.app_protocol != AppProtocol.UNKNOWN:
                    f_data["app_protocol"] = pkt_rec.app_protocol
                if pkt_rec.tls_info and pkt_rec.tls_info.server_name:
                    f_data["sni"] = pkt_rec.tls_info.server_name
                if pkt_rec.http_request and pkt_rec.http_request.host:
                    f_data["http_host"] = pkt_rec.http_request.host
                if pkt_rec.dns_info and pkt_rec.dns_info.questions:
                    f_data["dns_domain"] = pkt_rec.dns_info.questions[0].name

                # TCP Handshake Latency Calculation
                if (
                    "SYN" in pkt_rec.tcp_flags
                    and "ACK" in pkt_rec.tcp_flags
                    and f_data.get("syn_time")
                    and not f_data.get("syn_ack_time")
                ):
                    f_data["syn_ack_time"] = ts_dt
                    rtt_sec = (ts_dt - f_data["syn_time"]).total_seconds()
                    if rtt_sec >= 0:
                        f_data["rtt"] = round(rtt_sec, 4)
                        f_data["tcp_state"] = "ESTABLISHED"
                elif "FIN" in pkt_rec.tcp_flags or "RST" in pkt_rec.tcp_flags:
                    f_data["tcp_state"] = "CLOSED"

        self.last_parsed_packets = packet_records

        # GeoIP & ASN Enrichment for flows and external IPs
        geoip_summary: Dict[str, int] = {}
        ip_intel_cache: Dict[str, Any] = {}

        for ip in unique_external_ips:
            intel = self.net_intel.lookup_ip(ip)
            ip_intel_cache[ip] = intel
            if intel and intel.country:
                country_name = intel.country
                geoip_summary[country_name] = geoip_summary.get(country_name, 0) + 1
            if intel and (intel.is_tor_exit_node or intel.is_vpn):
                tag_name = "Tor Exit Node" if intel.is_tor_exit_node else "Commercial VPN/Proxy"
                forensic_alerts.append(
                    f"Network capture contains traffic/DNS resolution involving known {tag_name} ({ip})"
                )

        network_flows: List[NetworkFlow] = []
        for flow_idx, (f_key, f_data) in enumerate(flows_dict.items(), start=1):
            dur = max(0.0, (f_data["end_time"] - f_data["start_time"]).total_seconds())
            flow_id = f"flow-{flow_idx:04d}-{f_data['client_ip']}:{f_data['client_port']}-{f_data['server_ip']}:{f_data['server_port']}"

            c_intel = ip_intel_cache.get(f_data["client_ip"])
            s_intel = ip_intel_cache.get(f_data["server_ip"])

            c_geo = f"{c_intel.city}, {c_intel.country}" if (c_intel and c_intel.country) else None
            s_geo = f"{s_intel.city}, {s_intel.country}" if (s_intel and s_intel.country) else None
            c_asn = f"AS{c_intel.asn} {c_intel.as_org}" if (c_intel and c_intel.asn) else None
            s_asn = f"AS{s_intel.asn} {s_intel.as_org}" if (s_intel and s_intel.asn) else None
            c_cloud = c_intel.cloud_provider_name if c_intel else None
            s_cloud = s_intel.cloud_provider_name if s_intel else None
            is_vpn_tor = bool(
                (c_intel and (c_intel.is_vpn or c_intel.is_tor_exit_node))
                or (s_intel and (s_intel.is_vpn or s_intel.is_tor_exit_node))
            )

            if is_vpn_tor:
                forensic_alerts.append(
                    f"Flow {flow_id} connects to known Tor Exit Node or VPN/Proxy infrastructure"
                )

            network_flows.append(
                NetworkFlow(
                    flow_id=flow_id,
                    protocol=f_data["protocol"],
                    client_ip=f_data["client_ip"],
                    client_port=f_data["client_port"],
                    server_ip=f_data["server_ip"],
                    server_port=f_data["server_port"],
                    client_geo=c_geo,
                    server_geo=s_geo,
                    client_asn=c_asn,
                    server_asn=s_asn,
                    client_cloud_tag=c_cloud,
                    server_cloud_tag=s_cloud,
                    is_vpn_tor=is_vpn_tor,
                    total_packets=f_data["total_packets"],
                    forward_packets=f_data["forward_packets"],
                    reverse_packets=f_data["reverse_packets"],
                    total_bytes=f_data["total_bytes"],
                    forward_bytes=f_data["forward_bytes"],
                    reverse_bytes=f_data["reverse_bytes"],
                    start_time=f_data["start_time"],
                    end_time=f_data["end_time"],
                    duration_seconds=round(dur, 3),
                    handshake_rtt_seconds=f_data.get("rtt"),
                    app_protocol=f_data["app_protocol"],
                    sni=f_data["sni"],
                    http_host=f_data["http_host"],
                    dns_domain=f_data["dns_domain"],
                    tcp_state=f_data["tcp_state"],
                )
            )

        # Sort top talkers
        top_talkers_ips = [
            {"ip": ip, "bytes": ip_talker_bytes[ip], "packets": ip_talker_pkts[ip]}
            for ip in sorted(
                ip_talker_bytes.keys(), key=lambda x: ip_talker_bytes[x], reverse=True
            )[:10]
        ]
        top_talkers_ports = [
            {"port": port, "packets": count}
            for port, count in sorted(port_talker_pkts.items(), key=lambda x: x[1], reverse=True)[
                :10
            ]
        ]

        # Overall Time and Threat Assessment
        total_packets = len(raw_packets)
        total_bytes = sum(r[2] for r in raw_packets)
        start_time = raw_packets[0][0] if raw_packets else None
        end_time = raw_packets[-1][0] if raw_packets else None
        duration_seconds = (
            round((end_time - start_time).total_seconds(), 3) if (start_time and end_time) else 0.0
        )

        threat_score = 0.0
        if any(f.is_vpn_tor for f in network_flows) or any(
            (
                intel
                and (getattr(intel, "is_tor_exit_node", False) or getattr(intel, "is_vpn", False))
            )
            for intel in ip_intel_cache.values()
        ):
            threat_score += 35.0
        if any(p == 4444 or p == 1337 or p == 6667 for p in port_talker_pkts.keys()):
            threat_score += 25.0
            forensic_alerts.append(
                "Traffic detected on known suspicious default C2/IRC ports (4444, 1337, 6667)"
            )

        threat_score = min(100.0, round(threat_score, 1))
        verdict = "BENIGN"
        if threat_score >= 60.0:
            verdict = "MALICIOUS"
        elif threat_score >= 25.0:
            verdict = "SUSPICIOUS"

        link_type = raw_packets[0][1] if raw_packets else "Ethernet"

        return PCAPAnalysisReport(
            file_path=file_path_str,
            filename=filename,
            size_bytes=size_bytes,
            hashes=hashes,
            file_format=file_format,
            total_packets=total_packets,
            total_bytes=total_bytes,
            duration_seconds=duration_seconds,
            start_time=start_time,
            end_time=end_time,
            link_type=link_type,
            packets_by_protocol=packets_by_proto,
            top_talkers_ips=top_talkers_ips,
            top_talkers_ports=top_talkers_ports,
            flows=network_flows,
            dns_queries_count=dns_count,
            http_requests_count=http_count,
            tls_handshakes_count=tls_count,
            unique_snis=sorted(list(unique_snis)),
            unique_dns_domains=sorted(list(unique_domains)),
            geoip_summary=geoip_summary,
            forensic_alerts=forensic_alerts,
            threat_score=threat_score,
            verdict=verdict,
        )

    def _parse_classic_pcap(
        self, data: bytes, alerts: List[str]
    ) -> List[Tuple[datetime, str, int, int, bytes]]:
        """Parse classic .pcap container file."""
        magic = data[:4]
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            endian = "<"

        is_nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")

        _magic, _v_maj, _v_min, _thiszone, _sigfigs, _snaplen, network = struct.unpack_from(
            endian + "IHHIIII", data, 0
        )

        link_type_map = {
            1: "Ethernet",
            12: "Raw IP",
            101: "Raw IP",
            113: "Linux Cooked (SLL)",
            276: "Linux Cooked v2 (SLL2)",
        }
        link_type_str = link_type_map.get(network, f"LinkType_{network}")

        packets: List[Tuple[datetime, str, int, int, bytes]] = []
        offset = 24

        while offset + 16 <= len(data):
            ts_sec, ts_sub, incl_len, orig_len = struct.unpack_from(endian + "IIII", data, offset)
            offset += 16

            if offset + incl_len > len(data):
                alerts.append(f"Truncated PCAP packet at byte offset {offset}")
                incl_len = max(0, len(data) - offset)

            pkt_bytes = data[offset : offset + incl_len]
            offset += incl_len

            ts_float = ts_sec + (ts_sub / 1_000_000_000.0 if is_nano else ts_sub / 1_000_000.0)
            try:
                dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                dt = datetime.now(timezone.utc)

            packets.append((dt, link_type_str, orig_len, incl_len, pkt_bytes))

        return packets

    def _parse_pcapng(
        self, data: bytes, alerts: List[str]
    ) -> List[Tuple[datetime, str, int, int, bytes]]:
        """Parse PCAPNG block structure."""
        packets: List[Tuple[datetime, str, int, int, bytes]] = []
        offset = 0
        endian = "<"
        link_type_str = "Ethernet"

        while offset + 8 <= len(data):
            block_type = struct.unpack_from("<I", data, offset)[0]
            # Check endianness from SHB magic if this is Section Header Block
            if block_type == 0x0A0D0D0A and offset + 12 <= len(data):
                bom = data[offset + 8 : offset + 12]
                endian = ">" if bom == b"\x1a\x2b\x3c\x4d" else "<"

            block_type, block_len = struct.unpack_from(endian + "II", data, offset)
            if block_len < 12 or offset + block_len > len(data):
                alerts.append(f"Invalid PCAPNG block length ({block_len}) at offset {offset}")
                break

            if block_type == 0x00000001:  # IDB (Interface Description Block)
                if offset + 12 <= len(data):
                    link_type = struct.unpack_from(endian + "H", data, offset + 8)[0]
                    link_type_map = {
                        1: "Ethernet",
                        12: "Raw IP",
                        101: "Raw IP",
                        113: "Linux Cooked (SLL)",
                    }
                    link_type_str = link_type_map.get(link_type, f"LinkType_{link_type}")

            elif block_type == 0x00000006:  # EPB (Enhanced Packet Block)
                if offset + 28 <= len(data):
                    _if_id, ts_high, ts_low, caplen, wirelen = struct.unpack_from(
                        endian + "IIIII", data, offset + 8
                    )
                    ts_raw = (ts_high << 32) | ts_low
                    ts_float = ts_raw / 1_000_000.0  # Default microsecond resolution
                    try:
                        dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
                    except (ValueError, OSError, OverflowError):
                        dt = datetime.now(timezone.utc)

                    pkt_bytes = data[offset + 28 : offset + 28 + caplen]
                    packets.append((dt, link_type_str, wirelen, caplen, pkt_bytes))

            elif block_type == 0x00000003:  # SPB (Simple Packet Block)
                if offset + 12 <= len(data):
                    wirelen = struct.unpack_from(endian + "I", data, offset + 8)[0]
                    caplen = min(wirelen, block_len - 16)
                    pkt_bytes = data[offset + 12 : offset + 12 + caplen]
                    dt = datetime.now(timezone.utc)
                    packets.append((dt, link_type_str, wirelen, caplen, pkt_bytes))

            # Move to next 32-bit aligned block
            offset += block_len
            if block_len % 4 != 0:
                offset += 4 - (block_len % 4)

        return packets

    def _dissect_packet(
        self,
        pkt_num: int,
        ts_dt: datetime,
        link_type_str: str,
        wire_len: int,
        cap_len: int,
        raw: bytes,
    ) -> PacketRecord:
        """Dissect raw bytes across Layer 2, Layer 3, Layer 4, and Application layer."""
        src_mac: Optional[str] = None
        dst_mac: Optional[str] = None
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        ip_ver: Optional[int] = None
        ttl: Optional[int] = None
        proto = TransportProtocol.OTHER
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: List[str] = []
        tcp_seq: Optional[int] = None
        tcp_ack: Optional[int] = None
        payload = b""

        # Layer 2: Ethernet II Dissection
        l3_data = raw
        if link_type_str == "Ethernet" and len(raw) >= 14:
            dst_mac = ":".join(f"{b:02x}" for b in raw[:6])
            src_mac = ":".join(f"{b:02x}" for b in raw[6:12])
            ethertype = struct.unpack_from(">H", raw, 12)[0]
            l3_offset = 14
            if ethertype == 0x8100 and len(raw) >= 18:  # 802.1Q VLAN Tagged
                ethertype = struct.unpack_from(">H", raw, 16)[0]
                l3_offset = 18
            l3_data = raw[l3_offset:]
        elif "SLL" in link_type_str and len(raw) >= 16:  # Linux Cooked SLL
            ethertype = struct.unpack_from(">H", raw, 14)[0]
            l3_data = raw[16:]

        # Layer 3: Network Layer (IPv4 / IPv6 / ARP)
        l4_data = b""
        l4_proto_num = -1

        if len(l3_data) >= 20 and (l3_data[0] >> 4) == 4:  # IPv4
            ip_ver = 4
            ihl = (l3_data[0] & 0x0F) * 4
            if len(l3_data) >= ihl:
                total_len, _ident, _flags_frag, ttl, l4_proto_num, _chk = struct.unpack_from(
                    ">HHHBBH", l3_data, 2
                )
                src_ip = socket.inet_ntoa(l3_data[12:16])
                dst_ip = socket.inet_ntoa(l3_data[16:20])
                actual_end = min(len(l3_data), total_len) if total_len > 0 else len(l3_data)
                l4_data = l3_data[ihl:actual_end]

        elif len(l3_data) >= 40 and (l3_data[0] >> 4) == 6:  # IPv6
            ip_ver = 6
            _ver_tc_fl, payload_len, l4_proto_num, hop_limit = struct.unpack_from(
                ">IHBB", l3_data, 0
            )
            ttl = hop_limit
            src_ip = socket.inet_ntop(socket.AF_INET6, l3_data[8:24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, l3_data[24:40])
            l4_data = l3_data[40 : 40 + payload_len]

        elif len(l3_data) >= 28 and len(raw) >= 14 and raw[12:14] == b"\x08\x06":  # ARP
            proto = TransportProtocol.ARP
            _htype, _ptype, hlen, plen, _opcode = struct.unpack_from(">HHBBH", l3_data, 0)
            if hlen == 6 and plen == 4:
                src_ip = socket.inet_ntoa(l3_data[14:18])
                dst_ip = socket.inet_ntoa(l3_data[24:28])

        # Layer 4: Transport Layer (TCP / UDP / ICMP)
        if l4_proto_num == 6 and len(l4_data) >= 20:  # TCP
            proto = TransportProtocol.TCP
            src_port, dst_port = struct.unpack_from(">HH", l4_data, 0)
            tcp_seq = struct.unpack_from(">I", l4_data, 4)[0]
            tcp_ack = struct.unpack_from(">I", l4_data, 8)[0]
            data_offset = (l4_data[12] >> 4) * 4
            flags_byte = l4_data[13]

            if flags_byte & 0x02:
                tcp_flags.append("SYN")
            if flags_byte & 0x10:
                tcp_flags.append("ACK")
            if flags_byte & 0x01:
                tcp_flags.append("FIN")
            if flags_byte & 0x04:
                tcp_flags.append("RST")
            if flags_byte & 0x08:
                tcp_flags.append("PSH")
            if flags_byte & 0x20:
                tcp_flags.append("URG")

            if len(l4_data) >= data_offset:
                payload = l4_data[data_offset:]

        elif l4_proto_num == 17 and len(l4_data) >= 8:  # UDP
            proto = TransportProtocol.UDP
            src_port, dst_port, udp_len, _chk = struct.unpack_from(">HHHH", l4_data, 0)
            payload = l4_data[8 : min(len(l4_data), udp_len)] if udp_len >= 8 else l4_data[8:]

        elif l4_proto_num == 1:  # ICMP
            proto = TransportProtocol.ICMP
            payload = l4_data

        elif l4_proto_num == 58:  # ICMPv6
            proto = TransportProtocol.ICMPV6
            payload = l4_data

        # Layer 7: Application Layer Dissectors
        app_proto = AppProtocol.UNKNOWN
        dns_info: Optional[DNSPacketInfo] = None
        http_req: Optional[HTTPRequestInfo] = None
        http_resp: Optional[HTTPResponseInfo] = None
        tls_info: Optional[TLSHandshakeInfo] = None

        # Dissect DNS (Port 53 or 5353)
        if (src_port in (53, 5353) or dst_port in (53, 5353)) and len(payload) >= 12:
            dns_info = self._dissect_dns(payload)
            if dns_info:
                app_proto = AppProtocol.DNS

        # Dissect HTTP
        if not dns_info and payload:
            if payload.startswith(
                (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"CONNECT ")
            ):
                http_req = self._dissect_http_request(payload)
                if http_req:
                    app_proto = AppProtocol.HTTP
            elif payload.startswith((b"HTTP/1.0 ", b"HTTP/1.1 ", b"HTTP/2.0 ")):
                http_resp = self._dissect_http_response(payload)
                if http_resp:
                    app_proto = AppProtocol.HTTP

        # Dissect TLS Record / Handshake
        if not dns_info and not http_req and not http_resp and len(payload) >= 5:
            if payload[0] == 22 and payload[1:3] in (
                b"\x03\x01",
                b"\x03\x02",
                b"\x03\x03",
                b"\x03\x04",
            ):
                tls_info = self._dissect_tls_handshake(payload)
                if tls_info:
                    app_proto = AppProtocol.TLS
            elif src_port in (443, 8443) or dst_port in (443, 8443):
                app_proto = AppProtocol.TLS

        return PacketRecord(
            packet_num=pkt_num,
            timestamp=ts_dt,
            wire_len=wire_len,
            cap_len=cap_len,
            link_type=link_type_str,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_version=ip_ver,
            ttl=ttl,
            transport_protocol=proto,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            payload_len=len(payload),
            app_protocol=app_proto,
            dns_info=dns_info,
            http_request=http_req,
            http_response=http_resp,
            tls_info=tls_info,
        )

    def _dissect_dns(self, payload: bytes) -> Optional[DNSPacketInfo]:
        """Dissect DNS payload into questions, answers, and resource records."""
        try:
            tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
                ">HHHHHH", payload, 0
            )
            is_resp = bool(flags & 0x8000)
            opcode = (flags >> 11) & 0x0F
            rcode = flags & 0x0F
            rcode_name = DNS_RCODE_MAP.get(rcode, f"RCODE_{rcode}")

            offset = 12
            questions: List[DNSResourceRecord] = []
            answers: List[DNSResourceRecord] = []
            authorities: List[DNSResourceRecord] = []
            additionals: List[DNSResourceRecord] = []

            # Parse Question Records
            for _ in range(min(qdcount, 20)):
                if offset >= len(payload):
                    break
                qname, offset = decode_dns_name(payload, offset)
                if offset + 4 > len(payload):
                    break
                qtype_num, _qclass_num = struct.unpack_from(">HH", payload, offset)
                offset += 4
                qtype_str = DNS_TYPE_MAP.get(qtype_num, f"TYPE_{qtype_num}")
                questions.append(
                    DNSResourceRecord(
                        name=qname, record_type=qtype_str, record_class="IN", ttl=0, rdata=""
                    )
                )

            # Helper for Resource Records (Answers, Authorities, Additionals)
            def parse_rrs(count: int) -> List[DNSResourceRecord]:
                nonlocal offset
                rrs: List[DNSResourceRecord] = []
                for _ in range(min(count, 50)):
                    if offset >= len(payload):
                        break
                    rr_name, offset = decode_dns_name(payload, offset)
                    if offset + 10 > len(payload):
                        break
                    rr_type, _rr_class, rr_ttl, rdlength = struct.unpack_from(
                        ">HHIH", payload, offset
                    )
                    offset += 10
                    type_str = DNS_TYPE_MAP.get(rr_type, f"TYPE_{rr_type}")
                    rdata_raw = payload[offset : offset + rdlength]
                    offset += rdlength

                    rdata_str = ""
                    if rr_type == 1 and len(rdata_raw) == 4:  # A record (IPv4)
                        rdata_str = socket.inet_ntoa(rdata_raw)
                    elif rr_type == 28 and len(rdata_raw) == 16:  # AAAA record (IPv6)
                        rdata_str = socket.inet_ntop(socket.AF_INET6, rdata_raw)
                    elif rr_type in (2, 5, 12):  # NS, CNAME, PTR
                        rdata_str, _ = decode_dns_name(payload, offset - rdlength)
                    elif rr_type == 15 and len(rdata_raw) >= 3:  # MX
                        pref = struct.unpack_from(">H", rdata_raw, 0)[0]
                        mx_name, _ = decode_dns_name(payload, offset - rdlength + 2)
                        rdata_str = f"{pref} {mx_name}"
                    elif rr_type == 16 and rdata_raw:  # TXT
                        txt_len = rdata_raw[0]
                        rdata_str = rdata_raw[1 : 1 + txt_len].decode("latin-1", errors="replace")
                    else:
                        rdata_str = rdata_raw.hex()

                    rrs.append(
                        DNSResourceRecord(
                            name=rr_name,
                            record_type=type_str,
                            record_class="IN",
                            ttl=rr_ttl,
                            rdata=rdata_str,
                        )
                    )
                return rrs

            answers = parse_rrs(ancount)
            authorities = parse_rrs(nscount)
            additionals = parse_rrs(arcount)

            return DNSPacketInfo(
                transaction_id=tx_id,
                is_response=is_resp,
                opcode=opcode,
                rcode=rcode,
                rcode_name=rcode_name,
                questions=questions,
                answers=answers,
                authorities=authorities,
                additionals=additionals,
            )
        except Exception:
            return None

    def _dissect_http_request(self, payload: bytes) -> Optional[HTTPRequestInfo]:
        """Dissect HTTP request line and headers."""
        try:
            head_part = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
            lines = head_part.split("\r\n")
            req_line = lines[0].split(" ")
            if len(req_line) < 3:
                return None

            method, uri, version = req_line[0], req_line[1], req_line[2]
            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k.strip().lower()] = v.strip()

            body_snip = None
            if b"\r\n\r\n" in payload:
                body_raw = payload.split(b"\r\n\r\n", 1)[1]
                if body_raw:
                    body_snip = body_raw[:256].decode("latin-1", errors="replace")

            return HTTPRequestInfo(
                method=method,
                uri=uri,
                version=version,
                host=headers.get("host"),
                user_agent=headers.get("user-agent"),
                referer=headers.get("referer"),
                content_type=headers.get("content-type"),
                headers=headers,
                body_snippet=body_snip,
                body_length=len(payload.split(b"\r\n\r\n", 1)[1]) if b"\r\n\r\n" in payload else 0,
            )
        except Exception:
            return None

    def _dissect_http_response(self, payload: bytes) -> Optional[HTTPResponseInfo]:
        """Dissect HTTP response status line and headers."""
        try:
            head_part = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
            lines = head_part.split("\r\n")
            status_line = lines[0].split(" ", 2)
            if len(status_line) < 2:
                return None

            version = status_line[0]
            status_code = int(status_line[1])
            reason_phrase = status_line[2] if len(status_line) > 2 else "OK"

            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k.strip().lower()] = v.strip()

            body_snip = None
            if b"\r\n\r\n" in payload:
                body_raw = payload.split(b"\r\n\r\n", 1)[1]
                if body_raw:
                    body_snip = body_raw[:256].decode("latin-1", errors="replace")

            return HTTPResponseInfo(
                version=version,
                status_code=status_code,
                reason_phrase=reason_phrase,
                server=headers.get("server"),
                content_type=headers.get("content-type"),
                location=headers.get("location"),
                headers=headers,
                body_snippet=body_snip,
                body_length=len(payload.split(b"\r\n\r\n", 1)[1]) if b"\r\n\r\n" in payload else 0,
            )
        except Exception:
            return None

    def _dissect_tls_handshake(self, payload: bytes) -> Optional[TLSHandshakeInfo]:
        """Dissect TLS Client Hello, extracting SNI and Cipher Suites."""
        try:
            rec_type = payload[0]
            tls_ver_raw = struct.unpack_from(">H", payload, 1)[0]
            tls_ver_str = TLS_VERSION_MAP.get(tls_ver_raw, f"TLS ({hex(tls_ver_raw)})")

            if len(payload) < 9:
                return None

            hs_type = payload[5]
            if hs_type != 1:  # Client Hello
                return TLSHandshakeInfo(
                    content_type=rec_type,
                    tls_version=tls_ver_str,
                    handshake_type=f"Handshake_{hs_type}",
                )

            # Client Hello parsing
            client_ver = struct.unpack_from(">H", payload, 9)[0]
            offset = 11 + 32  # Skip client random (32 bytes)

            if offset >= len(payload):
                return None

            sess_id_len = payload[offset]
            offset += 1 + sess_id_len

            if offset + 2 > len(payload):
                return None

            cipher_len = struct.unpack_from(">H", payload, offset)[0]
            offset += 2

            ciphers: List[str] = []
            cipher_ids: List[int] = []
            for _ in range(cipher_len // 2):
                if offset + 2 > len(payload):
                    break
                c_id = struct.unpack_from(">H", payload, offset)[0]
                offset += 2
                cipher_ids.append(c_id)
                ciphers.append(TLS_CIPHER_SUITES.get(c_id, f"0x{c_id:04X}"))

            if offset >= len(payload):
                return None

            comp_len = payload[offset]
            offset += 1 + comp_len

            server_name: Optional[str] = None
            supported_versions: List[str] = []
            ext_types: List[int] = []

            if offset + 2 <= len(payload):
                ext_total_len = struct.unpack_from(">H", payload, offset)[0]
                offset += 2
                ext_end = min(len(payload), offset + ext_total_len)

                while offset + 4 <= ext_end:
                    ext_type, ext_len = struct.unpack_from(">HH", payload, offset)
                    offset += 4
                    ext_types.append(ext_type)

                    # Extension 0x0000: Server Name Indication (SNI)
                    if ext_type == 0x0000 and offset + ext_len <= len(payload):
                        if ext_len >= 5:
                            _sn_list_len, sn_type, sn_len = struct.unpack_from(
                                ">HBH", payload, offset
                            )
                            if sn_type == 0 and offset + 5 + sn_len <= len(payload):
                                server_name = payload[offset + 5 : offset + 5 + sn_len].decode(
                                    "latin-1", errors="replace"
                                )

                    # Extension 0x002B: Supported Versions (TLS 1.3 indicator)
                    elif ext_type == 0x002B and offset + ext_len <= len(payload):
                        if ext_len >= 2:
                            sv_len = payload[offset]
                            for i in range(sv_len // 2):
                                if offset + 1 + (i * 2) + 2 <= len(payload):
                                    v_id = struct.unpack_from(">H", payload, offset + 1 + (i * 2))[
                                        0
                                    ]
                                    supported_versions.append(
                                        TLS_VERSION_MAP.get(v_id, f"0x{v_id:04X}")
                                    )

                    offset += ext_len

            # JA3 String & Hash
            ja3_str = f"{client_ver},{'-'.join(str(c) for c in cipher_ids)},{'-'.join(str(e) for e in ext_types)},,"
            ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()

            return TLSHandshakeInfo(
                content_type=rec_type,
                tls_version=tls_ver_str,
                handshake_type="Client Hello",
                server_name=server_name,
                cipher_suites=ciphers,
                supported_versions=supported_versions,
                ja3_string=ja3_str,
                ja3_hash=ja3_hash,
            )
        except Exception:
            return None
