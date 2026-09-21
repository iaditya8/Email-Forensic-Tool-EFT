"""Forensic Windows Event Log (EVTX) and Sysmon correlation engine.

Provides pure-Python parsing of binary EVTX files (ELF format, 64KB chunks, BinXml records),
Microsoft Sysmon event analysis (Event IDs 1, 3, 7, 11) and Security Event ID 4688,
hierarchical process tree reconstruction, and MITRE ATT&CK LOLBAS anomaly detection.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from eft.models.evtx import (
    EVTXAnalysisReport,
    ProcessThreatClassification,
    ProcessTreeNode,
    SuspiciousProcessAnomaly,
    SysmonFileCreateEvent,
    SysmonImageLoadEvent,
    SysmonNetworkEvent,
    SysmonProcessCreateEvent,
)


class WindowsLogAnalyzer:
    """Forensic Windows Event Log analyzer and Sysmon process correlation engine."""

    # EVTX Container Constants
    EVTX_FILE_MAGIC = b"ElfFile\x00"
    EVTX_CHUNK_MAGIC = b"ElfChnk\x00"
    EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"  # 0x00002A2A
    FILETIME_EPOCH_DIFF = 116444736000000000  # Hundreds of nanoseconds between 1601 and 1970

    # Suspicious Office Binaries (Parent Process)
    OFFICE_PARENTS = {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "msaccess.exe",
        "eqnedt32.exe",
        "mspub.exe",
        "visio.exe",
    }

    # Suspicious Web Server Binaries (Parent Process)
    WEB_SERVER_PARENTS = {
        "w3wp.exe",
        "httpd.exe",
        "nginx.exe",
        "tomcat.exe",
        "tomcat8.exe",
        "tomcat9.exe",
        "tomcat10.exe",
        "java.exe",
        "php-cgi.exe",
        "php.exe",
        "node.exe",
    }

    # Suspicious System Binaries that shouldn't spawn interactive shells
    SUSPICIOUS_SYSTEM_PARENTS = {
        "spoolsv.exe",
        "services.exe",
        "smss.exe",
        "lsass.exe",
        "csrss.exe",
    }

    # Script/Shell Execution Binaries (Child Process)
    SHELL_CHILDREN = {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "cscript.exe",
        "wscript.exe",
        "mshta.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "curl.exe",
        "vssadmin.exe",
        "schtasks.exe",
        "whoami.exe",
        "net.exe",
        "net1.exe",
        "ipconfig.exe",
        "bash.exe",
        "sh.exe",
    }

    def __init__(self) -> None:
        """Initialize the Windows Log Analyzer."""
        pass

    @staticmethod
    def filetime_to_datetime(ft: int) -> datetime:
        """Convert a Windows 64-bit FILETIME integer to a UTC datetime."""
        if ft < WindowsLogAnalyzer.FILETIME_EPOCH_DIFF:
            return datetime.fromtimestamp(0, tz=timezone.utc)
        try:
            timestamp_sec = (ft - WindowsLogAnalyzer.FILETIME_EPOCH_DIFF) / 10000000.0
            return datetime.fromtimestamp(timestamp_sec, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return datetime.fromtimestamp(0, tz=timezone.utc)

    def analyze_file(self, file_path: Union[str, Path]) -> EVTXAnalysisReport:
        """Analyze a Windows EVTX log file from a local filesystem path.

        Args:
            file_path: Path to the .evtx or log file.

        Returns:
            EVTXAnalysisReport containing correlated process trees, anomalies, and IOCs.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        raw_bytes = path.read_bytes()
        return self.analyze_bytes(raw_bytes, filename=path.name, file_path=str(path.resolve()))

    def analyze_bytes(
        self,
        raw_bytes: bytes,
        filename: str = "memory_capture.evtx",
        file_path: Optional[str] = None,
    ) -> EVTXAnalysisReport:
        """Analyze raw EVTX binary bytes, exported XML, or JSON event records.

        Args:
            raw_bytes: Binary payload of EVTX, XML, or JSON log file.
            filename: Name of the artifact being analyzed.
            file_path: Optional full filesystem path.

        Returns:
            EVTXAnalysisReport with complete DFIR triage and correlation.
        """
        md5_hash = hashlib.md5(raw_bytes).hexdigest()
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        hashes = {"md5": md5_hash, "sha256": sha256_hash}

        # Determine file format and parse records
        if (
            raw_bytes.startswith(self.EVTX_FILE_MAGIC)
            or self.EVTX_CHUNK_MAGIC in raw_bytes
            or self.EVTX_RECORD_MAGIC in raw_bytes
        ):
            raw_records = self._parse_binary_evtx(raw_bytes)
            if not raw_records:
                raw_records = self._parse_text_events(raw_bytes)
        else:
            raw_records = self._parse_text_events(raw_bytes)
            if not raw_records:
                raw_records = self._carve_evtx_records(raw_bytes)

        return self._correlate_and_generate_report(
            raw_records=raw_records,
            filename=filename,
            file_path=file_path,
            size_bytes=len(raw_bytes),
            hashes=hashes,
        )

    def analyze_events(
        self,
        events: List[Dict[str, Any]],
        filename: str = "in_memory_events.json",
        file_path: Optional[str] = None,
    ) -> EVTXAnalysisReport:
        """Analyze a pre-parsed list of Windows Event dictionary records.

        Args:
            events: List of parsed event dictionaries (containing EventID, EventData, etc.).
            filename: Identifier for the log source.
            file_path: Optional file path.

        Returns:
            EVTXAnalysisReport with complete DFIR triage and correlation.
        """
        serialized = json.dumps(events, default=str).encode("utf-8")
        hashes = {
            "md5": hashlib.md5(serialized).hexdigest(),
            "sha256": hashlib.sha256(serialized).hexdigest(),
        }
        return self._correlate_and_generate_report(
            raw_records=events,
            filename=filename,
            file_path=file_path,
            size_bytes=len(serialized),
            hashes=hashes,
        )

    # -------------------------------------------------------------------------
    # Binary EVTX Parsing Subsystem
    # -------------------------------------------------------------------------

    def _parse_binary_evtx(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse raw binary EVTX chunks and extract event records."""
        records: List[Dict[str, Any]] = []
        if len(data) < 4096:
            return self._carve_evtx_records(data)

        # Parse File Header (4096 bytes)
        # Header layout:
        # 0x00: Magic "ElfFile\x00" (8 bytes)
        # 0x08: First chunk number (uint64)
        # 0x10: Last chunk number (uint64)
        # 0x18: Next record identifier (uint64)
        # 0x20: Header size (uint32)
        # 0x28: Header block size (uint16)
        # 0x2A: Number of chunks (uint16)

        file_header_size = struct.unpack_from("<I", data, 0x20)[0]
        if file_header_size == 0 or file_header_size > len(data):
            file_header_size = 4096

        offset = file_header_size
        chunk_size = 65536  # 64 KB

        while offset + chunk_size <= len(data):
            chunk_data = data[offset : offset + chunk_size]
            if chunk_data.startswith(self.EVTX_CHUNK_MAGIC):
                chunk_records = self._parse_evtx_chunk(chunk_data)
                records.extend(chunk_records)
            offset += chunk_size

        # If no standard chunks found, scan records directly by magic signature
        if not records:
            records = self._carve_evtx_records(data)

        return records

    def _parse_evtx_chunk(self, chunk: bytes) -> List[Dict[str, Any]]:
        """Parse an individual 64KB EVTX chunk."""
        records: List[Dict[str, Any]] = []
        if len(chunk) < 512 or not chunk.startswith(self.EVTX_CHUNK_MAGIC):
            return records

        # Chunk Header:
        # 0x28: Header size (uint32, 512)
        # 0x2C: Last event record data offset (uint32)
        # 0x30: Free space offset (uint32)
        # 0x80 - 0x200: Event record offset table (uint32 entries)
        free_space_offset = struct.unpack_from("<I", chunk, 0x30)[0]
        if free_space_offset == 0 or free_space_offset > len(chunk):
            free_space_offset = len(chunk)

        # Parse record offset table (from 0x80 to 0x200, up to 64 offsets)
        offsets_set: Set[int] = set()
        for tbl_idx in range(0x80, 0x200, 4):
            rec_off = struct.unpack_from("<I", chunk, tbl_idx)[0]
            if 0 < rec_off < free_space_offset:
                offsets_set.add(rec_off)

        sorted_offsets = sorted(offsets_set)
        for rec_off in sorted_offsets:
            if rec_off + 24 <= len(chunk):
                rec = self._parse_single_record(chunk[rec_off:])
                if rec:
                    records.append(rec)

        # If offset table was empty/corrupt, scan sequentially from 0x200
        if not records:
            curr = 512
            while curr + 24 < free_space_offset:
                if chunk[curr : curr + 4] == self.EVTX_RECORD_MAGIC:
                    rec_size = struct.unpack_from("<I", chunk, curr + 4)[0]
                    if rec_size >= 24 and curr + rec_size <= len(chunk):
                        rec = self._parse_single_record(chunk[curr : curr + rec_size])
                        if rec:
                            records.append(rec)
                        curr += rec_size
                        continue
                curr += 4

        return records

    def _parse_single_record(self, record_data: bytes) -> Optional[Dict[str, Any]]:
        """Parse an individual EVTX binary record header and payload."""
        if len(record_data) < 24:
            return None

        magic = record_data[:4]
        if magic != self.EVTX_RECORD_MAGIC:
            return None

        size, record_id, written_filetime = struct.unpack_from("<IQ8xQ", record_data, 4)
        if size < 24 or size > len(record_data):
            size = len(record_data)

        timestamp = self.filetime_to_datetime(written_filetime)
        payload = record_data[24:size]

        # Extract textual strings and XML data from the BinXml payload
        extracted_info = self._extract_binxml_content(payload)
        extracted_info["RecordId"] = record_id
        if "Timestamp" not in extracted_info:
            extracted_info["Timestamp"] = timestamp

        return extracted_info

    def _carve_evtx_records(self, data: bytes) -> List[Dict[str, Any]]:
        """Carve EVTX records by scanning for the record magic identifier."""
        records: List[Dict[str, Any]] = []
        pos = 0
        while True:
            pos = data.find(self.EVTX_RECORD_MAGIC, pos)
            if pos == -1 or pos + 24 > len(data):
                break

            size = struct.unpack_from("<I", data, pos + 4)[0]
            if 24 <= size <= 65536 and pos + size <= len(data):
                rec = self._parse_single_record(data[pos : pos + size])
                if rec:
                    records.append(rec)
                pos += size
            else:
                pos += 4
        return records

    def _extract_binxml_content(self, payload: bytes) -> Dict[str, Any]:
        """Extract key-value parameters and XML structures from BinXml / binary record payload."""
        result: Dict[str, Any] = {
            "EventID": 0,
            "EventData": {},
        }

        # Strategy 1: Look for embedded UTF-8 or UTF-16 XML strings
        try:
            utf8_text = payload.decode("utf-8", errors="ignore")
            if "<Event" in utf8_text:
                xml_start = utf8_text.find("<Event")
                xml_end = utf8_text.find("</Event>", xml_start)
                if xml_end != -1:
                    parsed = self._parse_xml_event_string(utf8_text[xml_start : xml_end + 8])
                    if parsed:
                        return parsed
        except Exception:
            pass

        try:
            utf16_text = payload.decode("utf-16le", errors="ignore")
            if "<Event" in utf16_text:
                xml_start = utf16_text.find("<Event")
                xml_end = utf16_text.find("</Event>", xml_start)
                if xml_end != -1:
                    parsed = self._parse_xml_event_string(utf16_text[xml_start : xml_end + 8])
                    if parsed:
                        return parsed
        except Exception:
            pass

        # Strategy 2: Extract UTF-16LE and ASCII string tokens from BinXml stream
        strings_found: List[str] = []

        # Extract UTF-16LE strings
        utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00)+")
        for match in utf16_pattern.finditer(payload):
            try:
                s = match.group(0).decode("utf-16le").strip()
                if s:
                    strings_found.append(s)
            except Exception:
                continue

        # Extract ASCII strings
        ascii_pattern = re.compile(rb"[\x20-\x7e]{3,}")
        for match in ascii_pattern.finditer(payload):
            try:
                s = match.group(0).decode("ascii").strip()
                if s and s not in strings_found:
                    strings_found.append(s)
            except Exception:
                continue

        # Reconstruct fields from extracted strings
        event_data: Dict[str, Any] = {}
        for idx, s in enumerate(strings_found):
            # Check for Event ID
            if s.isdigit() and int(s) in {
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                22,
                4688,
            }:
                result["EventID"] = int(s)

            # Check for GUID format
            if re.match(
                r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$",
                s,
            ):
                if "ProcessGuid" not in event_data:
                    event_data["ProcessGuid"] = s
                elif "ParentProcessGuid" not in event_data:
                    event_data["ParentProcessGuid"] = s

            # Check for Windows file paths / binaries
            if s.lower().endswith((".exe", ".dll", ".sys", ".ps1", ".vbs", ".bat", ".cmd", ".scr")):
                if "Image" not in event_data:
                    event_data["Image"] = s
                elif "ParentImage" not in event_data and "Image" in event_data:
                    event_data["ParentImage"] = s
                elif "ImageLoaded" not in event_data and result["EventID"] == 7:
                    event_data["ImageLoaded"] = s

            # Check for command line (contains spaces, flags, or matches binary)
            if any(
                s.startswith(flag)
                for flag in ("-", "/", "cmd", "powershell", "certutil", "mshta", "regsvr32", "wmic")
            ):
                if "CommandLine" not in event_data:
                    event_data["CommandLine"] = s

            # Check for IPs
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s):
                if "SourceIp" not in event_data:
                    event_data["SourceIp"] = s
                elif "DestinationIp" not in event_data:
                    event_data["DestinationIp"] = s

            # Check for Hashes (SHA256, MD5)
            if "SHA256=" in s or "MD5=" in s or "IMPHASH=" in s:
                event_data["Hashes"] = s

            # Key-Value pairs like Name=Value
            if "=" in s and not s.startswith("-"):
                parts = s.split("=", 1)
                event_data[parts[0]] = parts[1]

        result["EventData"] = event_data
        return result

    # -------------------------------------------------------------------------
    # Text / XML / JSON Parsing Subsystem
    # -------------------------------------------------------------------------

    def _parse_text_events(self, raw_bytes: bytes) -> List[Dict[str, Any]]:
        """Parse text-based event formats (JSON, XML string, or lines)."""
        records: List[Dict[str, Any]] = []

        # Try JSON parsing
        try:
            text = raw_bytes.decode("utf-8")
            data = json.loads(text)
            if isinstance(data, list):
                return [d for d in data if isinstance(d, dict)]
            if isinstance(data, dict):
                if "Events" in data and isinstance(data["Events"], list):
                    return [d for d in data["Events"] if isinstance(d, dict)]
                return [data]
        except Exception:
            pass

        # Try XML parsing
        try:
            text = raw_bytes.decode("utf-8", errors="ignore")
            if "<Events>" in text or "<Event" in text:
                return self._parse_xml_events(text)
        except Exception:
            pass

        return records

    def _parse_xml_events(self, xml_content: str) -> List[Dict[str, Any]]:
        """Parse XML string containing <Event> or <Events> elements."""
        records: List[Dict[str, Any]] = []
        try:
            # Wrap in root if multiple events without container
            if not xml_content.strip().startswith("<Events>"):
                xml_content = f"<Events>{xml_content}</Events>"

            root = ET.fromstring(xml_content)
            for event_node in root.findall(".//Event") if root.tag != "Event" else [root]:
                rec = self._parse_xml_event_node(event_node)
                if rec:
                    records.append(rec)
        except Exception:
            # Fallback regex parsing of <Event>...</Event> blocks
            event_blocks = re.findall(r"<Event.*?</Event>", xml_content, re.DOTALL)
            for block in event_blocks:
                parsed_rec = self._parse_xml_event_string(block)
                if parsed_rec:
                    records.append(parsed_rec)

        return records

    def _parse_xml_event_string(self, xml_str: str) -> Optional[Dict[str, Any]]:
        """Parse a single XML event string."""
        try:
            root = ET.fromstring(xml_str)
            return self._parse_xml_event_node(root)
        except Exception:
            return None

    def _parse_xml_event_node(self, node: ET.Element) -> Dict[str, Any]:
        """Extract structured dictionary from an XML <Event> element."""
        record: Dict[str, Any] = {
            "EventID": 0,
            "RecordId": 0,
            "Timestamp": datetime.now(timezone.utc),
            "Provider": "",
            "EventData": {},
        }

        # System Header Information
        system_node = None
        for child in node:
            if child.tag.endswith("System"):
                system_node = child
                break

        if system_node is not None:
            for item in system_node:
                tag = item.tag.split("}")[-1]  # Strip XML namespace if any
                if tag == "EventID":
                    try:
                        record["EventID"] = int(item.text.strip()) if item.text else 0
                    except ValueError:
                        pass
                elif tag == "EventRecordID":
                    try:
                        record["RecordId"] = int(item.text.strip()) if item.text else 0
                    except ValueError:
                        pass
                elif tag == "Provider":
                    record["Provider"] = item.attrib.get("Name", "")
                elif tag == "TimeCreated":
                    time_str = item.attrib.get("SystemTime", "")
                    if time_str:
                        record["Timestamp"] = self._parse_iso_timestamp(time_str)

        # EventData Payload
        event_data_node = None
        for child in node:
            if child.tag.endswith("EventData") or child.tag.endswith("UserData"):
                event_data_node = child
                break

        if event_data_node is not None:
            for data_item in event_data_node:
                name = data_item.attrib.get("Name", "")
                text = data_item.text or ""
                if name:
                    record["EventData"][name] = text.strip()
                elif data_item.tag:
                    tag_name = data_item.tag.split("}")[-1]
                    record["EventData"][tag_name] = text.strip()

        return record

    @staticmethod
    def _parse_iso_timestamp(ts_str: str) -> datetime:
        """Parse standard ISO/W3C formatted timestamp."""
        try:
            # Handle trailing Z
            cleaned = ts_str.replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)
        except Exception:
            return datetime.now(timezone.utc)

    # -------------------------------------------------------------------------
    # Sysmon & Security Event Processing
    # -------------------------------------------------------------------------

    def _parse_hashes_string(self, hashes_raw: str) -> Dict[str, str]:
        """Parse Sysmon hashes string into structured hash dictionary (md5, sha256, imphash)."""
        result: Dict[str, str] = {}
        if not hashes_raw:
            return result

        # Formats: "SHA256=...,MD5=..." or "SHA256=... MD5=..."
        parts = re.split(r"[,|\s]+", hashes_raw)
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                result[k.strip().lower()] = v.strip().lower()
            elif len(part) == 64:
                result["sha256"] = part.lower()
            elif len(part) == 32:
                result["md5"] = part.lower()
        return result

    def _normalize_event(
        self, raw: Dict[str, Any]
    ) -> Optional[
        Union[
            SysmonProcessCreateEvent,
            SysmonNetworkEvent,
            SysmonImageLoadEvent,
            SysmonFileCreateEvent,
        ]
    ]:
        """Convert a raw event dictionary into a canonical typed Sysmon/Security model."""
        event_id = raw.get("EventID", 0)
        data: Dict[str, Any] = raw.get("EventData", {})
        if not isinstance(data, dict):
            data = {}

        # Fallback fields directly on root
        for k, v in raw.items():
            if k not in ("EventID", "EventData", "Timestamp", "RecordId") and k not in data:
                data[k] = v

        timestamp = raw.get("Timestamp")
        if not isinstance(timestamp, datetime):
            if isinstance(timestamp, str):
                timestamp = self._parse_iso_timestamp(timestamp)
            elif isinstance(timestamp, (int, float)):
                timestamp = self.filetime_to_datetime(int(timestamp))
            else:
                timestamp = datetime.now(timezone.utc)

        # Ensure UTC timezone
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        record_id = int(raw.get("RecordId", 0) or data.get("RecordId", 0) or 0)

        # Sysmon Event ID 1: Process Creation OR Security Event ID 4688
        if event_id in (1, 4688):
            pid_raw = data.get("ProcessId") or data.get("NewProcessId") or 0
            try:
                pid = int(str(pid_raw), 16 if str(pid_raw).startswith("0x") else 10)
            except ValueError:
                pid = 0

            parent_pid_raw = data.get("ParentProcessId") or 0
            try:
                parent_pid = int(
                    str(parent_pid_raw), 16 if str(parent_pid_raw).startswith("0x") else 10
                )
            except ValueError:
                parent_pid = 0

            image = data.get("Image") or data.get("NewProcessName") or ""
            command_line = data.get("CommandLine") or image
            hashes = self._parse_hashes_string(data.get("Hashes", ""))

            return SysmonProcessCreateEvent(
                event_id=event_id,
                timestamp=timestamp,
                record_id=record_id,
                process_guid=data.get("ProcessGuid"),
                process_id=pid,
                image=image,
                command_line=command_line,
                current_directory=data.get("CurrentDirectory"),
                user=data.get("User") or data.get("SubjectUserName"),
                logon_guid=data.get("LogonGuid"),
                logon_id=data.get("LogonId"),
                terminal_session_id=int(data.get("TerminalSessionId", 0) or 0)
                if data.get("TerminalSessionId")
                else None,
                integrity_level=data.get("IntegrityLevel"),
                hashes=hashes,
                parent_process_guid=data.get("ParentProcessGuid"),
                parent_process_id=parent_pid,
                parent_image=data.get("ParentImage") or data.get("ParentProcessName"),
                parent_command_line=data.get("ParentCommandLine"),
                parent_user=data.get("ParentUser"),
            )

        # Sysmon Event ID 3: Network Connection
        elif event_id == 3:
            pid_raw = data.get("ProcessId", 0)
            try:
                pid = int(str(pid_raw), 16 if str(pid_raw).startswith("0x") else 10)
            except ValueError:
                pid = 0

            src_port = int(data.get("SourcePort", 0) or 0)
            dst_port = int(data.get("DestinationPort", 0) or 0)

            return SysmonNetworkEvent(
                event_id=event_id,
                timestamp=timestamp,
                record_id=record_id,
                process_guid=data.get("ProcessGuid"),
                process_id=pid,
                image=data.get("Image", ""),
                user=data.get("User"),
                protocol=data.get("Protocol", "tcp").lower(),
                initiated=data.get("Initiated", "true").lower() == "true",
                source_ip=data.get("SourceIp", "0.0.0.0"),
                source_port=src_port,
                destination_ip=data.get("DestinationIp", "0.0.0.0"),
                destination_port=dst_port,
                destination_hostname=data.get("DestinationHostname"),
                destination_port_name=data.get("DestinationPortName"),
            )

        # Sysmon Event ID 7: Image / Module Loaded
        elif event_id == 7:
            pid_raw = data.get("ProcessId", 0)
            try:
                pid = int(str(pid_raw), 16 if str(pid_raw).startswith("0x") else 10)
            except ValueError:
                pid = 0

            hashes = self._parse_hashes_string(data.get("Hashes", ""))
            signed_val = data.get("Signed")
            is_signed = signed_val.lower() == "true" if signed_val else None

            return SysmonImageLoadEvent(
                event_id=event_id,
                timestamp=timestamp,
                record_id=record_id,
                process_guid=data.get("ProcessGuid"),
                process_id=pid,
                image=data.get("Image", ""),
                image_loaded=data.get("ImageLoaded", ""),
                file_version=data.get("FileVersion"),
                description=data.get("Description"),
                product=data.get("Product"),
                company=data.get("Company"),
                hashes=hashes,
                signed=is_signed,
                signature=data.get("Signature"),
                signature_status=data.get("SignatureStatus"),
            )

        # Sysmon Event ID 11: File Create
        elif event_id == 11:
            pid_raw = data.get("ProcessId", 0)
            try:
                pid = int(str(pid_raw), 16 if str(pid_raw).startswith("0x") else 10)
            except ValueError:
                pid = 0

            creation_time = None
            if data.get("CreationUtcTime"):
                creation_time = self._parse_iso_timestamp(data["CreationUtcTime"])

            return SysmonFileCreateEvent(
                event_id=event_id,
                timestamp=timestamp,
                record_id=record_id,
                process_guid=data.get("ProcessGuid"),
                process_id=pid,
                image=data.get("Image", ""),
                target_filename=data.get("TargetFilename", ""),
                creation_time=creation_time,
            )

        return None

    # -------------------------------------------------------------------------
    # Correlation & Behavioral Analysis
    # -------------------------------------------------------------------------

    def _correlate_and_generate_report(
        self,
        raw_records: List[Dict[str, Any]],
        filename: str,
        file_path: Optional[str],
        size_bytes: int,
        hashes: Dict[str, str],
    ) -> EVTXAnalysisReport:
        """Correlate events, construct hierarchical process trees, detect anomalies, and generate report."""
        events_by_id: Dict[int, int] = {}
        total_sysmon = 0
        total_security = 0

        process_events: List[SysmonProcessCreateEvent] = []
        network_events: List[SysmonNetworkEvent] = []
        image_load_events: List[SysmonImageLoadEvent] = []
        file_create_events: List[SysmonFileCreateEvent] = []

        timeline_start: Optional[datetime] = None
        timeline_end: Optional[datetime] = None

        unique_images: Set[str] = set()
        unique_users: Set[str] = set()
        network_destinations: Set[str] = set()

        # Parse & classify records
        for raw in raw_records:
            eid = int(raw.get("EventID", 0) or 0)
            events_by_id[eid] = events_by_id.get(eid, 0) + 1

            if eid in {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 22, 23, 25, 26}:
                total_sysmon += 1
            elif eid in {4688, 4624, 4625, 4672, 4720}:
                total_security += 1

            typed_event = self._normalize_event(raw)
            if typed_event is None:
                continue

            ts = typed_event.timestamp
            if timeline_start is None or ts < timeline_start:
                timeline_start = ts
            if timeline_end is None or ts > timeline_end:
                timeline_end = ts

            if isinstance(typed_event, SysmonProcessCreateEvent):
                process_events.append(typed_event)
                if typed_event.image:
                    unique_images.add(typed_event.image)
                if typed_event.user:
                    unique_users.add(typed_event.user)

            elif isinstance(typed_event, SysmonNetworkEvent):
                network_events.append(typed_event)
                if typed_event.destination_ip:
                    dest = typed_event.destination_ip
                    if typed_event.destination_port:
                        dest += f":{typed_event.destination_port}"
                    network_destinations.add(dest)

            elif isinstance(typed_event, SysmonImageLoadEvent):
                image_load_events.append(typed_event)

            elif isinstance(typed_event, SysmonFileCreateEvent):
                file_create_events.append(typed_event)

        # Build Process Nodes
        node_by_guid: Dict[str, ProcessTreeNode] = {}
        node_by_pid: Dict[int, List[ProcessTreeNode]] = {}

        for proc in process_events:
            node = ProcessTreeNode(
                process_guid=proc.process_guid,
                process_id=proc.process_id,
                image=proc.image,
                command_line=proc.command_line,
                user=proc.user,
                start_time=proc.timestamp,
                parent_guid=proc.parent_process_guid,
                parent_pid=proc.parent_process_id,
                parent_image=proc.parent_image,
            )

            if proc.process_guid:
                node_by_guid[proc.process_guid] = node
            if proc.process_id not in node_by_pid:
                node_by_pid[proc.process_id] = []
            node_by_pid[proc.process_id].append(node)

        # Correlate Network Events to Process Nodes
        for net in network_events:
            matched_node = None
            if net.process_guid and net.process_guid in node_by_guid:
                matched_node = node_by_guid[net.process_guid]
            elif net.process_id in node_by_pid:
                # Match closest in time before or at net event
                candidates = [
                    n for n in node_by_pid[net.process_id] if n.start_time <= net.timestamp
                ]
                if candidates:
                    matched_node = max(candidates, key=lambda n: n.start_time)
                else:
                    matched_node = node_by_pid[net.process_id][0]

            if matched_node:
                matched_node.network_connections.append(net)

        # Correlate Image Load Events to Process Nodes
        for img in image_load_events:
            matched_node = None
            if img.process_guid and img.process_guid in node_by_guid:
                matched_node = node_by_guid[img.process_guid]
            elif img.process_id in node_by_pid:
                candidates = [
                    n for n in node_by_pid[img.process_id] if n.start_time <= img.timestamp
                ]
                if candidates:
                    matched_node = max(candidates, key=lambda n: n.start_time)
                else:
                    matched_node = node_by_pid[img.process_id][0]

            if matched_node:
                matched_node.loaded_images.append(img)

        # Correlate File Create Events to Process Nodes
        for fc in file_create_events:
            matched_node = None
            if fc.process_guid and fc.process_guid in node_by_guid:
                matched_node = node_by_guid[fc.process_guid]
            elif fc.process_id in node_by_pid:
                candidates = [n for n in node_by_pid[fc.process_id] if n.start_time <= fc.timestamp]
                if candidates:
                    matched_node = max(candidates, key=lambda n: n.start_time)
                else:
                    matched_node = node_by_pid[fc.process_id][0]

            if matched_node:
                matched_node.created_files.append(fc)

        # Behavioral Anomaly & LOLBAS Detection on all nodes
        all_anomalies: List[SuspiciousProcessAnomaly] = []
        all_nodes = list(node_by_guid.values())
        for nodes in node_by_pid.values():
            for n in nodes:
                if n not in all_nodes:
                    all_nodes.append(n)

        for node in all_nodes:
            detected_anomalies = self._detect_process_anomalies(node)
            if detected_anomalies:
                node.anomalies.extend(detected_anomalies)
                all_anomalies.extend(detected_anomalies)
                # Elevate threat classification on the node
                highest = max(
                    detected_anomalies,
                    key=lambda a: (
                        3 if a.severity == "CRITICAL" else (2 if a.severity == "HIGH" else 1)
                    ),
                )
                node.threat_classification = highest.classification

        # Build Hierarchical Process Tree (Parent -> Children)
        root_trees: List[ProcessTreeNode] = []
        attached_guids: Set[str] = set()

        for node in all_nodes:
            is_child = False
            # Try GUID parent match
            if (
                node.parent_guid
                and node.parent_guid in node_by_guid
                and node.parent_guid != node.process_guid
            ):
                parent_node = node_by_guid[node.parent_guid]
                parent_node.children.append(node)
                is_child = True
                if node.process_guid:
                    attached_guids.add(node.process_guid)
            # Try PID parent match
            elif (
                node.parent_pid
                and node.parent_pid in node_by_pid
                and node.parent_pid != node.process_id
            ):
                # Match parent active before child
                potential_parents = [
                    p for p in node_by_pid[node.parent_pid] if p.start_time <= node.start_time
                ]
                if potential_parents:
                    parent_node = max(potential_parents, key=lambda p: p.start_time)
                    if node not in parent_node.children:
                        parent_node.children.append(node)
                        is_child = True
                        if node.process_guid:
                            attached_guids.add(node.process_guid)

            if not is_child:
                root_trees.append(node)

        # Filter out nodes that became children from the root tree list
        final_root_trees = [
            n for n in root_trees if not (n.process_guid and n.process_guid in attached_guids)
        ]

        # Calculate Threat Score and Verdict
        threat_score, verdict = self._calculate_threat_score(all_anomalies)

        # Extract IOCs
        extracted_iocs = self._extract_iocs(
            all_anomalies, all_nodes, process_events, network_events, file_create_events
        )

        # Executive Summary & Remediation
        summary = self._generate_executive_summary(
            total_records=len(raw_records),
            total_sysmon=total_sysmon,
            total_security=total_security,
            anomalies=all_anomalies,
            verdict=verdict,
            threat_score=threat_score,
        )
        remediation = self._generate_remediation_guidance(all_anomalies)

        return EVTXAnalysisReport(
            file_path=file_path,
            filename=filename,
            size_bytes=size_bytes,
            hashes=hashes,
            total_records_parsed=len(raw_records),
            total_sysmon_events=total_sysmon,
            total_security_events=total_security,
            events_by_id=events_by_id,
            event_timeline_start=timeline_start,
            event_timeline_end=timeline_end,
            process_trees=final_root_trees,
            anomalies=all_anomalies,
            unique_images_executed=sorted(list(unique_images)),
            unique_users=sorted(list(unique_users)),
            network_destinations=sorted(list(network_destinations)),
            threat_score=threat_score,
            verdict=verdict,
            extracted_iocs=extracted_iocs,
            executive_summary=summary,
            remediation_guidance=remediation,
        )

    # -------------------------------------------------------------------------
    # Anomaly & Threat Detection Engine
    # -------------------------------------------------------------------------

    def _detect_process_anomalies(self, node: ProcessTreeNode) -> List[SuspiciousProcessAnomaly]:
        """Inspect process attributes, command lines, and parentage for malicious behaviors."""
        anomalies: List[SuspiciousProcessAnomaly] = []

        image_lower = node.image.lower()
        image_base = PureWindowsPath(image_lower).name
        cmd_lower = node.command_line.lower()

        parent_img_lower = (node.parent_image or "").lower()
        parent_base = PureWindowsPath(parent_img_lower).name if parent_img_lower else ""

        # 1. Office Macro Spawning Shells / Scripts (T1204.002)
        if parent_base in self.OFFICE_PARENTS:
            if image_base in self.SHELL_CHILDREN or any(
                sh in image_base
                for sh in ("cmd", "powershell", "wscript", "cscript", "mshta", "certutil")
            ):
                anomalies.append(
                    SuspiciousProcessAnomaly(
                        timestamp=node.start_time,
                        classification=ProcessThreatClassification.OFFICE_MACRO_SPAWN,
                        severity="CRITICAL",
                        process_image=node.image,
                        process_pid=node.process_id,
                        command_line=node.command_line,
                        parent_image=node.parent_image,
                        parent_pid=node.parent_pid,
                        mitre_attack_technique="T1204.002 - Malicious Office Macro Execution",
                        detection_reason=f"Microsoft Office application '{parent_base}' spawned interactive shell/script interpreter '{image_base}'.",
                        associated_process_guid=node.process_guid,
                    )
                )

        # 2. Web Shell Spawning (T1505.003)
        if parent_base in self.WEB_SERVER_PARENTS:
            if image_base in self.SHELL_CHILDREN or any(
                sh in image_base for sh in ("cmd", "powershell", "whoami", "net", "bash", "sh")
            ):
                anomalies.append(
                    SuspiciousProcessAnomaly(
                        timestamp=node.start_time,
                        classification=ProcessThreatClassification.WEB_SHELL_SPAWN,
                        severity="CRITICAL",
                        process_image=node.image,
                        process_pid=node.process_id,
                        command_line=node.command_line,
                        parent_image=node.parent_image,
                        parent_pid=node.parent_pid,
                        mitre_attack_technique="T1505.003 - Server Software Component: Web Shell",
                        detection_reason=f"Web server daemon '{parent_base}' spawned command execution child process '{image_base}'.",
                        associated_process_guid=node.process_guid,
                    )
                )

        # 3. Suspicious System Service Spawns
        if parent_base in self.SUSPICIOUS_SYSTEM_PARENTS:
            if image_base in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
                anomalies.append(
                    SuspiciousProcessAnomaly(
                        timestamp=node.start_time,
                        classification=ProcessThreatClassification.SUSPICIOUS_SERVICE_SPAWN,
                        severity="CRITICAL",
                        process_image=node.image,
                        process_pid=node.process_id,
                        command_line=node.command_line,
                        parent_image=node.parent_image,
                        parent_pid=node.parent_pid,
                        mitre_attack_technique="T1059.001 / T1059.003 - Process Spawn from Critical System Service",
                        detection_reason=f"Critical system service '{parent_base}' unexpectedly spawned interactive shell '{image_base}'.",
                        associated_process_guid=node.process_guid,
                    )
                )

        # 4. LOLBAS Abuse Patterns
        # Certutil download (T1105)
        if "certutil" in image_base:
            if any(
                flag in cmd_lower
                for flag in ("-urlcache", "-split", "http://", "https://", "-decode")
            ):
                anomalies.append(
                    SuspiciousProcessAnomaly(
                        timestamp=node.start_time,
                        classification=ProcessThreatClassification.LOLBAS_ABUSE,
                        severity="HIGH",
                        process_image=node.image,
                        process_pid=node.process_id,
                        command_line=node.command_line,
                        parent_image=node.parent_image,
                        parent_pid=node.parent_pid,
                        mitre_attack_technique="T1105 - Ingress Tool Transfer (Certutil)",
                        detection_reason="Certutil invoked with URL caching, file splitting, or downloading flags.",
                        associated_process_guid=node.process_guid,
                    )
                )

        # Mshta remote/inline execution (T1218.005)
        if "mshta" in image_base:
            if any(
                kw in cmd_lower
                for kw in ("javascript:", "vbscript:", "http://", "https://", "about:")
            ):
                anomalies.append(
                    SuspiciousProcessAnomaly(
                        timestamp=node.start_time,
                        classification=ProcessThreatClassification.LOLBAS_ABUSE,
                        severity="HIGH",
                        process_image=node.image,
                        process_pid=node.process_id,
                        command_line=node.command_line,
                        parent_image=node.parent_image,
                        parent_pid=node.parent_pid,
                        mitre_attack_technique="T1218.005 - Signed Binary Proxy Execution: Mshta",
                        detection_reason="Mshta invoked with inline script handler (javascript/vbscript) or remote HTTP URL.",
                        associated_process_guid=node.process_guid,
                    )
                )

        # Regsvr32 Squiblydoo (T1218.010)
        if "regsvr32" in image_base:
            if any(kw in cmd_lower for kw in ("/s", "/u", "/i:http", "scrobj.dll")):
                anomalies.append(
                    SuspiciousProcessAnomaly(
                        timestamp=node.start_time,
                        classification=ProcessThreatClassification.LOLBAS_ABUSE,
                        severity="HIGH",
                        process_image=node.image,
                        process_pid=node.process_id,
                        command_line=node.command_line,
                        parent_image=node.parent_image,
                        parent_pid=node.parent_pid,
                        mitre_attack_technique="T1218.010 - Signed Binary Proxy Execution: Regsvr32 (Squiblydoo)",
                        detection_reason="Regsvr32 executing scriptlet with /i flag or scrobj.dll.",
                        associated_process_guid=node.process_guid,
                    )
                )

        # Rundll32 inline script or suspicious URL (T1218.011)
        if "rundll32" in image_base:
            if any(
                kw in cmd_lower
                for kw in ("javascript:", "url.dll", "shellexec_run", "temp\\", "appdata\\")
            ):
                anomalies.append(
                    SuspiciousProcessAnomaly(
                        timestamp=node.start_time,
                        classification=ProcessThreatClassification.LOLBAS_ABUSE,
                        severity="HIGH",
                        process_image=node.image,
                        process_pid=node.process_id,
                        command_line=node.command_line,
                        parent_image=node.parent_image,
                        parent_pid=node.parent_pid,
                        mitre_attack_technique="T1218.011 - Signed Binary Proxy Execution: Rundll32",
                        detection_reason="Rundll32 invoked with suspicious script handler, DLL path, or shell entrypoint.",
                        associated_process_guid=node.process_guid,
                    )
                )

        # Bitsadmin download / job execution (T1197)
        if "bitsadmin" in image_base:
            if any(
                flag in cmd_lower
                for flag in ("/transfer", "/create", "/addfile", "http://", "https://")
            ):
                anomalies.append(
                    SuspiciousProcessAnomaly(
                        timestamp=node.start_time,
                        classification=ProcessThreatClassification.LOLBAS_ABUSE,
                        severity="MEDIUM",
                        process_image=node.image,
                        process_pid=node.process_id,
                        command_line=node.command_line,
                        parent_image=node.parent_image,
                        parent_pid=node.parent_pid,
                        mitre_attack_technique="T1197 - BITS Jobs",
                        detection_reason="Bitsadmin invoked to transfer files or create background transfer jobs.",
                        associated_process_guid=node.process_guid,
                    )
                )

        # Shadow Copy Deletion / Ransomware Prep (T1490)
        if (
            ("vssadmin" in image_base and "delete" in cmd_lower and "shadows" in cmd_lower)
            or ("wmic" in image_base and "shadowcopy" in cmd_lower and "delete" in cmd_lower)
            or ("wbadmin" in image_base and "delete" in cmd_lower)
            or ("bcdedit" in image_base and "recoveryenabled" in cmd_lower and "no" in cmd_lower)
        ):
            anomalies.append(
                SuspiciousProcessAnomaly(
                    timestamp=node.start_time,
                    classification=ProcessThreatClassification.LOLBAS_ABUSE,
                    severity="CRITICAL",
                    process_image=node.image,
                    process_pid=node.process_id,
                    command_line=node.command_line,
                    parent_image=node.parent_image,
                    parent_pid=node.parent_pid,
                    mitre_attack_technique="T1490 - Inhibit System Recovery: Volume Shadow Copy Deletion",
                    detection_reason="Destructive command attempting to delete volume shadow copies or disable system recovery.",
                    associated_process_guid=node.process_guid,
                )
            )

        # 5. Encoded / Obfuscated Command Execution (T1059.001)
        if "powershell" in image_base or "pwsh" in image_base:
            if any(
                flag in cmd_lower
                for flag in (
                    "-enc",
                    "-encodedcommand",
                    "-e ",
                    "-ec ",
                    "downloadstring",
                    "downloadfile",
                    "invoke-webrequest",
                    "invoke-expression",
                    "iex(",
                    "iex ",
                    "frombase64string",
                    "-w hidden",
                    "-windowstyle hidden",
                    "-ep bypass",
                    "-executionpolicy bypass",
                )
            ):
                anomalies.append(
                    SuspiciousProcessAnomaly(
                        timestamp=node.start_time,
                        classification=ProcessThreatClassification.ENCODED_COMMAND_EXECUTION,
                        severity="HIGH",
                        process_image=node.image,
                        process_pid=node.process_id,
                        command_line=node.command_line,
                        parent_image=node.parent_image,
                        parent_pid=node.parent_pid,
                        mitre_attack_technique="T1059.001 - Command and Scripting Interpreter: PowerShell",
                        detection_reason="PowerShell executed with encoded commands, hidden window style, bypass policies, or inline web download cradle.",
                        associated_process_guid=node.process_guid,
                    )
                )

        # 6. Credential Dumping Attempt (T1003)
        if any(
            dump in cmd_lower
            for dump in (
                "lsass",
                "comsvcs.dll",
                "minidump",
                "mimikatz",
                "sekurlsa",
                "ntdsutil",
                "logonpasswords",
            )
        ):
            if any(
                bin_kw in image_base
                for bin_kw in ("procdump", "rundll32", "mimikatz", "powershell", "cmd", "ntdsutil")
            ):
                anomalies.append(
                    SuspiciousProcessAnomaly(
                        timestamp=node.start_time,
                        classification=ProcessThreatClassification.CREDENTIAL_DUMPING_ATTEMPT,
                        severity="CRITICAL",
                        process_image=node.image,
                        process_pid=node.process_id,
                        command_line=node.command_line,
                        parent_image=node.parent_image,
                        parent_pid=node.parent_pid,
                        mitre_attack_technique="T1003 - OS Credential Dumping",
                        detection_reason="Process command line exhibits signatures of memory minidumping or LSASS credential extraction.",
                        associated_process_guid=node.process_guid,
                    )
                )

        return anomalies

    # -------------------------------------------------------------------------
    # Scoring & Attribution
    # -------------------------------------------------------------------------

    def _calculate_threat_score(
        self, anomalies: List[SuspiciousProcessAnomaly]
    ) -> Tuple[float, str]:
        """Compute forensic threat score and assign verdict."""
        if not anomalies:
            return 0.0, "BENIGN"

        score = 0.0
        critical_count = 0
        high_count = 0
        medium_count = 0

        for a in anomalies:
            if a.severity == "CRITICAL":
                score += 40.0
                critical_count += 1
            elif a.severity == "HIGH":
                score += 20.0
                high_count += 1
            else:
                score += 10.0
                medium_count += 1

        # Cap score between 0.0 and 100.0
        score = min(100.0, max(0.0, score))

        if score >= 60.0 or critical_count > 0:
            verdict = "MALICIOUS"
        elif score >= 20.0 or high_count > 0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"

        return round(score, 1), verdict

    def _extract_iocs(
        self,
        anomalies: List[SuspiciousProcessAnomaly],
        all_nodes: List[ProcessTreeNode],
        process_events: List[SysmonProcessCreateEvent],
        network_events: List[SysmonNetworkEvent],
        file_create_events: List[SysmonFileCreateEvent],
    ) -> List[str]:
        """Extract actionable IOCs (IPs, hashes, dropped paths, command lines) from anomalous events."""
        iocs: Set[str] = set()

        # Malicious / Anomalous images and commands
        for a in anomalies:
            if a.process_image:
                iocs.add(f"Image: {a.process_image}")
            if a.command_line and len(a.command_line) < 256:
                iocs.add(f"CommandLine: {a.command_line}")

        # Hashes of anomalous processes
        anomalous_guids = {
            a.associated_process_guid for a in anomalies if a.associated_process_guid
        }
        for proc in process_events:
            if proc.process_guid in anomalous_guids or any(
                proc.image == a.process_image for a in anomalies
            ):
                for h_type, h_val in proc.hashes.items():
                    iocs.add(f"{h_type.upper()}: {h_val}")

        # Network destinations for anomalous processes
        for net in network_events:
            if net.process_guid in anomalous_guids:
                iocs.add(f"Egress-IP: {net.destination_ip}:{net.destination_port}")
                if net.destination_hostname:
                    iocs.add(f"Egress-Host: {net.destination_hostname}")

        # Created files from anomalous processes
        for fc in file_create_events:
            if fc.process_guid in anomalous_guids:
                iocs.add(f"Dropped-File: {fc.target_filename}")

        return sorted(list(iocs))

    def _generate_executive_summary(
        self,
        total_records: int,
        total_sysmon: int,
        total_security: int,
        anomalies: List[SuspiciousProcessAnomaly],
        verdict: str,
        threat_score: float,
    ) -> str:
        """Construct executive summary describing triage findings."""
        lines = [
            f"Windows Event Log Forensic Triage completed on {total_records} record(s) "
            f"({total_sysmon} Sysmon events, {total_security} Security events).",
            f"Forensic Threat Score: {threat_score}/100.0 (Verdict: {verdict}).",
        ]

        if not anomalies:
            lines.append(
                "No behavioral anomalies or LOLBAS abuse patterns detected. Baseline activity appears benign."
            )
        else:
            lines.append(f"Identified {len(anomalies)} suspicious process execution anomal(ies):")
            for idx, a in enumerate(anomalies[:5], 1):
                lines.append(
                    f"  {idx}. [{a.severity}] {a.classification.value}: {a.detection_reason}"
                )
            if len(anomalies) > 5:
                lines.append(f"  ... and {len(anomalies) - 5} additional behavioral alert(s).")

        return "\n".join(lines)

    def _generate_remediation_guidance(
        self, anomalies: List[SuspiciousProcessAnomaly]
    ) -> List[str]:
        """Generate tactical IR remediation recommendations based on detected anomalies."""
        if not anomalies:
            return [
                "Maintain continuous Sysmon telemetry logging with process creation and network monitoring enabled."
            ]

        guidance: Set[str] = {
            "Isolate the affected host from the corporate network immediately to prevent lateral movement.",
            "Acquire full volatile memory (RAM) and disk triage image for deep post-incident analysis.",
        }

        for a in anomalies:
            if a.classification == ProcessThreatClassification.OFFICE_MACRO_SPAWN:
                guidance.add(
                    "Enforce Microsoft Office Attack Surface Reduction (ASR) rule 'Block all Office applications from creating child processes'."
                )
            elif a.classification == ProcessThreatClassification.WEB_SHELL_SPAWN:
                guidance.add(
                    "Inspect web server document roots (e.g. wwwroot, htdocs) for recently modified ASPX/PHP webshell files."
                )
            elif a.classification == ProcessThreatClassification.LOLBAS_ABUSE:
                guidance.add(
                    "Implement AppLocker / Windows Defender Application Control (WDAC) to restrict LOLBAS binaries (certutil, mshta, regsvr32)."
                )
            elif a.classification == ProcessThreatClassification.ENCODED_COMMAND_EXECUTION:
                guidance.add(
                    "Enable PowerShell Constrained Language Mode and Script Block Logging (Event ID 4104)."
                )
            elif a.classification == ProcessThreatClassification.CREDENTIAL_DUMPING_ATTEMPT:
                guidance.add(
                    "Enable Windows Defender Credential Guard and LSA Protection (RunAsPPL) to protect LSASS memory."
                )

        return sorted(list(guidance))
