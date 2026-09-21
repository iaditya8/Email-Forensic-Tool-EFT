"""Windows Security log analyzer for logon anomalies, privilege escalation, and persistence detection.

Parses Windows Security and System events (4624, 4625, 4672, 7045, 4697, 4698, 4720, 4728, 4732, 4756),
detects brute force attacks, Pass-the-Hash (PtH), suspicious services/scheduled tasks,
and synthesizes unified UTC forensic timeline events.
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from eft.analysis.evtx_analyzer import WindowsLogAnalyzer
from eft.models.logon_persistence import (
    AccountManagementEvent,
    LogonEvent,
    PrivilegeAssignedEvent,
    ScheduledTaskEvent,
    SecurityAnomalyAlert,
    SecurityLogonReport,
    SecurityThreatClassification,
    ServiceInstalledEvent,
    WindowsLogonType,
)
from eft.models.timeline import TimelineEvent


class WindowsSecurityAnalyzer:
    """Forensic Windows Security log analyzer for authentication, privilege, and persistence triage."""

    # High-privilege group names (case-insensitive substrings)
    PRIVILEGED_GROUPS = {
        "administrators",
        "domain admins",
        "enterprise admins",
        "schema admins",
        "account operators",
        "backup operators",
        "server operators",
        "remote desktop users",
        "group policy creator owners",
        "cryptographic operators",
    }

    # Suspicious execution keywords in service image paths or task commands
    SUSPICIOUS_EXEC_KEYWORDS = {
        "powershell",
        "pwsh",
        "cmd.exe",
        "-enc",
        "-encodedcommand",
        "-w hidden",
        "-ep bypass",
        "downloadstring",
        "iex",
        "cscript",
        "wscript",
        "mshta",
        "certutil",
        "regsvr32",
        "rundll32",
        "bitsadmin",
        "vssadmin",
    }

    # Suspicious path locations for services and tasks
    SUSPICIOUS_PATHS = {
        "appdata",
        "temp",
        "tmp",
        "users\\public",
        "perflogs",
        "programdata",
        "windows\\temp",
    }

    def __init__(
        self,
        brute_force_threshold: int = 5,
        spray_threshold: int = 3,
        time_window_seconds: int = 600,
    ) -> None:
        """Initialize the Windows Security Analyzer.

        Args:
            brute_force_threshold: Failed logons required on a single account to trigger brute force.
            spray_threshold: Distinct accounts targeted from one IP to trigger password spray.
            time_window_seconds: Time window for correlation of authentication failure bursts.
        """
        self.brute_force_threshold = brute_force_threshold
        self.spray_threshold = spray_threshold
        self.time_window_seconds = time_window_seconds
        self._log_parser = WindowsLogAnalyzer()

    def analyze_file(self, file_path: Union[str, Path]) -> SecurityLogonReport:
        """Analyze Windows Security log file (.evtx, JSON, XML).

        Args:
            file_path: Path to the log file on disk.

        Returns:
            SecurityLogonReport with correlated logons, anomalies, and timeline events.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        raw_bytes = path.read_bytes()
        return self.analyze_bytes(raw_bytes, filename=path.name, file_path=str(path.resolve()))

    def analyze_bytes(
        self,
        raw_bytes: bytes,
        filename: str = "security_events.evtx",
        file_path: Optional[str] = None,
    ) -> SecurityLogonReport:
        """Analyze raw binary EVTX bytes, XML, or JSON event records.

        Args:
            raw_bytes: Binary payload of EVTX or log file.
            filename: Name of the artifact.
            file_path: Optional full path.

        Returns:
            SecurityLogonReport with complete DFIR triage and correlation.
        """
        md5_hash = hashlib.md5(raw_bytes).hexdigest()
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        hashes = {"md5": md5_hash, "sha256": sha256_hash}

        # Parse records using WindowsLogAnalyzer
        if (
            raw_bytes.startswith(WindowsLogAnalyzer.EVTX_FILE_MAGIC)
            or WindowsLogAnalyzer.EVTX_CHUNK_MAGIC in raw_bytes
            or WindowsLogAnalyzer.EVTX_RECORD_MAGIC in raw_bytes
        ):
            raw_records = self._log_parser._parse_binary_evtx(raw_bytes)
            if not raw_records:
                raw_records = self._log_parser._parse_text_events(raw_bytes)
        else:
            raw_records = self._log_parser._parse_text_events(raw_bytes)
            if not raw_records:
                raw_records = self._log_parser._carve_evtx_records(raw_bytes)

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
        filename: str = "in_memory_security_events.json",
        file_path: Optional[str] = None,
    ) -> SecurityLogonReport:
        """Analyze a pre-parsed list of Windows Event dictionary records.

        Args:
            events: List of event dictionaries.
            filename: Identifier for the log source.
            file_path: Optional file path.

        Returns:
            SecurityLogonReport with complete DFIR triage.
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
    # Normalization & Structured Record Extraction
    # -------------------------------------------------------------------------

    def _normalize_logon_type(self, type_raw: Any) -> Tuple[WindowsLogonType, int]:
        """Convert raw logon type value to typed WindowsLogonType enum and int."""
        try:
            val = int(str(type_raw))
            for member in WindowsLogonType:
                if member.value == val:
                    return member, val
            return WindowsLogonType.UNKNOWN, val
        except (ValueError, TypeError):
            return WindowsLogonType.UNKNOWN, 0

    def _parse_sub_status_reason(self, sub_status: Optional[str]) -> Optional[str]:
        """Map Windows NTSTATUS sub-status error code to human-readable failure reason."""
        if not sub_status:
            return None
        code = sub_status.strip().upper()
        mapping = {
            "0XC000006A": "Bad password / username or password incorrect",
            "0XC0000064": "User does not exist",
            "0XC0000234": "User account locked out",
            "0XC0000072": "Account currently disabled",
            "0XC000006F": "User logon outside authorized hours",
            "0XC0000070": "User logon from unauthorized workstation",
            "0XC0000193": "Account has expired",
            "0XC0000071": "Password expired",
            "0XC0000224": "User must change password at next logon",
        }
        return mapping.get(code, f"Authentication error ({code})")

    def _parse_task_xml(
        self, xml_content: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Extract Command, Arguments, and UserId from Scheduled Task XML definition."""
        command = None
        args = None
        user_id = None
        if not xml_content:
            return command, args, user_id

        try:
            root = ET.fromstring(xml_content)
            # Find Exec Action
            exec_nodes = root.findall(
                ".//{http://schemas.microsoft.com/windows/2004/02/mit/task}Exec"
            )
            if not exec_nodes:
                exec_nodes = root.findall(".//Exec")

            for exec_node in exec_nodes:
                cmd_node = exec_node.find(
                    "{http://schemas.microsoft.com/windows/2004/02/mit/task}Command"
                )
                if cmd_node is None:
                    cmd_node = exec_node.find("Command")
                if cmd_node is not None and cmd_node.text:
                    command = cmd_node.text.strip()

                args_node = exec_node.find(
                    "{http://schemas.microsoft.com/windows/2004/02/mit/task}Arguments"
                )
                if args_node is None:
                    args_node = exec_node.find("Arguments")
                if args_node is not None and args_node.text:
                    args = args_node.text.strip()

            # Find Principal UserId
            princ_nodes = root.findall(
                ".//{http://schemas.microsoft.com/windows/2004/02/mit/task}Principal"
            )
            if not princ_nodes:
                princ_nodes = root.findall(".//Principal")

            for princ_node in princ_nodes:
                user_node = princ_node.find(
                    "{http://schemas.microsoft.com/windows/2004/02/mit/task}UserId"
                )
                if user_node is None:
                    user_node = princ_node.find("UserId")
                if user_node is not None and user_node.text:
                    user_id = user_node.text.strip()

        except Exception:
            # Fallback regex extraction
            cmd_match = re.search(r"<Command>(.*?)</Command>", xml_content, re.IGNORECASE)
            if cmd_match:
                command = cmd_match.group(1).strip()
            args_match = re.search(r"<Arguments>(.*?)</Arguments>", xml_content, re.IGNORECASE)
            if args_match:
                args = args_match.group(1).strip()
            user_match = re.search(r"<UserId>(.*?)</UserId>", xml_content, re.IGNORECASE)
            if user_match:
                user_id = user_match.group(1).strip()

        return command, args, user_id

    # -------------------------------------------------------------------------
    # Correlation & Reporting Subsystem
    # -------------------------------------------------------------------------

    def _correlate_and_generate_report(
        self,
        raw_records: List[Dict[str, Any]],
        filename: str,
        file_path: Optional[str],
        size_bytes: int,
        hashes: Dict[str, str],
    ) -> SecurityLogonReport:
        """Correlate security records, detect threat anomalies, and build Master Timeline."""
        events_by_id: Dict[int, int] = {}
        logons: List[LogonEvent] = []
        special_privileges: List[PrivilegeAssignedEvent] = []
        services_installed: List[ServiceInstalledEvent] = []
        scheduled_tasks: List[ScheduledTaskEvent] = []
        account_events: List[AccountManagementEvent] = []

        timeline_start: Optional[datetime] = None
        timeline_end: Optional[datetime] = None

        unique_users: Set[str] = set()
        unique_ips: Set[str] = set()
        logons_by_type: Dict[str, int] = {}

        total_success = 0
        total_failed = 0
        total_admin = 0
        total_services = 0
        total_tasks = 0
        total_accounts = 0

        # Step 1: Normalize and categorize records
        for raw in raw_records:
            eid = int(raw.get("EventID", 0) or 0)
            events_by_id[eid] = events_by_id.get(eid, 0) + 1

            data: Dict[str, Any] = raw.get("EventData", {})
            if not isinstance(data, dict):
                data = {}
            for k, v in raw.items():
                if k not in ("EventID", "EventData", "Timestamp", "RecordId") and k not in data:
                    data[k] = v

            ts = raw.get("Timestamp")
            if not isinstance(ts, datetime):
                if isinstance(ts, str):
                    ts = WindowsLogAnalyzer._parse_iso_timestamp(ts)
                elif isinstance(ts, (int, float)):
                    ts = WindowsLogAnalyzer.filetime_to_datetime(int(ts))
                else:
                    ts = datetime.now(timezone.utc)

            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)

            if timeline_start is None or ts < timeline_start:
                timeline_start = ts
            if timeline_end is None or ts > timeline_end:
                timeline_end = ts

            record_id = int(raw.get("RecordId", 0) or data.get("RecordId", 0) or 0)

            # Event 4624 (Logon Success) or 4625 (Logon Failure)
            if eid in (4624, 4625):
                is_success = eid == 4624
                if is_success:
                    total_success += 1
                else:
                    total_failed += 1

                logon_type_enum, logon_type_id = self._normalize_logon_type(
                    data.get("LogonType", 0)
                )
                type_name = (
                    logon_type_enum.name
                    if logon_type_enum != WindowsLogonType.UNKNOWN
                    else f"TYPE_{logon_type_id}"
                )
                logons_by_type[type_name] = logons_by_type.get(type_name, 0) + 1

                target_user = data.get("TargetUserName") or data.get("TargetUser") or "UNKNOWN"
                if target_user and target_user not in ("-", "UNKNOWN"):
                    unique_users.add(target_user)

                ip = data.get("IpAddress") or data.get("WorkstationIp")
                if ip and ip not in ("-", "127.0.0.1", "::1"):
                    unique_ips.add(ip)

                sub_status = data.get("SubStatus")
                failure_reason = self._parse_sub_status_reason(sub_status)

                ip_port_raw = data.get("IpPort")
                ip_port = int(ip_port_raw) if ip_port_raw and str(ip_port_raw).isdigit() else None

                logon_evt = LogonEvent(
                    event_id=eid,
                    record_id=record_id,
                    timestamp=ts,
                    is_success=is_success,
                    logon_type=logon_type_enum,
                    logon_type_id=logon_type_id,
                    target_user_name=target_user,
                    target_domain_name=data.get("TargetDomainName"),
                    target_user_sid=data.get("TargetUserSid"),
                    target_logon_id=data.get("TargetLogonId"),
                    subject_user_name=data.get("SubjectUserName"),
                    subject_domain_name=data.get("SubjectDomainName"),
                    subject_user_sid=data.get("SubjectUserSid"),
                    ip_address=ip if ip != "-" else None,
                    ip_port=ip_port,
                    workstation_name=data.get("WorkstationName")
                    if data.get("WorkstationName") != "-"
                    else None,
                    authentication_package_name=data.get("AuthenticationPackageName"),
                    logon_process_name=data.get("LogonProcessName"),
                    elevated_token=data.get("ElevatedToken", "").lower() == "true"
                    if "ElevatedToken" in data
                    else None,
                    status=data.get("Status"),
                    sub_status=sub_status,
                    failure_reason=failure_reason,
                )
                logons.append(logon_evt)

            # Event 4672 (Special Privileges Assigned)
            elif eid == 4672:
                total_admin += 1
                subj_user = data.get("SubjectUserName") or data.get("TargetUserName") or "UNKNOWN"
                if subj_user and subj_user not in ("-", "UNKNOWN"):
                    unique_users.add(subj_user)

                priv_raw = data.get("PrivilegeList", "")
                priv_list = [p.strip() for p in re.split(r"[\r\n\t,]+", priv_raw) if p.strip()]

                priv_evt = PrivilegeAssignedEvent(
                    event_id=eid,
                    record_id=record_id,
                    timestamp=ts,
                    subject_user_name=subj_user,
                    subject_domain_name=data.get("SubjectDomainName"),
                    subject_user_sid=data.get("SubjectUserSid"),
                    subject_logon_id=data.get("SubjectLogonId"),
                    privilege_list=priv_list,
                )
                special_privileges.append(priv_evt)

            # Event 7045 (System) or 4697 (Security) (Service Installed)
            elif eid in (7045, 4697):
                total_services += 1
                service_name = data.get("ServiceName") or "UnknownService"
                image_path = data.get("ImagePath") or data.get("ServiceFileName") or ""

                svc_evt = ServiceInstalledEvent(
                    event_id=eid,
                    record_id=record_id,
                    timestamp=ts,
                    service_name=service_name,
                    image_path=image_path,
                    service_type=data.get("ServiceType"),
                    start_type=data.get("StartType"),
                    account_name=data.get("AccountName") or data.get("ServiceAccount"),
                    subject_user_name=data.get("SubjectUserName"),
                )
                services_installed.append(svc_evt)

            # Event 4698 or 4702 (Scheduled Task Created/Updated)
            elif eid in (4698, 4702):
                total_tasks += 1
                task_name = data.get("TaskName") or "UnknownTask"
                task_xml = data.get("TaskContent") or data.get("TaskXml") or ""
                cmd, args, uid = self._parse_task_xml(task_xml)

                task_evt = ScheduledTaskEvent(
                    event_id=eid,
                    record_id=record_id,
                    timestamp=ts,
                    task_name=task_name,
                    action_command=cmd or data.get("ActionCommand"),
                    action_arguments=args or data.get("ActionArguments"),
                    user_context=uid or data.get("UserContext"),
                    subject_user_name=data.get("SubjectUserName"),
                    task_xml_raw=task_xml if len(task_xml) < 4096 else task_xml[:4096],
                )
                scheduled_tasks.append(task_evt)

            # Event 4720 (User Created) or 4728/4732/4756 (Group Member Added)
            elif eid in (4720, 4728, 4732, 4756):
                total_accounts += 1
                action_map = {
                    4720: "USER_CREATED",
                    4728: "MEMBER_ADDED_TO_GLOBAL_GROUP",
                    4732: "MEMBER_ADDED_TO_LOCAL_GROUP",
                    4756: "MEMBER_ADDED_TO_UNIVERSAL_GROUP",
                }
                action = action_map.get(eid, "ACCOUNT_MANAGEMENT")

                target_user = (
                    data.get("TargetUserName")
                    or data.get("MemberName")
                    or data.get("SamAccountName")
                    or "UNKNOWN"
                )
                if target_user and target_user not in ("-", "UNKNOWN"):
                    unique_users.add(target_user)

                group_name = data.get("TargetUserName") if eid in (4728, 4732, 4756) else None
                if eid in (4728, 4732, 4756):
                    # For group membership events, MemberName is the user, TargetUserName is the group
                    target_user = data.get("MemberName") or data.get("MemberSid") or "UNKNOWN"

                acct_evt = AccountManagementEvent(
                    event_id=eid,
                    record_id=record_id,
                    timestamp=ts,
                    action=action,
                    target_user_name=target_user,
                    target_domain_name=data.get("TargetDomainName"),
                    target_sid=data.get("TargetSid") or data.get("MemberSid"),
                    group_name=group_name or data.get("GroupName"),
                    group_domain_name=data.get("GroupDomainName"),
                    group_sid=data.get("GroupSid"),
                    subject_user_name=data.get("SubjectUserName"),
                    subject_domain_name=data.get("SubjectDomainName"),
                )
                account_events.append(acct_evt)

        # Step 2: Behavioral Threat Anomaly Detection
        anomalies = self._detect_security_anomalies(
            logons=logons,
            special_privileges=special_privileges,
            services=services_installed,
            tasks=scheduled_tasks,
            account_events=account_events,
        )

        # Step 3: Threat Scoring & Verdict
        threat_score, verdict = self._calculate_security_threat_score(anomalies)

        # Step 4: Extract IOCs
        extracted_iocs = self._extract_security_iocs(
            anomalies, services_installed, scheduled_tasks, account_events
        )

        # Step 5: Master Timeline Synthesis
        timeline_events = self._synthesize_master_timeline(
            logons=logons,
            special_privileges=special_privileges,
            services=services_installed,
            tasks=scheduled_tasks,
            account_events=account_events,
            anomalies=anomalies,
        )

        # Step 6: Executive Summary & Remediation
        summary = self._generate_security_summary(
            total_records=len(raw_records),
            total_success=total_success,
            total_failed=total_failed,
            total_admin=total_admin,
            total_services=total_services,
            total_tasks=total_tasks,
            total_accounts=total_accounts,
            anomalies=anomalies,
            verdict=verdict,
            threat_score=threat_score,
        )
        remediation = self._generate_security_remediation(anomalies)

        return SecurityLogonReport(
            file_path=file_path,
            filename=filename,
            size_bytes=size_bytes,
            hashes=hashes,
            total_events_parsed=len(raw_records),
            total_successful_logons=total_success,
            total_failed_logons=total_failed,
            total_admin_logons=total_admin,
            total_services_installed=total_services,
            total_scheduled_tasks=total_tasks,
            total_account_changes=total_accounts,
            events_by_id=events_by_id,
            timeline_start=timeline_start,
            timeline_end=timeline_end,
            logons=logons,
            special_privileges=special_privileges,
            services_installed=services_installed,
            scheduled_tasks=scheduled_tasks,
            account_management_events=account_events,
            anomalies=anomalies,
            unique_users=sorted(list(unique_users)),
            unique_source_ips=sorted(list(unique_ips)),
            logons_by_type=logons_by_type,
            timeline_events=timeline_events,
            threat_score=threat_score,
            verdict=verdict,
            extracted_iocs=extracted_iocs,
            executive_summary=summary,
            remediation_guidance=remediation,
        )

    # -------------------------------------------------------------------------
    # Anomaly Detection Algorithms
    # -------------------------------------------------------------------------

    def _detect_security_anomalies(
        self,
        logons: List[LogonEvent],
        special_privileges: List[PrivilegeAssignedEvent],
        services: List[ServiceInstalledEvent],
        tasks: List[ScheduledTaskEvent],
        account_events: List[AccountManagementEvent],
    ) -> List[SecurityAnomalyAlert]:
        """Run correlation heuristics across logon sequences, persistence, and account events."""
        anomalies: List[SecurityAnomalyAlert] = []

        # Sort logons chronologically
        sorted_logons = sorted(logons, key=lambda evt: evt.timestamp)

        # 1. Brute Force & Account Compromise Detection (T1110.001)
        failures_by_user: Dict[str, List[LogonEvent]] = {}
        for logon_evt in sorted_logons:
            if not logon_evt.is_success and logon_evt.target_user_name not in ("-", "UNKNOWN"):
                u = logon_evt.target_user_name.lower()
                failures_by_user.setdefault(u, []).append(logon_evt)

        for user, fail_list in failures_by_user.items():
            if len(fail_list) >= self.brute_force_threshold:
                # Check if bursts occurred within time window
                first_ts = fail_list[0].timestamp
                last_ts = fail_list[-1].timestamp
                span = (last_ts - first_ts).total_seconds()

                # Check if subsequent successful logon occurred after the failures
                success_after = [
                    s
                    for s in sorted_logons
                    if s.is_success
                    and s.target_user_name.lower() == user
                    and s.timestamp >= first_ts
                ]

                severity = "CRITICAL" if success_after else "HIGH"
                reason = f"Detected {len(fail_list)} failed logon attempts on account '{user}' within {int(span)}s."
                if success_after:
                    reason += f" Account compromised: successful logon observed at {success_after[0].timestamp.isoformat()}."

                src_ip = fail_list[0].ip_address

                anomalies.append(
                    SecurityAnomalyAlert(
                        timestamp=last_ts,
                        classification=SecurityThreatClassification.BRUTE_FORCE_ATTACK,
                        severity=severity,
                        target_user=user,
                        source_ip=src_ip,
                        mitre_attack_technique="T1110.001 - Password Guessing / Brute Force",
                        detection_reason=reason,
                        evidence_count=len(fail_list),
                        associated_records=[f.record_id for f in fail_list if f.record_id],
                    )
                )

        # 2. Password Spraying Detection (T1110.003)
        failures_by_ip: Dict[str, List[LogonEvent]] = {}
        for logon_evt in sorted_logons:
            if (
                not logon_evt.is_success
                and logon_evt.ip_address
                and logon_evt.ip_address not in ("-", "127.0.0.1", "::1")
            ):
                failures_by_ip.setdefault(logon_evt.ip_address, []).append(logon_evt)

        for ip, fail_list in failures_by_ip.items():
            targeted_users = {
                f.target_user_name.lower()
                for f in fail_list
                if f.target_user_name not in ("-", "UNKNOWN")
            }
            if len(targeted_users) >= self.spray_threshold:
                anomalies.append(
                    SecurityAnomalyAlert(
                        timestamp=fail_list[-1].timestamp,
                        classification=SecurityThreatClassification.PASSWORD_SPRAY,
                        severity="HIGH",
                        source_ip=ip,
                        mitre_attack_technique="T1110.003 - Password Spraying",
                        detection_reason=f"Source IP '{ip}' targeted {len(targeted_users)} distinct user accounts with failed logons ({', '.join(sorted(targeted_users)[:5])}).",
                        evidence_count=len(fail_list),
                        associated_records=[f.record_id for f in fail_list if f.record_id],
                    )
                )

        # 3. Pass-the-Hash / Overpass-the-Hash (Type 9 Logon) (T1550.002)
        for logon_evt in sorted_logons:
            if logon_evt.is_success and logon_evt.logon_type == WindowsLogonType.NEW_CREDENTIALS:
                proc = (logon_evt.logon_process_name or "").lower()
                pkg = (logon_evt.authentication_package_name or "").lower()
                if "seclogo" in proc or "ntlm" in pkg or not logon_evt.ip_address:
                    anomalies.append(
                        SecurityAnomalyAlert(
                            timestamp=logon_evt.timestamp,
                            classification=SecurityThreatClassification.PASS_THE_HASH,
                            severity="HIGH",
                            target_user=logon_evt.target_user_name,
                            source_ip=logon_evt.ip_address,
                            mitre_attack_technique="T1550.002 - Use Alternate Authentication Material: Pass the Hash",
                            detection_reason=f"Logon Type 9 (NewCredentials) executed by '{logon_evt.target_user_name}' via process '{logon_evt.logon_process_name}' indicating Pass-the-Hash / Overpass-the-Hash credential delegation.",
                            evidence_count=1,
                            associated_records=[logon_evt.record_id] if logon_evt.record_id else [],
                        )
                    )

        # 4. Cleartext Network Logon (Type 8 Logon) (T1040)
        for logon_evt in sorted_logons:
            if logon_evt.is_success and logon_evt.logon_type == WindowsLogonType.NETWORK_CLEARTEXT:
                anomalies.append(
                    SecurityAnomalyAlert(
                        timestamp=logon_evt.timestamp,
                        classification=SecurityThreatClassification.CLEARTEXT_LOGON,
                        severity="HIGH",
                        target_user=logon_evt.target_user_name,
                        source_ip=logon_evt.ip_address,
                        mitre_attack_technique="T1040 - Network Sniffing / Cleartext Authentication",
                        detection_reason=f"Logon Type 8 (NetworkCleartext) observed for '{logon_evt.target_user_name}' from IP '{logon_evt.ip_address}'. Credentials transmitted without transport encryption.",
                        evidence_count=1,
                        associated_records=[logon_evt.record_id] if logon_evt.record_id else [],
                    )
                )

        # 5. Suspicious Service Persistence (T1543.003)
        for svc in services:
            path_lower = svc.image_path.lower()
            is_suspicious = False
            reasons = []

            # Check execution keywords
            if any(kw in path_lower for kw in self.SUSPICIOUS_EXEC_KEYWORDS):
                is_suspicious = True
                reasons.append(
                    "executable command line contains scripting/interpreter or download flags"
                )

            # Check suspicious directory locations
            if any(p in path_lower for p in self.SUSPICIOUS_PATHS):
                is_suspicious = True
                reasons.append(
                    "service binary located in user-writable directory (AppData/Temp/Public/PerfLogs)"
                )

            # Check script extension
            if path_lower.endswith((".bat", ".vbs", ".ps1", ".cmd", ".scr")):
                is_suspicious = True
                reasons.append("service invokes non-standard script file directly")

            if is_suspicious:
                anomalies.append(
                    SecurityAnomalyAlert(
                        timestamp=svc.timestamp,
                        classification=SecurityThreatClassification.SUSPICIOUS_SERVICE_INSTALLATION,
                        severity="CRITICAL",
                        target_user=svc.account_name,
                        mitre_attack_technique="T1543.003 - Create or Modify System Process: Windows Service",
                        detection_reason=f"Suspicious service '{svc.service_name}' installed with command '{svc.image_path}': {'; '.join(reasons)}.",
                        evidence_count=1,
                        associated_records=[svc.record_id] if svc.record_id else [],
                    )
                )

        # 6. Suspicious Scheduled Task Persistence (T1053.005)
        for task in tasks:
            cmd = (task.action_command or "").lower()
            args = (task.action_arguments or "").lower()
            full_exec = f"{cmd} {args}".strip()

            is_suspicious = False
            reasons = []

            if any(kw in full_exec for kw in self.SUSPICIOUS_EXEC_KEYWORDS):
                is_suspicious = True
                reasons.append("action invokes script interpreter or obfuscation flags")

            if any(p in full_exec for p in self.SUSPICIOUS_PATHS):
                is_suspicious = True
                reasons.append("action binary resides in temporary or user-writable path")

            if is_suspicious:
                anomalies.append(
                    SecurityAnomalyAlert(
                        timestamp=task.timestamp,
                        classification=SecurityThreatClassification.SUSPICIOUS_SCHEDULED_TASK,
                        severity="CRITICAL",
                        target_user=task.user_context or task.subject_user_name,
                        mitre_attack_technique="T1053.005 - Scheduled Task/Job: Scheduled Task",
                        detection_reason=f"Scheduled Task '{task.task_name}' created with suspicious action '{full_exec}': {'; '.join(reasons)}.",
                        evidence_count=1,
                        associated_records=[task.record_id] if task.record_id else [],
                    )
                )

        # 7. Rogue Account Creation & Privilege Escalation (T1136.001 / T1098)
        created_accounts: Dict[str, AccountManagementEvent] = {}
        for acct in account_events:
            if acct.action == "USER_CREATED":
                created_accounts[acct.target_user_name.lower()] = acct
                anomalies.append(
                    SecurityAnomalyAlert(
                        timestamp=acct.timestamp,
                        classification=SecurityThreatClassification.UNAUTHORIZED_ACCOUNT_CREATION,
                        severity="MEDIUM",
                        target_user=acct.target_user_name,
                        mitre_attack_technique="T1136.001 - Create Account: Local Account",
                        detection_reason=f"New user account '{acct.target_user_name}' created by '{acct.subject_user_name}'.",
                        evidence_count=1,
                        associated_records=[acct.record_id] if acct.record_id else [],
                    )
                )

        for acct in account_events:
            if acct.group_name and any(
                pg in acct.group_name.lower() for pg in self.PRIVILEGED_GROUPS
            ):
                u = acct.target_user_name.lower()
                was_recently_created = u in created_accounts

                severity = "CRITICAL" if was_recently_created else "HIGH"
                reason = f"User '{acct.target_user_name}' added to privileged group '{acct.group_name}' by '{acct.subject_user_name}'."
                if was_recently_created:
                    reason += " Critical privilege escalation: Account was newly created in the same timeframe."

                anomalies.append(
                    SecurityAnomalyAlert(
                        timestamp=acct.timestamp,
                        classification=SecurityThreatClassification.PRIVILEGE_GROUP_ESCALATION,
                        severity=severity,
                        target_user=acct.target_user_name,
                        mitre_attack_technique="T1098 - Account Manipulation: Security Group Membership",
                        detection_reason=reason,
                        evidence_count=1,
                        associated_records=[acct.record_id] if acct.record_id else [],
                    )
                )

        return anomalies

    # -------------------------------------------------------------------------
    # Master Timeline Synthesis
    # -------------------------------------------------------------------------

    def _synthesize_master_timeline(
        self,
        logons: List[LogonEvent],
        special_privileges: List[PrivilegeAssignedEvent],
        services: List[ServiceInstalledEvent],
        tasks: List[ScheduledTaskEvent],
        account_events: List[AccountManagementEvent],
        anomalies: List[SecurityAnomalyAlert],
    ) -> List[TimelineEvent]:
        """Convert all security events and detected anomalies into canonical UTC TimelineEvents."""
        timeline: List[TimelineEvent] = []

        # Convert Logons
        for logon_evt in logons:
            status_str = "Successful Logon" if logon_evt.is_success else "Failed Logon"
            desc = f"{status_str} ({logon_evt.logon_type.name}): {logon_evt.target_user_name}"
            if logon_evt.ip_address:
                desc += f" from {logon_evt.ip_address}"
            if not logon_evt.is_success and logon_evt.failure_reason:
                desc += f" - {logon_evt.failure_reason}"

            # Tag anomalies for this logon record
            matched_anomalies = [
                a.classification.value
                for a in anomalies
                if logon_evt.record_id in a.associated_records
                or (
                    a.target_user
                    and a.target_user.lower() == logon_evt.target_user_name.lower()
                    and abs((a.timestamp - logon_evt.timestamp).total_seconds()) < 60
                )
            ]

            timeline.append(
                TimelineEvent(
                    timestamp_utc=logon_evt.timestamp,
                    event_type="LOGON_SUCCESS" if logon_evt.is_success else "LOGON_FAILURE",
                    source="Windows Security Log (Event 4624/4625)",
                    description=desc,
                    actor_or_host=f"{logon_evt.target_user_name}@{logon_evt.ip_address or logon_evt.workstation_name or 'localhost'}",
                    anomalies=matched_anomalies,
                    details={
                        "event_id": logon_evt.event_id,
                        "record_id": logon_evt.record_id,
                        "logon_type": logon_evt.logon_type.name,
                        "logon_type_id": logon_evt.logon_type_id,
                        "user": logon_evt.target_user_name,
                        "ip": logon_evt.ip_address,
                        "port": logon_evt.ip_port,
                        "sub_status": logon_evt.sub_status,
                    },
                )
            )

        # Convert Special Privileges (4672)
        for priv in special_privileges:
            timeline.append(
                TimelineEvent(
                    timestamp_utc=priv.timestamp,
                    event_type="SPECIAL_PRIVILEGE_ASSIGNED",
                    source="Windows Security Log (Event 4672)",
                    description=f"Special administrative privileges assigned to '{priv.subject_user_name}' ({len(priv.privilege_list)} privileges).",
                    actor_or_host=priv.subject_user_name,
                    details={
                        "event_id": priv.event_id,
                        "record_id": priv.record_id,
                        "user": priv.subject_user_name,
                        "privileges": priv.privilege_list,
                    },
                )
            )

        # Convert Services Installed (7045/4697)
        for svc in services:
            matched_anomalies = [
                a.classification.value
                for a in anomalies
                if svc.record_id in a.associated_records
                or (
                    a.classification == SecurityThreatClassification.SUSPICIOUS_SERVICE_INSTALLATION
                    and svc.service_name in a.detection_reason
                )
            ]

            timeline.append(
                TimelineEvent(
                    timestamp_utc=svc.timestamp,
                    event_type="SERVICE_INSTALLED",
                    source="Windows System/Security Log (Event 7045/4697)",
                    description=f"Service Installed: '{svc.service_name}' -> Image: '{svc.image_path}' (Account: {svc.account_name or 'LocalSystem'}).",
                    actor_or_host=svc.service_name,
                    anomalies=matched_anomalies,
                    details={
                        "event_id": svc.event_id,
                        "record_id": svc.record_id,
                        "service_name": svc.service_name,
                        "image_path": svc.image_path,
                        "account": svc.account_name,
                    },
                )
            )

        # Convert Scheduled Tasks (4698)
        for task in tasks:
            matched_anomalies = [
                a.classification.value
                for a in anomalies
                if task.record_id in a.associated_records
                or (
                    a.classification == SecurityThreatClassification.SUSPICIOUS_SCHEDULED_TASK
                    and task.task_name in a.detection_reason
                )
            ]

            cmd_str = f"{task.action_command or ''} {task.action_arguments or ''}".strip()
            timeline.append(
                TimelineEvent(
                    timestamp_utc=task.timestamp,
                    event_type="SCHEDULED_TASK_CREATED",
                    source="Windows Security Log (Event 4698)",
                    description=f"Scheduled Task Created: '{task.task_name}' -> Exec: '{cmd_str}' (User Context: {task.user_context or 'System'}).",
                    actor_or_host=task.task_name,
                    anomalies=matched_anomalies,
                    details={
                        "event_id": task.event_id,
                        "record_id": task.record_id,
                        "task_name": task.task_name,
                        "command": task.action_command,
                        "arguments": task.action_arguments,
                        "user": task.user_context,
                    },
                )
            )

        # Convert Account Management Events (4720, 4728, 4732, 4756)
        for acct in account_events:
            matched_anomalies = [
                a.classification.value
                for a in anomalies
                if acct.record_id in a.associated_records
                or (a.target_user and a.target_user.lower() == acct.target_user_name.lower())
            ]

            desc = f"Account Action ({acct.action}): User '{acct.target_user_name}'"
            if acct.group_name:
                desc += f" -> Group '{acct.group_name}'"
            if acct.subject_user_name:
                desc += f" (Operator: {acct.subject_user_name})"

            timeline.append(
                TimelineEvent(
                    timestamp_utc=acct.timestamp,
                    event_type=f"ACCOUNT_{acct.action}",
                    source=f"Windows Security Log (Event {acct.event_id})",
                    description=desc,
                    actor_or_host=acct.target_user_name,
                    anomalies=matched_anomalies,
                    details={
                        "event_id": acct.event_id,
                        "record_id": acct.record_id,
                        "action": acct.action,
                        "target_user": acct.target_user_name,
                        "group_name": acct.group_name,
                        "operator": acct.subject_user_name,
                    },
                )
            )

        # Sort chronologically
        timeline.sort(key=lambda t: t.timestamp_utc)

        # Compute delta timings
        for i in range(len(timeline)):
            if i > 0:
                prev = timeline[i - 1]
                delta = (timeline[i].timestamp_utc - prev.timestamp_utc).total_seconds()
                timeline[i].time_delta_seconds = delta
                if delta < 60:
                    timeline[i].time_delta_formatted = f"+{delta:.1f}s"
                elif delta < 3600:
                    timeline[i].time_delta_formatted = f"+{delta / 60:.1f}m"
                else:
                    timeline[i].time_delta_formatted = f"+{delta / 3600:.1f}h"

        return timeline

    # -------------------------------------------------------------------------
    # Threat Scoring & Attribution
    # -------------------------------------------------------------------------

    def _calculate_security_threat_score(
        self, anomalies: List[SecurityAnomalyAlert]
    ) -> Tuple[float, str]:
        """Compute threat score and assign forensic verdict."""
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

        score = min(100.0, max(0.0, score))

        if score >= 60.0 or critical_count > 0:
            verdict = "MALICIOUS"
        elif score >= 20.0 or high_count > 0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"

        return round(score, 1), verdict

    def _extract_security_iocs(
        self,
        anomalies: List[SecurityAnomalyAlert],
        services: List[ServiceInstalledEvent],
        tasks: List[ScheduledTaskEvent],
        account_events: List[AccountManagementEvent],
    ) -> List[str]:
        """Extract actionable IoCs (rogue accounts, attacker IPs, malicious binaries, task commands)."""
        iocs: Set[str] = set()

        for a in anomalies:
            if a.source_ip:
                iocs.add(f"Attacker-IP: {a.source_ip}")
            if a.target_user and a.classification in (
                SecurityThreatClassification.UNAUTHORIZED_ACCOUNT_CREATION,
                SecurityThreatClassification.PRIVILEGE_GROUP_ESCALATION,
            ):
                iocs.add(f"Rogue-Account: {a.target_user}")

        for svc in services:
            if any(svc.record_id in a.associated_records for a in anomalies) or any(
                kw in svc.image_path.lower() for kw in self.SUSPICIOUS_EXEC_KEYWORDS
            ):
                iocs.add(f"Persistence-Service: {svc.service_name} ({svc.image_path})")

        for task in tasks:
            if any(task.record_id in a.associated_records for a in anomalies):
                cmd_str = f"{task.action_command or ''} {task.action_arguments or ''}".strip()
                iocs.add(f"Persistence-Task: {task.task_name} ({cmd_str})")

        return sorted(list(iocs))

    def _generate_security_summary(
        self,
        total_records: int,
        total_success: int,
        total_failed: int,
        total_admin: int,
        total_services: int,
        total_tasks: int,
        total_accounts: int,
        anomalies: List[SecurityAnomalyAlert],
        verdict: str,
        threat_score: float,
    ) -> str:
        """Construct executive summary describing security log triage findings."""
        lines = [
            f"Windows Security & Persistence Log Triage completed on {total_records} record(s).",
            f"Authentication Telemetry: {total_success} successful logons, {total_failed} failed attempts, {total_admin} admin privilege elevations.",
            f"Persistence & Account Activity: {total_services} services installed, {total_tasks} scheduled tasks created, {total_accounts} account modifications.",
            f"Security Threat Score: {threat_score}/100.0 (Verdict: {verdict}).",
        ]

        if not anomalies:
            lines.append(
                "No brute force attacks, credential abuse, or suspicious persistence mechanisms detected."
            )
        else:
            lines.append(f"Identified {len(anomalies)} security threat alert(s):")
            for idx, a in enumerate(anomalies[:6], 1):
                lines.append(
                    f"  {idx}. [{a.severity}] {a.classification.value}: {a.detection_reason}"
                )
            if len(anomalies) > 6:
                lines.append(f"  ... and {len(anomalies) - 6} additional security finding(s).")

        return "\n".join(lines)

    def _generate_security_remediation(self, anomalies: List[SecurityAnomalyAlert]) -> List[str]:
        """Generate tactical IR remediation recommendations based on detected security anomalies."""
        if not anomalies:
            return [
                "Maintain active Windows Security Log audit policies (Logon/Logoff, Account Management, Privilege Use)."
            ]

        guidance: Set[str] = {
            "Immediately reset passwords and revoke active Kerberos TGT tokens for compromised user accounts.",
            "Review Domain Admins and local Administrators group memberships to remove unauthorized rogue accounts.",
        }

        for a in anomalies:
            if a.classification == SecurityThreatClassification.BRUTE_FORCE_ATTACK:
                guidance.add(
                    "Enforce Account Lockout Threshold (e.g. 5 attempts) and implement Multi-Factor Authentication (MFA)."
                )
            elif a.classification == SecurityThreatClassification.PASS_THE_HASH:
                guidance.add(
                    "Enable Windows Defender Remote Credential Guard and restrict NTLM authentication across internal subnets."
                )
            elif a.classification == SecurityThreatClassification.SUSPICIOUS_SERVICE_INSTALLATION:
                guidance.add(
                    "Inspect Windows Services (services.msc / sc.exe) and delete unauthorized persistence service binaries."
                )
            elif a.classification == SecurityThreatClassification.SUSPICIOUS_SCHEDULED_TASK:
                guidance.add(
                    "Audit Task Scheduler (schtasks.exe /query) and remove suspicious persistence task XML definitions."
                )
            elif a.classification == SecurityThreatClassification.CLEARTEXT_LOGON:
                guidance.add(
                    "Disable Basic Authentication on web servers and enforce TLS for all network authentication."
                )

        return sorted(list(guidance))
