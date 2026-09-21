"""Cloud audit log ingestion and threat correlation engine.

Parses Microsoft 365 Unified Audit Logs (UAL) and Google Workspace Admin/Login audit trails
(in JSON, NDJSON, and CSV formats), detects illicit inbox forwarding, email hiding rules,
unauthorized mailbox delegation, illicit OAuth consent, and impossible travel logins.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from eft.analysis.evtx_analyzer import WindowsLogAnalyzer
from eft.models.cloud_audit import (
    CloudAnomalyAlert,
    CloudAuditReport,
    CloudLoginRecord,
    CloudOAuthConsentRecord,
    CloudProvider,
    CloudThreatClassification,
    GoogleAdminAuditEvent,
    M365InboxRuleRecord,
    M365MailboxPermissionRecord,
)
from eft.models.timeline import TimelineEvent


class CloudAuditAnalyzer:
    """Forensic cloud audit log analyzer for M365 and Google Workspace."""

    # Sensitive / Hiding folders commonly abused by BEC threat actors
    SUSPICIOUS_FOLDERS = {
        "rss feeds",
        "rss subscriptions",
        "junk email",
        "junk",
        "deleted items",
        "trash",
        "conversation history",
        "archive",
        "sync issues",
        "conflicts",
        "local failures",
    }

    # High-privilege OAuth scopes targeting mailbox & directory data
    HIGH_RISK_OAUTH_SCOPES = {
        "mail.readwrite",
        "mail.read",
        "mail.send",
        "mailboxsettings.readwrite",
        "files.readwrite.all",
        "directory.readwrite.all",
        "user.readwrite.all",
        "full_access_as_app",
        "https://mail.google.com/",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.readonly",
    }

    # Suspicious subject filter keywords for BEC hiding rules
    SUSPICIOUS_RULE_KEYWORDS = {
        "invoice",
        "wire",
        "payment",
        "swift",
        "bank",
        "transfer",
        "statement",
        "remittance",
        "security",
        "password",
        "alert",
        "fraud",
        "phish",
        "verification",
        "code",
        "otp",
        "2fa",
    }

    def __init__(self, impossible_travel_threshold_seconds: int = 3600) -> None:
        """Initialize Cloud Audit Analyzer.

        Args:
            impossible_travel_threshold_seconds: Time threshold between disparate geo logins for impossible travel.
        """
        self.impossible_travel_threshold_seconds = impossible_travel_threshold_seconds

    def analyze_file(self, file_path: Union[str, Path]) -> CloudAuditReport:
        """Analyze cloud audit log from file path on disk.

        Args:
            file_path: Path to JSON or CSV log export.

        Returns:
            CloudAuditReport with triage findings and timeline.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        raw_bytes = path.read_bytes()
        return self.analyze_bytes(raw_bytes, filename=path.name, file_path=str(path.resolve()))

    def analyze_bytes(
        self,
        raw_bytes: bytes,
        filename: str = "cloud_audit.json",
        file_path: Optional[str] = None,
    ) -> CloudAuditReport:
        """Analyze raw bytes of M365 or Google Workspace audit logs.

        Args:
            raw_bytes: Binary payload of JSON or CSV export.
            filename: Artifact name.
            file_path: Optional file path.

        Returns:
            CloudAuditReport with parsed records and threat findings.
        """
        md5_hash = hashlib.md5(raw_bytes).hexdigest()
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        hashes = {"md5": md5_hash, "sha256": sha256_hash}

        text = raw_bytes.decode("utf-8", errors="ignore")
        records, provider = self._parse_cloud_log_text(text)

        return self._correlate_and_generate_report(
            raw_records=records,
            detected_provider=provider,
            filename=filename,
            file_path=file_path,
            size_bytes=len(raw_bytes),
            hashes=hashes,
        )

    def analyze_records(
        self,
        records: List[Dict[str, Any]],
        detected_provider: CloudProvider = CloudProvider.M365,
        filename: str = "in_memory_cloud_events.json",
        file_path: Optional[str] = None,
    ) -> CloudAuditReport:
        """Analyze pre-parsed list of cloud audit event records.

        Args:
            records: List of event dictionaries.
            detected_provider: M365 or GOOGLE_WORKSPACE.
            filename: Identifier for source.
            file_path: Optional file path.

        Returns:
            CloudAuditReport with triage findings.
        """
        serialized = json.dumps(records, default=str).encode("utf-8")
        hashes = {
            "md5": hashlib.md5(serialized).hexdigest(),
            "sha256": hashlib.sha256(serialized).hexdigest(),
        }
        return self._correlate_and_generate_report(
            raw_records=records,
            detected_provider=detected_provider,
            filename=filename,
            file_path=file_path,
            size_bytes=len(serialized),
            hashes=hashes,
        )

    # -------------------------------------------------------------------------
    # Ingestion & Schema Detection
    # -------------------------------------------------------------------------

    def _parse_cloud_log_text(self, text: str) -> Tuple[List[Dict[str, Any]], CloudProvider]:
        """Auto-detect format (JSON array, NDJSON, CSV) and provider (M365, Google Workspace)."""
        stripped = text.strip()
        records: List[Dict[str, Any]] = []
        provider = CloudProvider.UNKNOWN

        # 1. Try standard JSON or Reports API format
        if stripped.startswith(("{", "[")):
            try:
                data = json.loads(stripped)
                if isinstance(data, list):
                    records = [r for r in data if isinstance(r, dict)]
                elif isinstance(data, dict):
                    # Google Workspace Reports API {"items": [...]}
                    if "items" in data and isinstance(data["items"], list):
                        provider = CloudProvider.GOOGLE_WORKSPACE
                        records = [r for r in data["items"] if isinstance(r, dict)]
                    elif "value" in data and isinstance(data["value"], list):
                        records = [r for r in data["value"] if isinstance(r, dict)]
                    else:
                        records = [data]
            except Exception:
                pass

        # 2. Try NDJSON (Newline Delimited JSON)
        if not records and "\n" in stripped:
            ndjson_records = []
            for line in stripped.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        parsed = json.loads(line)
                        if isinstance(parsed, dict):
                            ndjson_records.append(parsed)
                    except Exception:
                        continue
            if ndjson_records:
                records = ndjson_records

        # 3. Try CSV Parsing
        if not records:
            try:
                reader = csv.DictReader(io.StringIO(stripped))
                for row in reader:
                    records.append(dict(row))
            except Exception:
                pass

        # Detect provider from records if still unknown
        if provider == CloudProvider.UNKNOWN and records:
            first = records[0]
            if (
                "Workload" in first
                or "RecordType" in first
                or "AuditData" in first
                or "Operation" in first
            ):
                provider = CloudProvider.M365
            elif "actor" in first or "events" in first or "id" in first:
                provider = CloudProvider.GOOGLE_WORKSPACE
            elif any("email" in k.lower() or "admin" in k.lower() for k in first.keys()):
                provider = CloudProvider.GOOGLE_WORKSPACE

        if provider == CloudProvider.UNKNOWN:
            provider = CloudProvider.M365  # Default fallback

        return records, provider

    def _normalize_m365_record(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten and parse nested JSON AuditData from M365 UAL records."""
        data = dict(raw)
        # Parse nested AuditData JSON string if present
        if "AuditData" in data and isinstance(data["AuditData"], str):
            try:
                audit_dict = json.loads(data["AuditData"])
                if isinstance(audit_dict, dict):
                    for k, v in audit_dict.items():
                        if k not in data:
                            data[k] = v
            except Exception:
                pass

        # Parse Parameters into dictionary
        params: Dict[str, Any] = {}
        if "Parameters" in data:
            raw_p = data["Parameters"]
            if isinstance(raw_p, list):
                for p in raw_p:
                    if isinstance(p, dict) and "Name" in p and "Value" in p:
                        params[p["Name"]] = p["Value"]
            elif isinstance(raw_p, dict):
                params = raw_p

        data["NormalizedParameters"] = params
        return data

    def _parse_timestamp(self, ts_raw: Any) -> datetime:
        """Parse ISO timestamp or epoch millisecond integer to UTC datetime."""
        if isinstance(ts_raw, datetime):
            return ts_raw if ts_raw.tzinfo else ts_raw.replace(tzinfo=timezone.utc)
        if isinstance(ts_raw, (int, float)):
            try:
                return datetime.fromtimestamp(
                    ts_raw / 1000.0 if ts_raw > 1e11 else ts_raw, tz=timezone.utc
                )
            except Exception:
                pass
        if isinstance(ts_raw, str):
            return WindowsLogAnalyzer._parse_iso_timestamp(ts_raw)
        return datetime.now(timezone.utc)

    # -------------------------------------------------------------------------
    # Correlation & Threat Engine
    # -------------------------------------------------------------------------

    def _correlate_and_generate_report(
        self,
        raw_records: List[Dict[str, Any]],
        detected_provider: CloudProvider,
        filename: str,
        file_path: Optional[str],
        size_bytes: int,
        hashes: Dict[str, str],
    ) -> CloudAuditReport:
        """Process cloud records, detect threat anomalies, and build Master Timeline."""
        inbox_rules: List[M365InboxRuleRecord] = []
        mailbox_delegations: List[M365MailboxPermissionRecord] = []
        oauth_consents: List[CloudOAuthConsentRecord] = []
        logins: List[CloudLoginRecord] = []
        google_admin_events: List[GoogleAdminAuditEvent] = []

        events_by_op: Dict[str, int] = {}
        timeline_start: Optional[datetime] = None
        timeline_end: Optional[datetime] = None

        unique_users: Set[str] = set()
        unique_ips: Set[str] = set()
        external_forwarding_set: Set[str] = set()

        for raw in raw_records:
            norm = self._normalize_m365_record(raw)
            op = norm.get("Operation") or norm.get("Event") or norm.get("name") or "UNKNOWN_OP"
            events_by_op[op] = events_by_op.get(op, 0) + 1

            ts = self._parse_timestamp(
                norm.get("CreationTime")
                or norm.get("CreationDate")
                or norm.get("Date")
                or norm.get("timestamp")
                or norm.get("id", {}).get("time")
            )
            if timeline_start is None or ts < timeline_start:
                timeline_start = ts
            if timeline_end is None or ts > timeline_end:
                timeline_end = ts

            user = (
                norm.get("UserId")
                or norm.get("UserIds")
                or norm.get("Actor")
                or norm.get("actor", {}).get("email")
                or "UNKNOWN_USER"
            )
            if user and user != "UNKNOWN_USER":
                unique_users.add(user)

            client_ip = (
                norm.get("ClientIP")
                or norm.get("ClientIPAddress")
                or norm.get("IP Address")
                or norm.get("ipAddress")
            )
            if client_ip and client_ip not in ("-", "127.0.0.1", "::1"):
                unique_ips.add(client_ip)

            params = norm.get("NormalizedParameters", {})

            # 1. M365 Inbox Rules (New-InboxRule, Set-InboxRule, Enable-InboxRule)
            if op.lower() in ("new-inboxrule", "set-inboxrule", "enable-inboxrule"):
                rule_name = params.get("Name") or norm.get("RuleName") or "UnnamedRule"
                fwd_to = self._extract_email_list(params.get("ForwardTo") or norm.get("ForwardTo"))
                red_to = self._extract_email_list(
                    params.get("RedirectTo") or norm.get("RedirectTo")
                )
                fwd_att = self._extract_email_list(
                    params.get("ForwardAsAttachmentTo") or norm.get("ForwardAsAttachmentTo")
                )
                move_folder = params.get("MoveToFolder") or norm.get("MoveToFolder")
                del_msg = (
                    str(params.get("DeleteMessage", "")).lower() == "true"
                    or "DeleteMessage" in params
                )
                mark_read = (
                    str(params.get("MarkAsRead", "")).lower() == "true" or "MarkAsRead" in params
                )
                subj_words = self._extract_string_list(params.get("SubjectContainsWords"))
                body_words = self._extract_string_list(params.get("BodyContainsWords"))

                for addr in fwd_to + red_to + fwd_att:
                    external_forwarding_set.add(addr)

                inbox_rule = M365InboxRuleRecord(
                    timestamp=ts,
                    record_id=norm.get("Id") or norm.get("RecordId"),
                    user_id=user,
                    client_ip=client_ip,
                    operation=op,
                    rule_name=rule_name,
                    mailbox_owner=norm.get("MailboxOwnerUPN") or user,
                    forward_to=fwd_to,
                    redirect_to=red_to,
                    forward_as_attachment_to=fwd_att,
                    move_to_folder=move_folder,
                    delete_message=del_msg,
                    mark_as_read=mark_read,
                    subject_contains_words=subj_words,
                    body_contains_words=body_words,
                    raw_parameters=params,
                )
                inbox_rules.append(inbox_rule)

            # 2. M365 Mailbox Delegation (Add-MailboxPermission, Add-RecipientPermission)
            elif op.lower() in ("add-mailboxpermission", "add-recipientpermission", "set-mailbox"):
                mbx_owner = (
                    norm.get("MailboxOwnerUPN")
                    or params.get("Identity")
                    or norm.get("Identity")
                    or user
                )
                delegate = (
                    params.get("User")
                    or params.get("Trustee")
                    or norm.get("Delegate")
                    or "UNKNOWN_DELEGATE"
                )
                rights_raw = params.get("AccessRights") or norm.get("AccessRights", "")
                rights = [r.strip() for r in str(rights_raw).split(",") if r.strip()]

                delegation = M365MailboxPermissionRecord(
                    timestamp=ts,
                    record_id=norm.get("Id") or norm.get("RecordId"),
                    user_id=user,
                    client_ip=client_ip,
                    operation=op,
                    mailbox_owner=mbx_owner,
                    delegate_user=delegate,
                    access_rights=rights,
                    is_external_delegate="@" in delegate
                    and not delegate.lower().endswith(
                        user.split("@")[-1].lower() if "@" in user else ""
                    ),
                )
                mailbox_delegations.append(delegation)

            # 3. OAuth Application Grants & Consent
            elif any(
                grant_op in op.lower()
                for grant_op in (
                    "consent to application",
                    "authorize application",
                    "add app role assignment",
                    "add service principal",
                )
            ):
                app_name = (
                    norm.get("ApplicationName")
                    or params.get("AppDisplayName")
                    or norm.get("Target", [{}])[0].get("name", "UnknownApp")
                    if isinstance(norm.get("Target"), list)
                    else "UnknownApp"
                )
                scopes_raw = norm.get("Scope") or params.get("Scope") or norm.get("Permissions", "")
                scopes = [s.strip() for s in re.split(r"[\s,]+", str(scopes_raw)) if s.strip()]

                oauth = CloudOAuthConsentRecord(
                    timestamp=ts,
                    record_id=norm.get("Id") or norm.get("RecordId"),
                    provider=detected_provider,
                    user_id=user,
                    client_ip=client_ip,
                    app_name=app_name,
                    app_id=norm.get("AppId") or params.get("AppId"),
                    client_id=norm.get("ClientId"),
                    scopes=scopes,
                    is_admin_consent="admin" in op.lower()
                    or str(norm.get("IsAdminConsent", "")).lower() == "true",
                )
                oauth_consents.append(oauth)

            # 4. Cloud Logins (M365 UserLoggedIn, Google Workspace login)
            elif op.lower() in (
                "userloggedin",
                "userloginfailed",
                "login",
                "login_verification",
                "login_failure",
            ):
                is_success = (
                    "failed" not in op.lower()
                    and str(norm.get("ResultStatus", "success")).lower() == "success"
                )
                geo_val = norm.get("GeoLocation")
                geo_dict: Dict[str, Any] = geo_val if isinstance(geo_val, dict) else {}
                city = norm.get("City") or norm.get("location_city") or geo_dict.get("City")
                country = (
                    norm.get("Country")
                    or norm.get("CountryCode")
                    or norm.get("location_country")
                    or geo_dict.get("Country")
                )

                login_evt = CloudLoginRecord(
                    timestamp=ts,
                    record_id=norm.get("Id") or norm.get("RecordId"),
                    provider=detected_provider,
                    user_id=user,
                    client_ip=client_ip or "0.0.0.0",
                    location_city=city,
                    location_country=country,
                    user_agent=norm.get("UserAgent"),
                    is_success=is_success,
                    error_code=norm.get("ErrorCode") or norm.get("LogonError"),
                )
                logins.append(login_evt)

            # 5. Google Workspace Admin Audit Events
            elif (
                detected_provider == CloudProvider.GOOGLE_WORKSPACE
                or "actor" in norm
                or "events" in norm
            ):
                if "events" in norm and isinstance(norm["events"], list):
                    for sub_evt in norm["events"]:
                        sub_name = sub_evt.get("name") or op
                        sub_type = sub_evt.get("type")
                        sub_params: Dict[str, Any] = {}
                        if "parameters" in sub_evt and isinstance(sub_evt["parameters"], list):
                            for p in sub_evt["parameters"]:
                                if isinstance(p, dict) and "name" in p and "value" in p:
                                    sub_params[p["name"]] = p["value"]

                        admin_evt = GoogleAdminAuditEvent(
                            timestamp=ts,
                            record_id=norm.get("id", {}).get("uniqueQualifier")
                            if isinstance(norm.get("id"), dict)
                            else norm.get("RecordId"),
                            actor_email=user,
                            ip_address=client_ip,
                            event_name=sub_name,
                            event_type=sub_type,
                            target_user=norm.get("TargetUser"),
                            parameters=sub_params,
                        )
                        google_admin_events.append(admin_evt)
                else:
                    admin_evt = GoogleAdminAuditEvent(
                        timestamp=ts,
                        record_id=norm.get("id", {}).get("uniqueQualifier")
                        if isinstance(norm.get("id"), dict)
                        else norm.get("RecordId"),
                        actor_email=user,
                        ip_address=client_ip,
                        event_name=op,
                        event_type=norm.get("type"),
                        target_user=norm.get("TargetUser"),
                        parameters=params or norm,
                    )
                    google_admin_events.append(admin_evt)

        # Detect Threat Anomalies
        anomalies = self._detect_cloud_anomalies(
            inbox_rules=inbox_rules,
            delegations=mailbox_delegations,
            oauth_consents=oauth_consents,
            logins=logins,
            google_events=google_admin_events,
        )

        # Threat Scoring & Verdict
        threat_score, verdict = self._calculate_cloud_threat_score(anomalies)

        # Extract IOCs
        extracted_iocs = self._extract_cloud_iocs(
            anomalies, inbox_rules, mailbox_delegations, oauth_consents
        )

        # Master Timeline Synthesis
        timeline_events = self._synthesize_cloud_timeline(
            inbox_rules=inbox_rules,
            delegations=mailbox_delegations,
            oauth_consents=oauth_consents,
            logins=logins,
            google_events=google_admin_events,
            anomalies=anomalies,
        )

        # Executive Summary & Remediation
        summary = self._generate_cloud_summary(
            total_records=len(raw_records),
            provider=detected_provider,
            inbox_rules=inbox_rules,
            delegations=mailbox_delegations,
            oauth_consents=oauth_consents,
            logins=logins,
            admin_events=google_admin_events,
            anomalies=anomalies,
            verdict=verdict,
            threat_score=threat_score,
        )
        remediation = self._generate_cloud_remediation(anomalies)

        return CloudAuditReport(
            file_path=file_path,
            filename=filename,
            size_bytes=size_bytes,
            hashes=hashes,
            detected_provider=detected_provider,
            total_records_parsed=len(raw_records),
            total_inbox_rules=len(inbox_rules),
            total_mailbox_delegations=len(mailbox_delegations),
            total_oauth_consents=len(oauth_consents),
            total_logins=len(logins),
            total_admin_events=len(google_admin_events),
            events_by_operation=events_by_op,
            timeline_start=timeline_start,
            timeline_end=timeline_end,
            inbox_rules=inbox_rules,
            mailbox_delegations=mailbox_delegations,
            oauth_consents=oauth_consents,
            logins=logins,
            google_admin_events=google_admin_events,
            anomalies=anomalies,
            unique_users=sorted(list(unique_users)),
            unique_client_ips=sorted(list(unique_ips)),
            external_forwarding_destinations=sorted(list(external_forwarding_set)),
            timeline_events=timeline_events,
            threat_score=threat_score,
            verdict=verdict,
            extracted_iocs=extracted_iocs,
            executive_summary=summary,
            remediation_guidance=remediation,
        )

    # -------------------------------------------------------------------------
    # Helper Parsing Utilities
    # -------------------------------------------------------------------------

    def _extract_email_list(self, val: Any) -> List[str]:
        """Extract email addresses from list, string, or semi-colon/comma delimited string."""
        if not val:
            return []
        if isinstance(val, list):
            res: List[str] = []
            for item in val:
                res.extend(self._extract_email_list(item))
            return res
        if isinstance(val, str):
            return [addr.strip().lower() for addr in re.split(r"[;,|\s]+", val) if "@" in addr]
        return []

    def _extract_string_list(self, val: Any) -> List[str]:
        """Extract strings from list or delimited string."""
        if not val:
            return []
        if isinstance(val, list):
            return [str(s).strip() for s in val if str(s).strip()]
        if isinstance(val, str):
            return [s.strip() for s in re.split(r"[,;]+", val) if s.strip()]
        return []

    # -------------------------------------------------------------------------
    # Threat & Anomaly Detection Heuristics
    # -------------------------------------------------------------------------

    def _detect_cloud_anomalies(
        self,
        inbox_rules: List[M365InboxRuleRecord],
        delegations: List[M365MailboxPermissionRecord],
        oauth_consents: List[CloudOAuthConsentRecord],
        logins: List[CloudLoginRecord],
        google_events: List[GoogleAdminAuditEvent],
    ) -> List[CloudAnomalyAlert]:
        """Evaluate cloud records against threat heuristics."""
        anomalies: List[CloudAnomalyAlert] = []

        # 1. Malicious Inbox Rules (External Forwarding / Redirection) (T1114.003)
        for rule in inbox_rules:
            all_fwd = rule.forward_to + rule.redirect_to + rule.forward_as_attachment_to
            if all_fwd:
                user_domain = rule.user_id.split("@")[-1].lower() if "@" in rule.user_id else ""
                ext_fwd = [f for f in all_fwd if user_domain and not f.endswith(f"@{user_domain}")]
                target_dest = ext_fwd if ext_fwd else all_fwd

                anomalies.append(
                    CloudAnomalyAlert(
                        timestamp=rule.timestamp,
                        provider=CloudProvider.M365,
                        classification=CloudThreatClassification.EXTERNAL_FORWARDING,
                        severity="CRITICAL",
                        actor_user=rule.user_id,
                        target_mailbox_or_user=rule.mailbox_owner,
                        client_ip=rule.client_ip,
                        mitre_attack_technique="T1114.003 - Email Forwarding Rule: Automated Exfiltration",
                        detection_reason=f"Inbox rule '{rule.rule_name}' created on mailbox '{rule.mailbox_owner}' automatically forwarding/redirecting messages to external address(es): {', '.join(target_dest)}.",
                        evidence={"rule_name": rule.rule_name, "forward_to": target_dest},
                    )
                )

        # 2. Email Hiding & Defense Evasion Rules (T1564.008)
        for rule in inbox_rules:
            reasons = []
            is_hiding = False

            if rule.move_to_folder:
                folder_clean = rule.move_to_folder.strip().lower()
                if any(sf in folder_clean for sf in self.SUSPICIOUS_FOLDERS):
                    is_hiding = True
                    reasons.append(
                        f"moves incoming emails to hiding folder '{rule.move_to_folder}'"
                    )

            if rule.delete_message:
                is_hiding = True
                reasons.append("automatically deletes incoming email messages")

            if rule.mark_as_read and (rule.subject_contains_words or rule.body_contains_words):
                is_hiding = True
                reasons.append("automatically marks targeted emails as read")

            if is_hiding:
                matched_keywords = [
                    kw
                    for kw in (rule.subject_contains_words + rule.body_contains_words)
                    if any(sk in kw.lower() for sk in self.SUSPICIOUS_RULE_KEYWORDS)
                ]
                if matched_keywords:
                    reasons.append(
                        f"targets security/financial keywords: {', '.join(matched_keywords)}"
                    )

                anomalies.append(
                    CloudAnomalyAlert(
                        timestamp=rule.timestamp,
                        provider=CloudProvider.M365,
                        classification=CloudThreatClassification.EMAIL_HIDING_RULE,
                        severity="CRITICAL",
                        actor_user=rule.user_id,
                        target_mailbox_or_user=rule.mailbox_owner,
                        client_ip=rule.client_ip,
                        mitre_attack_technique="T1564.008 - Defense Evasion: Email Hiding Rules",
                        detection_reason=f"Inbox rule '{rule.rule_name}' on mailbox '{rule.mailbox_owner}' hides incoming emails: {'; '.join(reasons)}.",
                        evidence={"rule_name": rule.rule_name, "reasons": reasons},
                    )
                )

        # 3. Mailbox Delegation Backdoors (T1098.002)
        for d in delegations:
            is_full = any("fullaccess" in r.lower() for r in d.access_rights)
            is_send = any(
                "sendas" in r.lower() or "sendonbehalf" in r.lower() for r in d.access_rights
            )

            if is_full or is_send or d.is_external_delegate:
                severity = "CRITICAL" if (is_full and d.is_external_delegate) else "HIGH"
                anomalies.append(
                    CloudAnomalyAlert(
                        timestamp=d.timestamp,
                        provider=CloudProvider.M365,
                        classification=CloudThreatClassification.UNAUTHORIZED_MAILBOX_DELEGATION,
                        severity=severity,
                        actor_user=d.user_id,
                        target_mailbox_or_user=d.mailbox_owner,
                        client_ip=d.client_ip,
                        mitre_attack_technique="T1098.002 - Account Manipulation: Additional Email Delegate Permissions",
                        detection_reason=f"Mailbox permissions ({', '.join(d.access_rights)}) on '{d.mailbox_owner}' granted to delegate '{d.delegate_user}' by '{d.user_id}'.",
                        evidence={
                            "mailbox": d.mailbox_owner,
                            "delegate": d.delegate_user,
                            "rights": d.access_rights,
                        },
                    )
                )

        # 4. Illicit OAuth Application Consent (T1528 / T1550.001)
        for oauth in oauth_consents:
            high_risk = [
                s
                for s in oauth.scopes
                if any(hr in s.lower() for hr in self.HIGH_RISK_OAUTH_SCOPES)
            ]
            if high_risk:
                anomalies.append(
                    CloudAnomalyAlert(
                        timestamp=oauth.timestamp,
                        provider=oauth.provider,
                        classification=CloudThreatClassification.ILLICIT_OAUTH_CONSENT,
                        severity="CRITICAL",
                        actor_user=oauth.user_id,
                        client_ip=oauth.client_ip,
                        mitre_attack_technique="T1528 - Steal Application Access Token / Illicit Consent Grant",
                        detection_reason=f"OAuth application '{oauth.app_name}' granted high-risk mailbox access scopes ({', '.join(high_risk)}) by '{oauth.user_id}'.",
                        evidence={
                            "app_name": oauth.app_name,
                            "scopes": oauth.scopes,
                            "high_risk_scopes": high_risk,
                        },
                    )
                )

        # 5. Impossible Travel & Multi-Geo Logins (T1078.004)
        logins_by_user: Dict[str, List[CloudLoginRecord]] = {}
        for login_item in logins:
            if login_item.is_success and login_item.user_id not in ("-", "UNKNOWN_USER"):
                logins_by_user.setdefault(login_item.user_id.lower(), []).append(login_item)

        for user, user_logins in logins_by_user.items():
            user_logins.sort(key=lambda x: x.timestamp)
            for i in range(len(user_logins) - 1):
                cur = user_logins[i]
                nxt = user_logins[i + 1]
                time_diff = (nxt.timestamp - cur.timestamp).total_seconds()

                # Different countries within impossible travel threshold
                if (
                    cur.location_country
                    and nxt.location_country
                    and cur.location_country != nxt.location_country
                ):
                    if 0 <= time_diff <= self.impossible_travel_threshold_seconds:
                        anomalies.append(
                            CloudAnomalyAlert(
                                timestamp=nxt.timestamp,
                                provider=nxt.provider,
                                classification=CloudThreatClassification.IMPOSSIBLE_TRAVEL_LOGIN,
                                severity="CRITICAL",
                                actor_user=user,
                                client_ip=nxt.client_ip,
                                mitre_attack_technique="T1078.004 - Valid Accounts: Cloud Accounts (Impossible Travel)",
                                detection_reason=f"Impossible travel detected for user '{user}': Login from '{cur.location_country}' ({cur.client_ip}) followed by login from '{nxt.location_country}' ({nxt.client_ip}) within {int(time_diff / 60)} minutes.",
                                evidence={
                                    "origin_country": cur.location_country,
                                    "origin_ip": cur.client_ip,
                                    "destination_country": nxt.location_country,
                                    "destination_ip": nxt.client_ip,
                                    "time_diff_seconds": time_diff,
                                },
                            )
                        )

        # 6. Google Workspace Admin & Routing Manipulation
        for g_evt in google_events:
            op_lower = g_evt.event_name.lower()
            if any(
                kw in op_lower
                for kw in (
                    "change_user_setting",
                    "email_routing",
                    "auto_forwarding",
                    "grant_admin_privilege",
                )
            ):
                severity = "CRITICAL" if "admin" in op_lower else "HIGH"
                anomalies.append(
                    CloudAnomalyAlert(
                        timestamp=g_evt.timestamp,
                        provider=CloudProvider.GOOGLE_WORKSPACE,
                        classification=CloudThreatClassification.SUSPICIOUS_ADMIN_ACTIVITY,
                        severity=severity,
                        actor_user=g_evt.actor_email,
                        target_mailbox_or_user=g_evt.target_user,
                        client_ip=g_evt.ip_address,
                        mitre_attack_technique="T1098 - Account Manipulation: Cloud Admin Routing/Privilege",
                        detection_reason=f"Google Workspace Admin operation '{g_evt.event_name}' executed by '{g_evt.actor_email}'.",
                        evidence={"event_name": g_evt.event_name, "parameters": g_evt.parameters},
                    )
                )

        return anomalies

    # -------------------------------------------------------------------------
    # Master Timeline Synthesis
    # -------------------------------------------------------------------------

    def _synthesize_cloud_timeline(
        self,
        inbox_rules: List[M365InboxRuleRecord],
        delegations: List[M365MailboxPermissionRecord],
        oauth_consents: List[CloudOAuthConsentRecord],
        logins: List[CloudLoginRecord],
        google_events: List[GoogleAdminAuditEvent],
        anomalies: List[CloudAnomalyAlert],
    ) -> List[TimelineEvent]:
        """Convert cloud audit records into canonical UTC TimelineEvents."""
        timeline: List[TimelineEvent] = []

        # Convert Inbox Rules
        for rule in inbox_rules:
            matched_anomalies = [
                a.classification.value
                for a in anomalies
                if a.actor_user.lower() == rule.user_id.lower()
                and abs((a.timestamp - rule.timestamp).total_seconds()) < 60
            ]
            fwd_str = (
                f" (Forward: {', '.join(rule.forward_to + rule.redirect_to)})"
                if (rule.forward_to or rule.redirect_to)
                else ""
            )
            timeline.append(
                TimelineEvent(
                    timestamp_utc=rule.timestamp,
                    event_type="CLOUD_INBOX_RULE_CREATED",
                    source=f"M365 Audit Log ({rule.operation})",
                    description=f"Inbox Rule '{rule.rule_name}' created on mailbox '{rule.mailbox_owner}' by '{rule.user_id}'{fwd_str}.",
                    actor_or_host=f"{rule.user_id}@{rule.client_ip or 'cloud'}",
                    anomalies=matched_anomalies,
                    details={
                        "rule_name": rule.rule_name,
                        "mailbox": rule.mailbox_owner,
                        "forward_to": rule.forward_to,
                        "redirect_to": rule.redirect_to,
                        "move_to_folder": rule.move_to_folder,
                        "delete_message": rule.delete_message,
                    },
                )
            )

        # Convert Mailbox Delegations
        for d in delegations:
            matched_anomalies = [
                a.classification.value
                for a in anomalies
                if a.actor_user.lower() == d.user_id.lower()
                and abs((a.timestamp - d.timestamp).total_seconds()) < 60
            ]
            timeline.append(
                TimelineEvent(
                    timestamp_utc=d.timestamp,
                    event_type="CLOUD_MAILBOX_DELEGATION_GRANTED",
                    source="M365 Audit Log (Add-MailboxPermission)",
                    description=f"Mailbox delegation rights ({', '.join(d.access_rights)}) on '{d.mailbox_owner}' granted to '{d.delegate_user}' by '{d.user_id}'.",
                    actor_or_host=f"{d.user_id}@{d.client_ip or 'cloud'}",
                    anomalies=matched_anomalies,
                    details={
                        "mailbox": d.mailbox_owner,
                        "delegate": d.delegate_user,
                        "access_rights": d.access_rights,
                    },
                )
            )

        # Convert OAuth Consents
        for oauth in oauth_consents:
            matched_anomalies = [
                a.classification.value
                for a in anomalies
                if a.actor_user.lower() == oauth.user_id.lower()
                and abs((a.timestamp - oauth.timestamp).total_seconds()) < 60
            ]
            timeline.append(
                TimelineEvent(
                    timestamp_utc=oauth.timestamp,
                    event_type="CLOUD_OAUTH_CONSENT_GRANTED",
                    source=f"{oauth.provider.value} Audit Log (OAuth Consent)",
                    description=f"OAuth application '{oauth.app_name}' granted scopes ({', '.join(oauth.scopes)}) by '{oauth.user_id}'.",
                    actor_or_host=f"{oauth.user_id}@{oauth.client_ip or 'cloud'}",
                    anomalies=matched_anomalies,
                    details={
                        "app_name": oauth.app_name,
                        "scopes": oauth.scopes,
                        "app_id": oauth.app_id,
                    },
                )
            )

        # Convert Cloud Logins
        for login_item in logins:
            status_str = "Login Success" if login_item.is_success else "Login Failed"
            loc_str = (
                f" [{login_item.location_city or ''} {login_item.location_country or ''}]".strip()
            )
            timeline.append(
                TimelineEvent(
                    timestamp_utc=login_item.timestamp,
                    event_type="CLOUD_LOGIN_SUCCESS"
                    if login_item.is_success
                    else "CLOUD_LOGIN_FAILURE",
                    source=f"{login_item.provider.value} Authentication Log",
                    description=f"{status_str}: '{login_item.user_id}' from {login_item.client_ip}{loc_str}.",
                    actor_or_host=f"{login_item.user_id}@{login_item.client_ip}",
                    details={
                        "user": login_item.user_id,
                        "ip": login_item.client_ip,
                        "country": login_item.location_country,
                        "is_success": login_item.is_success,
                    },
                )
            )

        # Convert Google Workspace Admin Events
        for g_item in google_events:
            timeline.append(
                TimelineEvent(
                    timestamp_utc=g_item.timestamp,
                    event_type=f"GOOGLE_ADMIN_{g_item.event_name}",
                    source="Google Workspace Admin Audit",
                    description=f"Admin Event '{g_item.event_name}' executed by '{g_item.actor_email}'.",
                    actor_or_host=f"{g_item.actor_email}@{g_item.ip_address or 'cloud'}",
                    details=g_item.parameters,
                )
            )

        # Sort chronologically and compute delta timings
        timeline.sort(key=lambda t: t.timestamp_utc)

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
    # Scoring & Attribution
    # -------------------------------------------------------------------------

    def _calculate_cloud_threat_score(
        self, anomalies: List[CloudAnomalyAlert]
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

    def _extract_cloud_iocs(
        self,
        anomalies: List[CloudAnomalyAlert],
        inbox_rules: List[M365InboxRuleRecord],
        delegations: List[M365MailboxPermissionRecord],
        oauth_consents: List[CloudOAuthConsentRecord],
    ) -> List[str]:
        """Extract actionable IoCs (forwarding addresses, attacker IPs, rogue delegates, app IDs)."""
        iocs: Set[str] = set()

        for a in anomalies:
            if a.client_ip and a.client_ip not in ("-", "127.0.0.1", "::1", "0.0.0.0"):
                iocs.add(f"Attacker-IP: {a.client_ip}")

        for rule in inbox_rules:
            for addr in rule.forward_to + rule.redirect_to + rule.forward_as_attachment_to:
                iocs.add(f"Exfiltration-Email: {addr}")

        for d in delegations:
            if d.is_external_delegate:
                iocs.add(f"Rogue-Delegate: {d.delegate_user}")

        for oauth in oauth_consents:
            if any(hr in s.lower() for hr in self.HIGH_RISK_OAUTH_SCOPES for s in oauth.scopes):
                iocs.add(f"Illicit-OAuth-App: {oauth.app_name} (ID: {oauth.app_id or 'N/A'})")

        return sorted(list(iocs))

    def _generate_cloud_summary(
        self,
        total_records: int,
        provider: CloudProvider,
        inbox_rules: List[M365InboxRuleRecord],
        delegations: List[M365MailboxPermissionRecord],
        oauth_consents: List[CloudOAuthConsentRecord],
        logins: List[CloudLoginRecord],
        admin_events: List[GoogleAdminAuditEvent],
        anomalies: List[CloudAnomalyAlert],
        verdict: str,
        threat_score: float,
    ) -> str:
        """Construct executive summary describing cloud audit log findings."""
        lines = [
            f"Cloud Audit Log Forensic Triage completed for {provider.value} on {total_records} record(s).",
            f"Telemetry Summary: {len(inbox_rules)} inbox rule operations, {len(delegations)} mailbox delegations, {len(oauth_consents)} OAuth grants, {len(logins)} logins, {len(admin_events)} admin actions.",
            f"Forensic Threat Score: {threat_score}/100.0 (Verdict: {verdict}).",
        ]

        if not anomalies:
            lines.append(
                "No malicious inbox forwarding, email hiding rules, or unauthorized delegation detected."
            )
        else:
            lines.append(f"Identified {len(anomalies)} cloud security anomaly alert(s):")
            for idx, a in enumerate(anomalies[:6], 1):
                lines.append(
                    f"  {idx}. [{a.severity}] {a.classification.value}: {a.detection_reason}"
                )
            if len(anomalies) > 6:
                lines.append(f"  ... and {len(anomalies) - 6} additional cloud finding(s).")

        return "\n".join(lines)

    def _generate_cloud_remediation(self, anomalies: List[CloudAnomalyAlert]) -> List[str]:
        """Generate tactical IR remediation guidance for detected cloud threats."""
        if not anomalies:
            return [
                "Maintain continuous unified audit logging (UAL) and enforce Conditional Access / MFA policies."
            ]

        guidance: Set[str] = {
            "Immediately reset compromised account credentials and revoke all active OAuth refresh tokens / Azure AD sessions (Revoke-AzureADUserAllRefreshToken).",
            "Enforce Multi-Factor Authentication (MFA) and Conditional Access policies blocking non-compliant geolocations.",
        }

        for a in anomalies:
            if a.classification in (
                CloudThreatClassification.EXTERNAL_FORWARDING,
                CloudThreatClassification.MALICIOUS_INBOX_RULE,
                CloudThreatClassification.EMAIL_HIDING_RULE,
            ):
                guidance.add(
                    "Audit and delete unauthorized inbox forwarding/hiding rules via PowerShell: Remove-InboxRule."
                )
                guidance.add(
                    "Enforce tenant-wide Outbound Anti-Spam policy blocking automatic external email forwarding."
                )
            elif a.classification == CloudThreatClassification.UNAUTHORIZED_MAILBOX_DELEGATION:
                guidance.add(
                    "Remove rogue mailbox delegate permissions: Remove-MailboxPermission / Remove-RecipientPermission."
                )
            elif a.classification == CloudThreatClassification.ILLICIT_OAUTH_CONSENT:
                guidance.add(
                    "Revoke illicit Enterprise Application OAuth consent grants in Microsoft Entra ID / Google Admin Console."
                )
            elif a.classification == CloudThreatClassification.IMPOSSIBLE_TRAVEL_LOGIN:
                guidance.add(
                    "Inspect Microsoft Entra Risky Users / Risky Sign-ins and enforce Location-based Conditional Access."
                )

        return sorted(list(guidance))
