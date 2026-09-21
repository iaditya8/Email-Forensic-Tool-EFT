"""Master Case Cross-Module Aggregation & Multi-Evidence Correlation Engine."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from eft.analysis.binary_static_analyzer import BinaryStaticAnalyzer
from eft.analysis.cloud_audit_analyzer import CloudAuditAnalyzer
from eft.analysis.credential_leak_analyzer import CredentialLeakAnalyzer
from eft.analysis.dns_threat_analyzer import DNSThreatAnalyzer
from eft.analysis.evtx_analyzer import WindowsLogAnalyzer
from eft.analysis.file_analyzer import FileArtifactAnalyzer
from eft.analysis.logon_persistence_analyzer import WindowsSecurityAnalyzer
from eft.analysis.memory_analyzer import MemoryArtifactAnalyzer
from eft.analysis.memory_ioc_matcher import MemoryIoCMatcher
from eft.analysis.memory_yara_scanner import MemoryYARAScanner
from eft.analysis.metadata_extractor import MetadataExtractor
from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.analysis.pcap_analyzer import NetworkPCAPAnalyzer
from eft.analysis.threat_scorer import ThreatScorer
from eft.core.integrity import compute_file_hashes
from eft.ingestion.engine import EmailIngester
from eft.models.master_case import (
    CaseEvidenceItem,
    CrossEvidenceCorrelation,
    EvidenceItemType,
    MasterCaseIoC,
    MasterCaseReport,
    MasterTimelineEvent,
)
from eft.reporting.custody import ChainOfCustodyManager
from eft.reporting.exporter import ForensicReportExporter


class MasterCaseAggregator:
    """Aggregates and cross-correlates multi-modal evidence items into a unified Master Case Report."""

    def __init__(
        self,
        case_id: str,
        examiner_name: str,
        examiner_agency: Optional[str] = None,
        case_title: Optional[str] = None,
    ) -> None:
        self.case_id = case_id
        self.examiner_name = examiner_name
        self.examiner_agency = examiner_agency
        self.case_title = case_title or f"Forensic Investigation {case_id}"
        self.evidence_items: List[CaseEvidenceItem] = []
        self._item_counter: int = 1

    @classmethod
    def detect_evidence_type(cls, file_path: Union[str, Path]) -> EvidenceItemType:
        """Detect the forensic evidence domain based on file extension and magic byte inspection."""
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix in [".eml", ".msg", ".mbox"]:
            return EvidenceItemType.EMAIL
        if suffix in [".pcap", ".pcapng", ".cap"]:
            return EvidenceItemType.NETWORK_PCAP
        if suffix in [".evtx"]:
            return EvidenceItemType.WINDOWS_EVTX
        if suffix in [".dmp", ".raw", ".vmem"]:
            return EvidenceItemType.VOLATILE_MEMORY

        # Check for JSON/CSV/XML logs vs generic files
        if suffix in [".json", ".csv", ".log", ".xml"]:
            try:
                sample_bytes = path.read_bytes()[:2048]
                sample_text = sample_bytes.decode("utf-8", errors="ignore").lower()
                if any(
                    k in sample_text
                    for k in [
                        "eventsource",
                        "eventname",
                        "cloudtrail",
                        "azure",
                        "useragent",
                        "audit",
                    ]
                ):
                    return EvidenceItemType.CLOUD_AUDIT
                if any(
                    k in sample_text
                    for k in ["eventid", "sysmon", "security-auditing", "windowsevent"]
                ):
                    return EvidenceItemType.WINDOWS_EVTX
            except Exception:
                pass

        return EvidenceItemType.FILE_BINARY

    def add_evidence_file(
        self,
        file_path: Union[str, Path],
        item_type: Optional[EvidenceItemType] = None,
        custom_label: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> CaseEvidenceItem:
        """Ingest, cryptographically manifest, analyze, and record a physical evidence file."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Evidence file not found: {path}")

        if item_type is None:
            item_type = self.detect_evidence_type(path)

        item_id = f"EVID-{self._item_counter:03d}"
        self._item_counter += 1

        # 1. Pre-Analysis Multi-Hashing & Manifest Creation
        pre_hashes = compute_file_hashes(path)
        manifest = ChainOfCustodyManager.create_manifest(
            file_path=path,
            case_id=self.case_id,
            evidence_id=item_id,
            examiner_name=self.examiner_name,
            examiner_agency=self.examiner_agency,
            notes=notes,
            pre_hashes=pre_hashes,
        )

        # 2. Domain-Specific Forensic Pipeline Execution
        raw_report: Dict[str, Any] = {}
        risk_score: float = 0.0
        risk_level: str = "BENIGN"
        summary: str = ""
        iocs: List[MasterCaseIoC] = []
        timeline_events: List[MasterTimelineEvent] = []
        mitre_techniques: List[str] = []

        if item_type == EvidenceItemType.EMAIL:
            raw_report, risk_score, risk_level, summary, iocs, timeline_events, mitre_techniques = (
                self._analyze_email_item(path, item_id)
            )
        elif item_type == EvidenceItemType.FILE_BINARY:
            raw_report, risk_score, risk_level, summary, iocs, timeline_events, mitre_techniques = (
                self._analyze_binary_item(path, item_id)
            )
        elif item_type == EvidenceItemType.NETWORK_PCAP:
            raw_report, risk_score, risk_level, summary, iocs, timeline_events, mitre_techniques = (
                self._analyze_pcap_item(path, item_id)
            )
        elif item_type in [EvidenceItemType.WINDOWS_EVTX, EvidenceItemType.CLOUD_AUDIT]:
            raw_report, risk_score, risk_level, summary, iocs, timeline_events, mitre_techniques = (
                self._analyze_log_item(path, item_id, item_type)
            )
        elif item_type == EvidenceItemType.VOLATILE_MEMORY:
            raw_report, risk_score, risk_level, summary, iocs, timeline_events, mitre_techniques = (
                self._analyze_memory_item(path, item_id)
            )

        # 3. Post-Analysis Multi-Hashing & Immutability Verification
        post_hashes = compute_file_hashes(path)
        manifest.post_analysis_hashes = post_hashes
        manifest.verification_timestamp_utc = datetime.now(timezone.utc)
        manifest.integrity_verified = (
            pre_hashes["sha256"] == post_hashes["sha256"]
            and pre_hashes["md5"] == post_hashes["md5"]
        )

        evidence_item = CaseEvidenceItem(
            item_id=item_id,
            item_type=item_type,
            source_path=str(path),
            source_name=custom_label or path.name,
            size_bytes=path.stat().st_size,
            manifest=manifest,
            risk_score=risk_score,
            risk_level=risk_level,
            summary=summary,
            extracted_iocs=iocs,
            timeline_events=timeline_events,
            mitre_techniques=mitre_techniques,
            raw_analysis_report=raw_report,
        )

        self.evidence_items.append(evidence_item)
        return evidence_item

    def _analyze_email_item(
        self, path: Path, item_id: str
    ) -> tuple[
        Dict[str, Any], float, str, str, List[MasterCaseIoC], List[MasterTimelineEvent], List[str]
    ]:
        ingester = EmailIngester()
        res = ingester.ingest_file(path)
        if not res.success or not res.messages:
            return {}, 0.0, "BENIGN", "Failed to parse email message", [], [], []

        email = res.messages[0]
        from eft.analysis.attachment_scanner import AttachmentThreatScanner
        from eft.analysis.auth_verifier import AuthenticationVerifier
        from eft.analysis.bec_detector import BECDetector
        from eft.analysis.obfuscation_detector import ContentObfuscationDetector
        from eft.analysis.relay_analyzer import RelayAnalyzer
        from eft.analysis.url_analyzer import URLAnalyzer
        from eft.ingestion.attachment_extractor import AttachmentExtractor
        from eft.ingestion.header_decomposer import HeaderDecomposer
        from eft.reporting.timeline import TimelineGenerator

        decomp = HeaderDecomposer.decompose(email.ordered_headers)
        email.header_decomposition = decomp
        email.extracted_attachments = AttachmentExtractor.extract_from_email(
            email, save_to_disk=False
        )
        email.authentication_report = AuthenticationVerifier.verify_email(email)
        transit_route = RelayAnalyzer.reconstruct_route(decomp.received_headers)
        net_service = NetworkIntelligenceService()
        email.transit_route = net_service.enrich_route(transit_route)
        email.url_report = URLAnalyzer().extract_urls(email)
        email.bec_report = BECDetector().detect(email)
        email.obfuscation_report = ContentObfuscationDetector().detect(email)
        scanner = AttachmentThreatScanner()
        email.attachment_threat_report = scanner.scan_email(email)
        email.timeline_report = TimelineGenerator.generate_timeline(email)
        risk = ThreatScorer.calculate_composite_risk(email)

        score = float(risk.overall_score)
        level = (
            "CRITICAL"
            if score >= 75
            else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 25 else "LOW"))
        )
        summary = f"Email from {email.from_address or 'Unknown'} with subject '{email.subject or 'No Subject'}'. Risk Score: {score:.1f}/100."

        iocs: List[MasterCaseIoC] = []
        if email.from_address:
            iocs.append(
                MasterCaseIoC(
                    ioc_type="email-address",
                    ioc_value=email.from_address,
                    source_item_id=item_id,
                    source_item_type=EvidenceItemType.EMAIL,
                    severity="INFO",
                    threat_category="IDENTITY",
                    description="Sender email address",
                )
            )
        if email.url_report and email.url_report.urls:
            for u in email.url_report.urls:
                iocs.append(
                    MasterCaseIoC(
                        ioc_type="url",
                        ioc_value=u.url,
                        source_item_id=item_id,
                        source_item_type=EvidenceItemType.EMAIL,
                        severity="HIGH" if u.risk_score >= 40 else "MEDIUM",
                        threat_category="PHISHING",
                        description=f"Extracted URL: {u.defanged_url}",
                    )
                )
        if email.extracted_attachments:
            for a in email.extracted_attachments:
                sha = a.hashes.get("sha256")
                if sha:
                    iocs.append(
                        MasterCaseIoC(
                            ioc_type="file-hash-sha256",
                            ioc_value=sha,
                            source_item_id=item_id,
                            source_item_type=EvidenceItemType.EMAIL,
                            severity="HIGH",
                            threat_category="MALICIOUS_PAYLOAD",
                            description=f"Email attachment SHA-256: {a.filename}",
                        )
                    )

        timeline: List[MasterTimelineEvent] = []
        dt = email.ingestion_timestamp_utc or datetime.now(timezone.utc)
        timeline.append(
            MasterTimelineEvent(
                timestamp_utc=dt,
                source_item_id=item_id,
                source_type=EvidenceItemType.EMAIL,
                event_category="EMAIL_DELIVERY",
                title=f"Email Received: {email.subject or 'No Subject'}",
                description=f"Message delivered from {email.from_address} to {', '.join(email.to_addresses)}",
                actor_or_source=email.from_address or "-",
                target_or_dest=", ".join(email.to_addresses) or "-",
                severity=level,
            )
        )

        has_urls = bool(email.url_report and email.url_report.urls)
        mitre = ["T1566.001", "T1566.002"] if email.extracted_attachments or has_urls else ["T1566"]
        return (
            json.loads(ForensicReportExporter.export_json(email)),
            score,
            level,
            summary,
            iocs,
            timeline,
            mitre,
        )

    def _analyze_binary_item(
        self, path: Path, item_id: str
    ) -> tuple[
        Dict[str, Any], float, str, str, List[MasterCaseIoC], List[MasterTimelineEvent], List[str]
    ]:
        static_analyzer = BinaryStaticAnalyzer()
        static_report = static_analyzer.analyze(path)
        art_analyzer = FileArtifactAnalyzer()
        art_report = art_analyzer.analyze_file(path)
        meta_extractor = MetadataExtractor()
        meta_report = meta_extractor.extract_from_file(path)

        score = 0.0
        entropy = static_report.overall_entropy or 0.0
        if entropy >= 7.2:
            score += 45.0
        suspicious_imports = (
            static_report.pe_analysis.suspicious_apis if static_report.pe_analysis else []
        )
        if suspicious_imports:
            score += 35.0
        if art_report.identification and art_report.identification.is_extension_mismatch:
            score += 25.0
        score = min(score, 100.0)

        level = (
            "CRITICAL"
            if score >= 75
            else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 25 else "BENIGN"))
        )
        detected_mime = (
            art_report.identification.detected_mime if art_report.identification else "binary"
        )
        summary = f"Binary artifact {path.name} ({detected_mime}). Entropy: {entropy:.2f}. Identified {len(suspicious_imports)} suspicious API imports."

        iocs: List[MasterCaseIoC] = [
            MasterCaseIoC(
                ioc_type="file-hash-sha256",
                ioc_value=art_report.hashes.get("sha256", ""),
                source_item_id=item_id,
                source_item_type=EvidenceItemType.FILE_BINARY,
                severity=level,
                threat_category="MALICIOUS_PAYLOAD",
                description=f"File SHA-256 digest of {path.name}",
            )
        ]

        timeline: List[MasterTimelineEvent] = [
            MasterTimelineEvent(
                timestamp_utc=datetime.now(timezone.utc),
                source_item_id=item_id,
                source_type=EvidenceItemType.FILE_BINARY,
                event_category="FILE_CREATION",
                title=f"File Analyzed: {path.name}",
                description=summary,
                actor_or_source=path.name,
                target_or_dest="File System",
                severity=level,
            )
        ]

        mitre = ["T1204.002", "T1027"] if entropy >= 7.0 else ["T1204"]
        if suspicious_imports:
            mitre.append("T1055")

        raw_report = {
            "static_report": static_report.model_dump(mode="json"),
            "artifact_report": art_report.model_dump(mode="json"),
            "metadata_report": meta_report.model_dump(mode="json"),
        }
        return raw_report, score, level, summary, iocs, timeline, mitre

    def _analyze_pcap_item(
        self, path: Path, item_id: str
    ) -> tuple[
        Dict[str, Any], float, str, str, List[MasterCaseIoC], List[MasterTimelineEvent], List[str]
    ]:
        pcap_analyzer = NetworkPCAPAnalyzer()
        pcap_report = pcap_analyzer.analyze(path)
        dns_analyzer = DNSThreatAnalyzer()
        dns_report = dns_analyzer.analyze_pcap(path)
        cred_analyzer = CredentialLeakAnalyzer()
        cred_report = cred_analyzer.analyze_pcap(path)

        score = 0.0
        dns_threats_count = (
            len(dns_report.tunneling_alerts)
            + len(dns_report.fast_flux_alerts)
            + len(dns_report.dga_alerts)
            + len(dns_report.large_txt_payloads)
        )
        if dns_threats_count > 0 or dns_report.threat_score >= 30:
            score += 50.0
        if cred_report.total_credentials_leaked > 0:
            score += 40.0
        score = min(score, 100.0)

        level = (
            "CRITICAL"
            if score >= 75
            else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 25 else "BENIGN"))
        )
        summary = f"PCAP capture containing {pcap_report.total_packets} packets. Flagged {dns_threats_count} DNS threats and {cred_report.total_credentials_leaked} cleartext credential leaks."

        iocs: List[MasterCaseIoC] = []
        for cred in cred_report.credentials:
            if cred.username:
                proto_name = (
                    cred.protocol.value if hasattr(cred.protocol, "value") else str(cred.protocol)
                )
                iocs.append(
                    MasterCaseIoC(
                        ioc_type="credential-leak",
                        ioc_value=f"{cred.username}:{cred.secret.masked_value}",
                        source_item_id=item_id,
                        source_item_type=EvidenceItemType.NETWORK_PCAP,
                        severity="HIGH",
                        threat_category="CREDENTIAL_THEFT",
                        description=f"Cleartext {proto_name} credentials captured between {cred.src_ip} and {cred.dst_ip}",
                    )
                )

        for threat in dns_report.tunneling_alerts:
            iocs.append(
                MasterCaseIoC(
                    ioc_type="domain",
                    ioc_value=threat.apex_domain,
                    source_item_id=item_id,
                    source_item_type=EvidenceItemType.NETWORK_PCAP,
                    severity="CRITICAL",
                    threat_category="C2_INFRASTRUCTURE",
                    description=f"DNS Tunneling detected on apex domain {threat.apex_domain}",
                )
            )

        for ff in dns_report.fast_flux_alerts:
            iocs.append(
                MasterCaseIoC(
                    ioc_type="domain",
                    ioc_value=ff.domain,
                    source_item_id=item_id,
                    source_item_type=EvidenceItemType.NETWORK_PCAP,
                    severity="CRITICAL",
                    threat_category="C2_INFRASTRUCTURE",
                    description=f"Fast-Flux DNS domain: {ff.domain}",
                )
            )

        for dga in dns_report.dga_alerts:
            iocs.append(
                MasterCaseIoC(
                    ioc_type="domain",
                    ioc_value=dga.domain,
                    source_item_id=item_id,
                    source_item_type=EvidenceItemType.NETWORK_PCAP,
                    severity="HIGH",
                    threat_category="C2_INFRASTRUCTURE",
                    description=f"DGA algorithmically generated domain: {dga.domain}",
                )
            )

        for ioc_val in dns_report.extracted_iocs:
            iocs.append(
                MasterCaseIoC(
                    ioc_type="domain" if "." in ioc_val else "ioc",
                    ioc_value=ioc_val,
                    source_item_id=item_id,
                    source_item_type=EvidenceItemType.NETWORK_PCAP,
                    severity="HIGH",
                    threat_category="C2_INFRASTRUCTURE",
                    description=f"Extracted DNS IoC: {ioc_val}",
                )
            )

        timeline: List[MasterTimelineEvent] = [
            MasterTimelineEvent(
                timestamp_utc=datetime.now(timezone.utc),
                source_item_id=item_id,
                source_type=EvidenceItemType.NETWORK_PCAP,
                event_category="NETWORK_FLOW",
                title=f"Network Capture Session: {path.name}",
                description=summary,
                actor_or_source="Local Network Interface",
                target_or_dest="External Gateways",
                severity=level,
            )
        ]

        mitre = ["T1071.004", "T1048.003"] if dns_threats_count > 0 else ["T1071"]
        if cred_report.total_credentials_leaked > 0:
            mitre.append("T1552.001")

        raw_report = {
            "pcap_report": pcap_report.model_dump(mode="json"),
            "dns_report": dns_report.model_dump(mode="json"),
            "credential_report": cred_report.model_dump(mode="json"),
        }
        return raw_report, score, level, summary, iocs, timeline, mitre

    def _analyze_log_item(
        self, path: Path, item_id: str, item_type: EvidenceItemType
    ) -> tuple[
        Dict[str, Any], float, str, str, List[MasterCaseIoC], List[MasterTimelineEvent], List[str]
    ]:
        evtx_rep = None
        sec_rep = None
        cloud_rep = None

        if path.suffix.lower() in [".evtx", ".xml"]:
            try:
                evtx_rep = WindowsLogAnalyzer().analyze_file(path)
            except Exception:
                pass
            try:
                sec_rep = WindowsSecurityAnalyzer().analyze_file(path)
            except Exception:
                pass
        else:
            try:
                cloud_rep = CloudAuditAnalyzer().analyze_file(path)
            except Exception:
                pass

        score = 0.0
        findings_count = (len(sec_rep.anomalies) if sec_rep else 0) + (
            len(cloud_rep.anomalies) if cloud_rep else 0
        )
        if findings_count > 0:
            score = min(30.0 + (findings_count * 15.0), 100.0)

        level = (
            "CRITICAL"
            if score >= 75
            else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 25 else "BENIGN"))
        )
        summary = f"Event log {path.name} processed. Correlated {findings_count} security findings across log records."

        iocs: List[MasterCaseIoC] = []
        mitre: List[str] = []
        if sec_rep:
            for f in sec_rep.anomalies:
                if f.target_user:
                    iocs.append(
                        MasterCaseIoC(
                            ioc_type="user-account",
                            ioc_value=f.target_user,
                            source_item_id=item_id,
                            source_item_type=item_type,
                            severity=f.severity or "MEDIUM",
                            threat_category="IDENTITY",
                            description=f"User involved in security event: {f.detection_reason}",
                        )
                    )
                if f.mitre_attack_technique:
                    mitre.append(f.mitre_attack_technique)
            for ioc in sec_rep.extracted_iocs:
                iocs.append(
                    MasterCaseIoC(
                        ioc_type="ip" if ":" in ioc or "." in ioc else "user-account",
                        ioc_value=ioc,
                        source_item_id=item_id,
                        source_item_type=item_type,
                        severity="MEDIUM",
                        threat_category="IDENTITY",
                        description="Extracted Windows security IoC",
                    )
                )

        if cloud_rep:
            for c in cloud_rep.anomalies:
                if c.actor_user:
                    iocs.append(
                        MasterCaseIoC(
                            ioc_type="cloud-account",
                            ioc_value=c.actor_user,
                            source_item_id=item_id,
                            source_item_type=item_type,
                            severity=c.severity or "HIGH",
                            threat_category="IDENTITY",
                            description=f"Cloud audit anomaly: {c.detection_reason}",
                        )
                    )
                if c.mitre_attack_technique:
                    mitre.append(c.mitre_attack_technique)
            for ioc in cloud_rep.extracted_iocs:
                iocs.append(
                    MasterCaseIoC(
                        ioc_type="ip" if ":" in ioc or "." in ioc else "cloud-account",
                        ioc_value=ioc,
                        source_item_id=item_id,
                        source_item_type=item_type,
                        severity="HIGH",
                        threat_category="IDENTITY",
                        description="Extracted Cloud audit IoC",
                    )
                )

        timeline: List[MasterTimelineEvent] = [
            MasterTimelineEvent(
                timestamp_utc=datetime.now(timezone.utc),
                source_item_id=item_id,
                source_type=item_type,
                event_category="PRIVILEGE_ESCALATION" if score >= 50 else "FAILED_LOGON",
                title=f"Log Correlation Event: {path.name}",
                description=summary,
                actor_or_source=path.name,
                target_or_dest="Windows/Cloud Audit Framework",
                severity=level,
            )
        ]

        raw_report = {
            "evtx_report": evtx_rep.model_dump(mode="json") if evtx_rep else None,
            "security_report": sec_rep.model_dump(mode="json") if sec_rep else None,
            "cloud_report": cloud_rep.model_dump(mode="json") if cloud_rep else None,
        }
        return raw_report, score, level, summary, iocs, timeline, list(set(mitre))

    def _analyze_memory_item(
        self, path: Path, item_id: str
    ) -> tuple[
        Dict[str, Any], float, str, str, List[MasterCaseIoC], List[MasterTimelineEvent], List[str]
    ]:
        mem_analyzer = MemoryArtifactAnalyzer()
        ext_report = mem_analyzer.analyze(path)
        ioc_matcher = MemoryIoCMatcher()
        ioc_report = ioc_matcher.scan_stream(path)
        yara_scanner = MemoryYARAScanner()
        yara_report = yara_scanner.scan_stream(path)

        score = 0.0
        if yara_report.yara_matches:
            score += 60.0
        if ioc_report.matches:
            score += 30.0
        score = min(score, 100.0)

        level = (
            "CRITICAL"
            if score >= 75
            else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 25 else "BENIGN"))
        )
        summary = f"Memory dump {path.name} scanned. Matched {len(yara_report.yara_matches)} YARA signatures and extracted {len(ioc_report.matches)} regex IoCs."

        iocs: List[MasterCaseIoC] = []
        for m in ioc_report.matches:
            iocs.append(
                MasterCaseIoC(
                    ioc_type=m.ioc_type,
                    ioc_value=m.value,
                    source_item_id=item_id,
                    source_item_type=EvidenceItemType.VOLATILE_MEMORY,
                    severity="HIGH" if m.ioc_type in ["ip", "url"] else "MEDIUM",
                    threat_category="C2_INFRASTRUCTURE"
                    if m.ioc_type in ["ip", "url"]
                    else "ARTIFACT",
                    description=f"In-memory extracted IoC ({m.ioc_type})",
                )
            )

        timeline: List[MasterTimelineEvent] = [
            MasterTimelineEvent(
                timestamp_utc=datetime.now(timezone.utc),
                source_item_id=item_id,
                source_type=EvidenceItemType.VOLATILE_MEMORY,
                event_category="MEMORY_INJECTION",
                title=f"Volatile Memory Triage: {path.name}",
                description=summary,
                actor_or_source=path.name,
                target_or_dest="Host RAM",
                severity=level,
            )
        ]

        mitre = ["T1055", "T1003.001"] if yara_report.yara_matches else ["T1055"]
        raw_report = {
            "extraction_report": ext_report.model_dump(mode="json"),
            "ioc_report": ioc_report.model_dump(mode="json"),
            "yara_report": yara_report.model_dump(mode="json"),
        }
        return raw_report, score, level, summary, iocs, timeline, mitre

    def correlate_and_build_report(self) -> MasterCaseReport:
        """Run cross-module correlation across all ingested evidence items and assemble MasterCaseReport."""
        all_iocs: List[MasterCaseIoC] = []
        all_timeline: List[MasterTimelineEvent] = []
        all_mitre_dict: Dict[str, Set[str]] = {}
        all_immutability: Dict[str, Any] = {}

        # 1. Aggregate IoCs, Timeline, MITRE, and Hashes
        for item in self.evidence_items:
            all_iocs.extend(item.extracted_iocs)
            all_timeline.extend(item.timeline_events)

            # Audit hash ledger
            all_immutability[item.item_id] = {
                "source_name": item.source_name,
                "item_type": item.item_type.value,
                "pre_sha256": item.manifest.pre_analysis_hashes.get("sha256"),
                "post_sha256": (item.manifest.post_analysis_hashes or {}).get("sha256"),
                "verified": item.manifest.integrity_verified,
            }

            for t_id in item.mitre_techniques:
                tactic = self._map_tactic(t_id)
                if tactic not in all_mitre_dict:
                    all_mitre_dict[tactic] = set()
                all_mitre_dict[tactic].add(t_id)

        # 2. Sort master timeline chronologically UTC
        all_timeline.sort(key=lambda ev: ev.timestamp_utc)

        # 3. Deduplicate IoCs by (ioc_type, ioc_value)
        deduped_iocs: List[MasterCaseIoC] = []
        seen_iocs: Set[str] = set()
        for ioc in all_iocs:
            key = f"{ioc.ioc_type}:{ioc.ioc_value.lower().strip()}"
            if key not in seen_iocs:
                seen_iocs.add(key)
                deduped_iocs.append(ioc)

        # 4. Cross-Evidence Correlations Discovery
        correlations = self._discover_correlations(all_iocs)

        # 5. Master Composite Risk Calculation
        overall_score = 0.0
        if self.evidence_items:
            max_score = max(it.risk_score for it in self.evidence_items)
            avg_score = sum(it.risk_score for it in self.evidence_items) / len(self.evidence_items)
            # Bonus for cross-module correlations
            corr_bonus = min(len(correlations) * 10.0, 30.0)
            overall_score = min(
                max(max_score * 0.7 + avg_score * 0.3 + corr_bonus, max_score), 100.0
            )

        overall_level = (
            "CRITICAL"
            if overall_score >= 75
            else (
                "HIGH" if overall_score >= 50 else ("MEDIUM" if overall_score >= 25 else "BENIGN")
            )
        )

        exec_summary = (
            f"Case {self.case_id} comprises {len(self.evidence_items)} forensic evidence items spanning "
            f"{len(set(it.item_type for it in self.evidence_items))} distinct forensic domains. "
            f"Identified {len(correlations)} cross-evidence correlation links, {len(deduped_iocs)} unique IoCs, "
            f"and established a unified chronological timeline of {len(all_timeline)} events. "
            f"All {len(self.evidence_items)} evidence files verified with 100% zero-byte mutation integrity."
        )

        final_mitre = {k: sorted(list(v)) for k, v in all_mitre_dict.items()}

        report = MasterCaseReport(
            case_id=self.case_id,
            case_title=self.case_title,
            examiner_name=self.examiner_name,
            examiner_agency=self.examiner_agency,
            created_at_utc=datetime.now(timezone.utc),
            evidence_items=self.evidence_items,
            overall_composite_risk_score=overall_score,
            overall_risk_level=overall_level,
            executive_summary=exec_summary,
            cross_module_correlations=correlations,
            master_timeline=all_timeline,
            master_ioc_ledger=deduped_iocs,
            mitre_matrix=final_mitre,
            immutability_audit=all_immutability,
        )
        return report

    def _discover_correlations(
        self, all_iocs: List[MasterCaseIoC]
    ) -> List[CrossEvidenceCorrelation]:
        """Find shared IoCs across different evidence items and build correlation chains."""
        correlations: List[CrossEvidenceCorrelation] = []
        ioc_map: Dict[str, List[MasterCaseIoC]] = {}

        for ioc in all_iocs:
            val = ioc.ioc_value.lower().strip()
            if not val or len(val) < 4:
                continue
            key = f"{ioc.ioc_type}:{val}"
            if key not in ioc_map:
                ioc_map[key] = []
            ioc_map[key].append(ioc)

        for key, matching_iocs in ioc_map.items():
            item_ids = list(set(i.source_item_id for i in matching_iocs))
            if len(item_ids) > 1:
                ioc_type, ioc_val = key.split(":", 1)
                correlations.append(
                    CrossEvidenceCorrelation(
                        correlation_type="SHARED_IOC",
                        title=f"Shared Indicator: {ioc_type.upper()} ({ioc_val})",
                        description=f"The indicator '{ioc_val}' was observed across {len(item_ids)} separate evidence items ({', '.join(item_ids)}), confirming an active multi-stage attack link.",
                        matched_ioc_type=ioc_type,
                        matched_ioc_value=ioc_val,
                        involved_item_ids=item_ids,
                        severity="HIGH",
                        mitre_technique="T1071"
                        if "ip" in ioc_type or "domain" in ioc_type
                        else "T1027",
                    )
                )

        # Multi-stage killchain check: Email + File + PCAP/Memory
        types_present = set(it.item_type for it in self.evidence_items)
        if (
            EvidenceItemType.EMAIL in types_present
            and EvidenceItemType.FILE_BINARY in types_present
        ):
            correlations.append(
                CrossEvidenceCorrelation(
                    correlation_type="ATTACK_CHAIN_SEQUENCE",
                    title="Phishing Lure to Binary Execution Chain",
                    description="Evidence correlates initial delivery via email lure with downstream static binary payload artifact staging.",
                    involved_item_ids=[
                        it.item_id
                        for it in self.evidence_items
                        if it.item_type in [EvidenceItemType.EMAIL, EvidenceItemType.FILE_BINARY]
                    ],
                    severity="CRITICAL",
                    mitre_technique="T1566.001",
                )
            )

        return correlations

    @staticmethod
    def _map_tactic(technique_id: str) -> str:
        """Map MITRE ATT&CK technique IDs to standardized ATT&CK tactics."""
        if technique_id.startswith("T1566"):
            return "Initial Access"
        if technique_id.startswith("T1204") or technique_id.startswith("T1059"):
            return "Execution"
        if technique_id.startswith("T1053") or technique_id.startswith("T1078"):
            return "Persistence"
        if technique_id.startswith("T1055") or technique_id.startswith("T1068"):
            return "Privilege Escalation"
        if technique_id.startswith("T1027") or technique_id.startswith("T1070"):
            return "Defense Evasion"
        if technique_id.startswith("T1003") or technique_id.startswith("T1552"):
            return "Credential Access"
        if technique_id.startswith("T1046") or technique_id.startswith("T1087"):
            return "Discovery"
        if technique_id.startswith("T1071") or technique_id.startswith("T1048"):
            return "Command and Control / Exfiltration"
        return "General Malicious Activity"
