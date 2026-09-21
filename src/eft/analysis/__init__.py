"""Analysis subsystem for Email Forensic Tool."""

from eft.analysis.attachment_scanner import AttachmentThreatScanner
from eft.analysis.auth_verifier import AuthenticationVerifier
from eft.analysis.bec_detector import BECDetector
from eft.analysis.binary_static_analyzer import BinaryStaticAnalyzer
from eft.analysis.cloud_audit_analyzer import CloudAuditAnalyzer
from eft.analysis.credential_leak_analyzer import CredentialLeakAnalyzer
from eft.analysis.dns_threat_analyzer import DNSThreatAnalyzer
from eft.analysis.domain_osint import DomainOSINTAnalyzer
from eft.analysis.evtx_analyzer import WindowsLogAnalyzer
from eft.analysis.file_analyzer import FileArtifactAnalyzer
from eft.analysis.logon_persistence_analyzer import WindowsSecurityAnalyzer
from eft.analysis.memory_analyzer import MemoryArtifactAnalyzer
from eft.analysis.metadata_extractor import MetadataExtractor
from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.analysis.obfuscation_detector import ContentObfuscationDetector
from eft.analysis.ole_analyzer import OLEMacroAnalyzer
from eft.analysis.pcap_analyzer import NetworkPCAPAnalyzer
from eft.analysis.pe_analyzer import PEBinaryAnalyzer
from eft.analysis.relay_analyzer import RelayAnalyzer
from eft.analysis.threat_scorer import ThreatScorer
from eft.analysis.url_analyzer import URLAnalyzer

__all__ = [
    "RelayAnalyzer",
    "NetworkIntelligenceService",
    "AuthenticationVerifier",
    "URLAnalyzer",
    "BECDetector",
    "ContentObfuscationDetector",
    "AttachmentThreatScanner",
    "ThreatScorer",
    "DomainOSINTAnalyzer",
    "FileArtifactAnalyzer",
    "MetadataExtractor",
    "PEBinaryAnalyzer",
    "OLEMacroAnalyzer",
    "BinaryStaticAnalyzer",
    "NetworkPCAPAnalyzer",
    "DNSThreatAnalyzer",
    "CredentialLeakAnalyzer",
    "WindowsLogAnalyzer",
    "WindowsSecurityAnalyzer",
    "CloudAuditAnalyzer",
    "MemoryArtifactAnalyzer",
]
