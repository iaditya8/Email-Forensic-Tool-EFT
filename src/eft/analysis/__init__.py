"""Analysis subsystem for Email Forensic Tool."""

from eft.analysis.attachment_scanner import AttachmentThreatScanner
from eft.analysis.auth_verifier import AuthenticationVerifier
from eft.analysis.bec_detector import BECDetector
from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.analysis.obfuscation_detector import ContentObfuscationDetector
from eft.analysis.relay_analyzer import RelayAnalyzer
from eft.analysis.url_analyzer import URLAnalyzer

__all__ = [
    "RelayAnalyzer",
    "NetworkIntelligenceService",
    "AuthenticationVerifier",
    "URLAnalyzer",
    "BECDetector",
    "ContentObfuscationDetector",
    "AttachmentThreatScanner",
]
