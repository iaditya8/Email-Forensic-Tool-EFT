"""Cleartext Credential & High-Risk Protocol Forensics Analyzer."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union
from urllib.parse import unquote_plus

from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.analysis.pcap_analyzer import NetworkPCAPAnalyzer
from eft.models.credential_leak import (
    CleartextProtocol,
    CredentialLeakageReport,
    DefangedSecret,
    ExtractedCredentialRecord,
    HighRiskProtocolExposure,
    SecretType,
    UnencryptedFileTransferRecord,
)
from eft.models.pcap import AppProtocol, PacketRecord, PCAPAnalysisReport


class CredentialLeakAnalyzer:
    """Forensic inspector for extracting and defanging cleartext credentials, API tokens, and insecure protocols."""

    # High-Risk Insecure Protocols Matrix: Port -> (Protocol Name, Risk Description, Recommended Replacement)
    HIGH_RISK_PORTS: Dict[int, Tuple[str, str, str]] = {
        21: (
            "FTP (File Transfer Protocol)",
            "Transmits authentication credentials and files unencrypted in cleartext across the network.",
            "Migrate to SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS/SSL).",
        ),
        23: (
            "Telnet (Remote Terminal)",
            "Unencrypted remote terminal protocol transmitting keystrokes, usernames, and passwords in cleartext.",
            "Migrate immediately to SSH (Secure Shell) version 2.",
        ),
        80: (
            "HTTP (Unencrypted Web)",
            "Transmits web requests, session cookies, form submissions, and authentication headers in cleartext.",
            "Enforce HTTPS with TLS 1.3 and HSTS (HTTP Strict Transport Security).",
        ),
        110: (
            "POP3 (Post Office Protocol v3)",
            "Transmits email credentials (USER/PASS) and mailbox contents in cleartext.",
            "Enforce POP3S (POP3 over TLS on port 995) or STARTTLS.",
        ),
        143: (
            "IMAP (Internet Message Access Protocol)",
            "Transmits mailbox authentication credentials and messages without encryption.",
            "Enforce IMAPS (IMAP over TLS on port 993) or STARTTLS.",
        ),
        161: (
            "SNMPv1 / SNMPv2c (Simple Network Management)",
            "Transmits network monitoring community strings (passwords) and device MIB configurations in cleartext.",
            "Upgrade to SNMPv3 with USM (User-based Security Model) authentication and AES privacy encryption.",
        ),
        389: (
            "LDAP (Lightweight Directory Access Protocol)",
            "Performs directory queries and simple binds (passwords) without transport encryption.",
            "Enforce LDAPS (LDAP over TLS on port 636) or StartTLS.",
        ),
    }

    # Regex signatures for API keys and tokens
    API_KEY_PATTERNS: List[Tuple[SecretType, str, re.Pattern[str]]] = [
        (
            SecretType.API_KEY,
            "AWS Access Key ID",
            re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        ),
        (
            SecretType.API_KEY,
            "GitHub Personal Access Token",
            re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"),
        ),
        (
            SecretType.API_KEY,
            "OpenAI API Key",
            re.compile(r"\b(sk-[a-zA-Z0-9_\-]{20,})\b"),
        ),
        (
            SecretType.API_KEY,
            "Slack Token",
            re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
        ),
        (
            SecretType.API_KEY,
            "Generic Bearer Token",
            re.compile(r"Bearer\s+([a-zA-Z0-9_\-\.]{24,})", re.IGNORECASE),
        ),
        (
            SecretType.PRIVATE_KEY,
            "RSA / OpenSSH Private Key Header",
            re.compile(r"(-----BEGIN [A-Z ]+PRIVATE KEY-----)"),
        ),
    ]

    # Sensitive file extensions for unencrypted file transfers
    SENSITIVE_FILE_EXTENSIONS: Set[str] = {
        ".key",
        ".pem",
        ".crt",
        ".cer",
        ".pfx",
        ".p12",
        ".kdbx",
        ".env",
        ".sql",
        ".bak",
        ".conf",
        ".config",
        ".ini",
        ".db",
        ".sqlite",
        ".sam",
        ".dit",
        ".shadow",
        ".passwd",
    }

    def __init__(self, intel_service: Optional[NetworkIntelligenceService] = None) -> None:
        """Initialize the Credential Leak Analyzer."""
        self.intel_service = intel_service or NetworkIntelligenceService()

    # -------------------------------------------------------------------------
    # Secret Defanging & Masking Utility
    # -------------------------------------------------------------------------

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Compute Shannon entropy for secret complexity measurement."""
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0.0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @classmethod
    def defang_secret(cls, raw_secret: str, secret_type: SecretType) -> DefangedSecret:
        """Safely mask and defang a sensitive credential while preserving evidence SHA-256 fingerprint."""
        raw_clean = raw_secret.strip()
        length = len(raw_clean)
        entropy = cls.calculate_entropy(raw_clean)
        sha256 = hashlib.sha256(raw_clean.encode("utf-8", errors="ignore")).hexdigest()

        if secret_type == SecretType.PRIVATE_KEY:
            masked = f"{raw_clean[:28]}... [DEFANGED PRIVATE KEY]"
        elif length <= 3:
            masked = "***"
        elif length <= 6:
            masked = f"{raw_clean[0]}****{raw_clean[-1]}"
        elif length <= 12:
            masked = f"{raw_clean[:2]}****{raw_clean[-2:]}"
        else:
            # For longer API keys or tokens
            if raw_clean.startswith("AKIA"):
                masked = f"AKIA****{raw_clean[-4:]}"
            elif raw_clean.startswith("ghp_"):
                masked = f"ghp_****{raw_clean[-4:]}"
            elif raw_clean.startswith("sk-"):
                masked = f"sk-****{raw_clean[-4:]}"
            else:
                masked = f"{raw_clean[:3]}****{raw_clean[-3:]}"

        return DefangedSecret(
            secret_type=secret_type,
            masked_value=masked,
            length=length,
            entropy=entropy,
            sha256_hash=sha256,
        )

    # -------------------------------------------------------------------------
    # Protocol Dissectors
    # -------------------------------------------------------------------------

    def _dissect_http_credentials(
        self, pkt: PacketRecord, raw_text: str
    ) -> List[ExtractedCredentialRecord]:
        """Dissect HTTP headers and POST bodies for Basic Auth, Bearer tokens, and form logins."""
        creds: List[ExtractedCredentialRecord] = []
        ts = pkt.timestamp
        src_ip = pkt.src_ip or "0.0.0.0"
        src_port = pkt.src_port or 0
        dst_ip = pkt.dst_ip or "0.0.0.0"
        dst_port = pkt.dst_port or 80

        endpoint: Optional[str] = None
        if pkt.http_request:
            host = pkt.http_request.host or dst_ip
            uri = pkt.http_request.uri
            endpoint = f"http://{host}{uri}"

        # 1. Check HTTP Basic Authentication header: Authorization: Basic <base64>
        basic_match = re.search(
            r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", raw_text, re.IGNORECASE
        )
        if basic_match:
            b64_str = basic_match.group(1)
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="replace")
                if ":" in decoded:
                    username, password = decoded.split(":", 1)
                    defanged = self.defang_secret(password, SecretType.BASIC_AUTH)
                    creds.append(
                        ExtractedCredentialRecord(
                            timestamp=ts,
                            protocol=CleartextProtocol.HTTP_BASIC_AUTH,
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            username=username,
                            secret=defanged,
                            endpoint_url=endpoint,
                            context_snippet=f"Authorization: Basic [User: {username}]",
                            severity="CRITICAL",
                        )
                    )
            except Exception:
                pass

        # 2. Check HTTP Bearer Authentication header: Authorization: Bearer <token>
        bearer_match = re.search(
            r"Authorization:\s*Bearer\s+([A-Za-z0-9_\-\.]{16,})", raw_text, re.IGNORECASE
        )
        if bearer_match:
            token = bearer_match.group(1)
            defanged = self.defang_secret(token, SecretType.BEARER_TOKEN)
            creds.append(
                ExtractedCredentialRecord(
                    timestamp=ts,
                    protocol=CleartextProtocol.HTTP_BEARER_AUTH,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    username=None,
                    secret=defanged,
                    endpoint_url=endpoint,
                    context_snippet="Authorization: Bearer <token>",
                    severity="HIGH",
                )
            )

        # 3. Check Cookies for session / auth tokens
        cookie_matches = re.findall(
            r"(?:Cookie|Set-Cookie):\s*.*?((?:session_id|sessionid|auth_token|token|jwt|PHPSESSID|JSESSIONID)=([^;\r\n]+))",
            raw_text,
            re.IGNORECASE,
        )
        for full_cookie, cookie_val in cookie_matches:
            if len(cookie_val) >= 12:
                defanged = self.defang_secret(cookie_val, SecretType.SESSION_COOKIE)
                creds.append(
                    ExtractedCredentialRecord(
                        timestamp=ts,
                        protocol=CleartextProtocol.HTTP_COOKIE_SESSION,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        username=None,
                        secret=defanged,
                        endpoint_url=endpoint,
                        context_snippet=f"Cookie: {full_cookie.split('=')[0]}=...",
                        severity="MEDIUM",
                    )
                )

        # 4. Check HTTP POST Form Body Login: username=...&password=...
        if pkt.http_request and pkt.http_request.method == "POST":
            body = pkt.http_request.body_snippet or ""
            # Form-urlencoded patterns
            form_match = re.search(
                r"(?:^|&)(?:username|user|email|login|account|uname)=([^&]+)&(?:password|pass|passwd|pwd|secret)=([^&]+)",
                body,
                re.IGNORECASE,
            )
            if not form_match:
                # Reversed order (pass first, then user)
                form_match = re.search(
                    r"(?:^|&)(?:password|pass|passwd|pwd|secret)=([^&]+)&(?:username|user|email|login|account|uname)=([^&]+)",
                    body,
                    re.IGNORECASE,
                )
                if form_match:
                    raw_pass = unquote_plus(form_match.group(1))
                    raw_user = unquote_plus(form_match.group(2))
                else:
                    raw_user = None
                    raw_pass = None
            else:
                raw_user = unquote_plus(form_match.group(1))
                raw_pass = unquote_plus(form_match.group(2))

            if raw_pass:
                defanged = self.defang_secret(raw_pass, SecretType.PASSWORD)
                creds.append(
                    ExtractedCredentialRecord(
                        timestamp=ts,
                        protocol=CleartextProtocol.HTTP_POST_BODY,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        username=raw_user,
                        secret=defanged,
                        endpoint_url=endpoint,
                        context_snippet=f"HTTP POST Form [User: {raw_user}]",
                        severity="CRITICAL",
                    )
                )

            # JSON Login Body patterns
            if "{" in body and "}" in body:
                try:
                    json_data = json.loads(body)
                    if isinstance(json_data, dict):
                        user_key = next(
                            (
                                k
                                for k in json_data
                                if k.lower() in ("username", "user", "email", "login", "account")
                            ),
                            None,
                        )
                        pass_key = next(
                            (
                                k
                                for k in json_data
                                if k.lower() in ("password", "pass", "passwd", "pwd", "secret")
                            ),
                            None,
                        )
                        if pass_key and json_data[pass_key]:
                            raw_pass = str(json_data[pass_key])
                            raw_user = str(json_data[user_key]) if user_key else None
                            defanged = self.defang_secret(raw_pass, SecretType.PASSWORD)
                            creds.append(
                                ExtractedCredentialRecord(
                                    timestamp=ts,
                                    protocol=CleartextProtocol.HTTP_POST_BODY,
                                    src_ip=src_ip,
                                    src_port=src_port,
                                    dst_ip=dst_ip,
                                    dst_port=dst_port,
                                    username=raw_user,
                                    secret=defanged,
                                    endpoint_url=endpoint,
                                    context_snippet=f"HTTP POST JSON [User: {raw_user}]",
                                    severity="CRITICAL",
                                )
                            )
                except Exception:
                    pass

        return creds

    def _dissect_smtp_auth(
        self, flow_lines: List[Tuple[datetime, str, str, int, str, int]]
    ) -> List[ExtractedCredentialRecord]:
        """Dissect SMTP AUTH LOGIN and AUTH PLAIN authentication dialogs."""
        creds: List[ExtractedCredentialRecord] = []
        waiting_for_pass_user: Optional[str] = None
        user_ts: Optional[datetime] = None
        src_ip = ""
        dst_ip = ""
        src_port = 0
        dst_port = 25

        for ts, line, s_ip, s_port, d_ip, d_port in flow_lines:
            clean = line.strip()
            # AUTH PLAIN <base64>
            if clean.upper().startswith("AUTH PLAIN"):
                parts = clean.split()
                if len(parts) >= 3:
                    b64_val = parts[2]
                    try:
                        decoded = base64.b64decode(b64_val).decode("latin-1", errors="replace")
                        tokens = decoded.split("\x00")
                        # Format is \0username\0password or authzid\0authcid\0password
                        non_empty = [t for t in tokens if t]
                        if len(non_empty) >= 2:
                            u, p = non_empty[0], non_empty[1]
                            defanged = self.defang_secret(p, SecretType.PASSWORD)
                            creds.append(
                                ExtractedCredentialRecord(
                                    timestamp=ts,
                                    protocol=CleartextProtocol.SMTP,
                                    src_ip=s_ip,
                                    src_port=s_port,
                                    dst_ip=d_ip,
                                    dst_port=d_port,
                                    username=u,
                                    secret=defanged,
                                    context_snippet=f"SMTP AUTH PLAIN [User: {u}]",
                                    severity="CRITICAL",
                                )
                            )
                    except Exception:
                        pass

            # AUTH LOGIN sequence
            elif clean.upper() == "AUTH LOGIN":
                waiting_for_pass_user = None
                user_ts = ts
                src_ip, src_port, dst_ip, dst_port = s_ip, s_port, d_ip, d_port

            elif waiting_for_pass_user is None and user_ts and (ts - user_ts).total_seconds() < 30:
                # Might be base64 username
                try:
                    dec_user = base64.b64decode(clean).decode("utf-8", errors="ignore")
                    if dec_user and len(dec_user) >= 2 and "@" in dec_user or dec_user.isalnum():
                        waiting_for_pass_user = dec_user
                except Exception:
                    pass
            elif waiting_for_pass_user and user_ts and (ts - user_ts).total_seconds() < 30:
                # Might be base64 password
                try:
                    dec_pass = base64.b64decode(clean).decode("utf-8", errors="ignore")
                    if dec_pass:
                        defanged = self.defang_secret(dec_pass, SecretType.PASSWORD)
                        creds.append(
                            ExtractedCredentialRecord(
                                timestamp=ts,
                                protocol=CleartextProtocol.SMTP,
                                src_ip=src_ip or s_ip,
                                src_port=src_port or s_port,
                                dst_ip=dst_ip or d_ip,
                                dst_port=dst_port or d_port,
                                username=waiting_for_pass_user,
                                secret=defanged,
                                context_snippet=f"SMTP AUTH LOGIN [User: {waiting_for_pass_user}]",
                                severity="CRITICAL",
                            )
                        )
                        waiting_for_pass_user = None
                        user_ts = None
                except Exception:
                    pass

        return creds

    def _scan_api_keys_and_tokens(
        self, pkt: PacketRecord, raw_text: str
    ) -> List[ExtractedCredentialRecord]:
        """Scan raw ASCII payload text for known high-entropy API key patterns and private keys."""
        creds: List[ExtractedCredentialRecord] = []
        ts = pkt.timestamp
        src_ip = pkt.src_ip or "0.0.0.0"
        src_port = pkt.src_port or 0
        dst_ip = pkt.dst_ip or "0.0.0.0"
        dst_port = pkt.dst_port or 0

        for sec_type, label, pattern in self.API_KEY_PATTERNS:
            for match in pattern.finditer(raw_text):
                token_val = match.group(1)
                defanged = self.defang_secret(token_val, sec_type)
                creds.append(
                    ExtractedCredentialRecord(
                        timestamp=ts,
                        protocol=CleartextProtocol.OTHER,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        username=None,
                        secret=defanged,
                        context_snippet=f"Leaked {label}",
                        severity="CRITICAL",
                    )
                )

        return creds

    def _extract_unencrypted_file(
        self, pkt: PacketRecord, raw_text: str
    ) -> Optional[UnencryptedFileTransferRecord]:
        """Detect and extract cleartext file transfer over HTTP or FTP."""
        ts = pkt.timestamp
        src_ip = pkt.src_ip or "0.0.0.0"
        src_port = pkt.src_port or 0
        dst_ip = pkt.dst_ip or "0.0.0.0"
        dst_port = pkt.dst_port or 80

        filename: Optional[str] = None
        content_type: Optional[str] = None
        size_bytes = 0

        # Check HTTP Content-Disposition: attachment; filename="example.pdf"
        disp_match = re.search(
            r'Content-Disposition:\s*.*?filename=["\']?([^"\'\r\n;]+)', raw_text, re.IGNORECASE
        )
        if disp_match:
            filename = disp_match.group(1).strip()

        # Check HTTP Content-Type
        ct_match = re.search(r"Content-Type:\s*([^\r\n;]+)", raw_text, re.IGNORECASE)
        if ct_match:
            content_type = ct_match.group(1).strip()

        # Check HTTP Content-Length
        cl_match = re.search(r"Content-Length:\s*(\d+)", raw_text, re.IGNORECASE)
        if cl_match:
            size_bytes = int(cl_match.group(1))

        # If no filename from disposition, check URI path extension
        if not filename and pkt.http_request:
            path = pkt.http_request.uri.split("?")[0]
            ext = os.path.splitext(path)[1].lower()
            if ext in (
                ".pdf",
                ".docx",
                ".xlsx",
                ".pptx",
                ".zip",
                ".tar",
                ".gz",
                ".exe",
                ".dll",
                ".sh",
                ".ps1",
                ".py",
                ".key",
                ".pem",
                ".env",
                ".sql",
                ".bak",
            ):
                filename = os.path.basename(path)

        if filename:
            ext = os.path.splitext(filename)[1].lower()
            is_sensitive = ext in self.SENSITIVE_FILE_EXTENSIONS
            reason = (
                f"Unencrypted transmission of high-risk sensitive file type ({ext})"
                if is_sensitive
                else None
            )

            return UnencryptedFileTransferRecord(
                timestamp=ts,
                protocol="HTTP",
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                filename=filename,
                size_bytes=size_bytes,
                content_type=content_type,
                sha256_hash=None,
                is_sensitive_file=is_sensitive,
                warning_reason=reason,
            )

        return None

    # -------------------------------------------------------------------------
    # Master Analysis Engine
    # -------------------------------------------------------------------------

    def analyze_packets(
        self,
        packets: Sequence[PacketRecord],
        source_hashes: Optional[Dict[str, str]] = None,
        file_path: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> CredentialLeakageReport:
        """Scan dissected PacketRecord sequence for credentials, files, and high-risk protocol exposures."""
        extracted_creds: List[ExtractedCredentialRecord] = []
        unencrypted_files: List[UnencryptedFileTransferRecord] = []
        port_exposures_map: Dict[Tuple[int, str], Set[str]] = defaultdict(set)
        port_packet_counts: Counter[Tuple[int, str]] = Counter()

        # Group plain lines for interactive protocols (FTP, Telnet, SMTP, POP3, IMAP)
        ftp_lines_by_flow: Dict[Tuple[str, str, int, int], List[Tuple[datetime, str]]] = (
            defaultdict(list)
        )
        smtp_lines: List[Tuple[datetime, str, str, int, str, int]] = []
        telnet_lines: Dict[Tuple[str, str, int, int], List[Tuple[datetime, str]]] = defaultdict(
            list
        )
        pop3_imap_lines: Dict[Tuple[str, str, int, int], List[Tuple[datetime, str]]] = defaultdict(
            list
        )

        for pkt in packets:
            src_ip = pkt.src_ip or ""
            dst_ip = pkt.dst_ip or ""
            src_port = pkt.src_port or 0
            dst_port = pkt.dst_port or 0
            ts = pkt.timestamp

            # 1. High-Risk Insecure Protocol Exposure Accounting
            for p in (src_port, dst_port):
                if p in self.HIGH_RISK_PORTS:
                    server_ip = dst_ip if dst_port == p else src_ip
                    client_ip = src_ip if dst_port == p else dst_ip
                    port_exposures_map[(p, server_ip)].add(client_ip)
                    port_packet_counts[(p, server_ip)] += 1

            # Extract raw ASCII / latin-1 strings from available payloads
            raw_text = ""
            if pkt.http_request:
                if pkt.app_protocol == AppProtocol.HTTP or dst_port in (80, 8080, 8000, 3000, 5000):
                    headers_str = "\n".join(
                        f"{k}: {v}" for k, v in pkt.http_request.headers.items()
                    )
                    body_str = pkt.http_request.body_snippet or ""
                    raw_text = f"{pkt.http_request.method} {pkt.http_request.uri} {pkt.http_request.version}\n{headers_str}\n\n{body_str}"
                else:
                    raw_text = pkt.http_request.body_snippet or ""
            elif pkt.http_response:
                headers_str = "\n".join(f"{k}: {v}" for k, v in pkt.http_response.headers.items())
                body_str = pkt.http_response.body_snippet or ""
                raw_text = f"{pkt.http_response.version} {pkt.http_response.status_code} {pkt.http_response.reason_phrase}\n{headers_str}\n\n{body_str}"

            # 2. HTTP Credentials & Session Cookies
            if raw_text and (
                pkt.app_protocol == AppProtocol.HTTP
                or dst_port in (80, 8080, 8000, 3000, 5000)
                or src_port in (80, 8080, 8000, 3000, 5000)
            ):
                http_creds = self._dissect_http_credentials(pkt, raw_text)
                extracted_creds.extend(http_creds)

                # API Keys and Token scanner
                api_creds = self._scan_api_keys_and_tokens(pkt, raw_text)
                # Deduplicate against already extracted bearer tokens
                existing_hashes = {c.secret.sha256_hash for c in extracted_creds}
                for ac in api_creds:
                    if ac.secret.sha256_hash not in existing_hashes:
                        extracted_creds.append(ac)
                        existing_hashes.add(ac.secret.sha256_hash)

                # Unencrypted file transfer check
                unenc_file = self._extract_unencrypted_file(pkt, raw_text)
                if unenc_file:
                    unencrypted_files.append(unenc_file)

            # 3. FTP Command Stream Lines (Port 21)
            if dst_port in (21, 2121) and raw_text:
                for line in raw_text.splitlines():
                    ftp_lines_by_flow[(src_ip, dst_ip, src_port, dst_port)].append((ts, line))

            # 4. Telnet Lines (Port 23)
            if (dst_port in (23, 2323) or src_port in (23, 2323)) and raw_text:
                for line in raw_text.splitlines():
                    telnet_lines[(src_ip, dst_ip, src_port, dst_port)].append((ts, line))

            # 5. SMTP Lines (Port 25, 587)
            if dst_port in (25, 587) and raw_text:
                for line in raw_text.splitlines():
                    smtp_lines.append((ts, line, src_ip, src_port, dst_ip, dst_port))

            # 6. POP3 / IMAP Lines (Port 110, 143)
            if dst_port in (110, 143) and raw_text:
                for line in raw_text.splitlines():
                    pop3_imap_lines[(src_ip, dst_ip, src_port, dst_port)].append((ts, line))

        # Dissect FTP Flows
        for (s_ip, d_ip, s_port, d_port), lines in ftp_lines_by_flow.items():
            user: Optional[str] = None
            for ts, line in lines:
                clean = line.strip()
                if clean.upper().startswith("USER "):
                    user = clean[5:].strip()
                elif clean.upper().startswith("PASS ") and user:
                    password = clean[5:].strip()
                    defanged = self.defang_secret(password, SecretType.PASSWORD)
                    extracted_creds.append(
                        ExtractedCredentialRecord(
                            timestamp=ts,
                            protocol=CleartextProtocol.FTP,
                            src_ip=s_ip,
                            src_port=s_port,
                            dst_ip=d_ip,
                            dst_port=d_port,
                            username=user,
                            secret=defanged,
                            context_snippet=f"FTP USER {user} / PASS",
                            severity="CRITICAL",
                        )
                    )
                    user = None

        # Dissect SMTP Auth Dialogs
        if smtp_lines:
            smtp_creds = self._dissect_smtp_auth(smtp_lines)
            extracted_creds.extend(smtp_creds)

        # Dissect POP3 / IMAP Lines
        for (s_ip, d_ip, s_port, d_port), lines in pop3_imap_lines.items():
            pop_user: Optional[str] = None
            proto_type = CleartextProtocol.POP3 if d_port == 110 else CleartextProtocol.IMAP
            for ts, line in lines:
                clean = line.strip()
                # POP3: USER / PASS
                if clean.upper().startswith("USER "):
                    pop_user = clean[5:].strip()
                elif clean.upper().startswith("PASS ") and pop_user:
                    password = clean[5:].strip()
                    defanged = self.defang_secret(password, SecretType.PASSWORD)
                    extracted_creds.append(
                        ExtractedCredentialRecord(
                            timestamp=ts,
                            protocol=proto_type,
                            src_ip=s_ip,
                            src_port=s_port,
                            dst_ip=d_ip,
                            dst_port=d_port,
                            username=pop_user,
                            secret=defanged,
                            context_snippet=f"{proto_type.value} USER {pop_user} / PASS",
                            severity="CRITICAL",
                        )
                    )
                    pop_user = None
                # IMAP: ? LOGIN "username" "password"
                elif "LOGIN" in clean.upper():
                    login_match = re.search(
                        r'LOGIN\s+["\']?([^"\'\s]+)["\']?\s+["\']?([^"\'\s]+)["\']?',
                        clean,
                        re.IGNORECASE,
                    )
                    if login_match:
                        imap_user = str(login_match.group(1))
                        imap_pass = str(login_match.group(2))
                        defanged = self.defang_secret(imap_pass, SecretType.PASSWORD)
                        extracted_creds.append(
                            ExtractedCredentialRecord(
                                timestamp=ts,
                                protocol=CleartextProtocol.IMAP,
                                src_ip=s_ip,
                                src_port=s_port,
                                dst_ip=d_ip,
                                dst_port=d_port,
                                username=imap_user,
                                secret=defanged,
                                context_snippet=f"IMAP LOGIN {imap_user}",
                                severity="CRITICAL",
                            )
                        )

        # Dissect Telnet Sessions
        for (s_ip, d_ip, s_port, d_port), lines in telnet_lines.items():
            for ts, line in lines:
                clean = line.strip()
                # Look for user/password patterns in telnet
                if clean.lower().startswith("login:") or clean.lower().startswith("user:"):
                    parts = clean.split(":", 1)
                    if len(parts) >= 2 and parts[1].strip():
                        pass

        # Build HighRiskProtocolExposure models
        protocol_exposures: List[HighRiskProtocolExposure] = []
        for (port, server_ip), client_set in port_exposures_map.items():
            proto_name, risk_desc, rec_replace = self.HIGH_RISK_PORTS[port]
            pkt_count = port_packet_counts[(port, server_ip)]
            protocol_exposures.append(
                HighRiskProtocolExposure(
                    protocol_name=proto_name,
                    port=port,
                    server_ip=server_ip,
                    client_ips=sorted(list(client_set)),
                    packet_count=pkt_count,
                    risk_description=risk_desc,
                    recommended_replacement=rec_replace,
                )
            )

        # Threat Scoring & IoCs
        threat_score = 0.0
        iocs: set[str] = set()

        if extracted_creds:
            threat_score += 50.0
            for c in extracted_creds:
                iocs.add(c.src_ip)
                iocs.add(c.dst_ip)
                if c.username:
                    iocs.add(c.username)

        sensitive_files = [f for f in unencrypted_files if f.is_sensitive_file]
        if sensitive_files:
            threat_score += 30.0
            for sf in sensitive_files:
                iocs.add(sf.filename)
        elif unencrypted_files:
            threat_score += 15.0

        if protocol_exposures:
            threat_score += min(30.0, len(protocol_exposures) * 10.0)
            for pe in protocol_exposures:
                iocs.add(pe.server_ip)
                iocs.update(pe.client_ips)

        threat_score = min(100.0, threat_score)

        # Verdict
        if threat_score >= 60.0:
            verdict = "MALICIOUS"
        elif threat_score >= 20.0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"

        # Executive Summary & Remediation
        summary_parts = []
        if extracted_creds:
            summary_parts.append(
                f"Discovered {len(extracted_creds)} cleartext authentication credential(s) / token(s) exposed on wire."
            )
        if unencrypted_files:
            summary_parts.append(
                f"Intercepted {len(unencrypted_files)} unencrypted file transmission(s) ({len(sensitive_files)} sensitive)."
            )
        if protocol_exposures:
            summary_parts.append(
                f"Identified {len(protocol_exposures)} unencrypted legacy protocol exposure(s)."
            )

        if not summary_parts:
            exec_summary = (
                "No cleartext credentials or high-risk unencrypted protocol exposures detected."
            )
        else:
            exec_summary = " ".join(summary_parts)

        remediation: List[str] = []
        if extracted_creds:
            remediation.append(
                "Immediately revoke, rotate, and expire all compromised credentials and API tokens."
            )
            remediation.append(
                "Force TLS 1.3 encryption across all internal and external communication endpoints."
            )
        if protocol_exposures:
            remediation.append(
                "Disable unencrypted legacy services (Telnet, FTP, unencrypted HTTP, SNMPv1/v2c, LDAP)."
            )
            remediation.append(
                "Implement network segmentation and 802.1X Network Access Control (NAC)."
            )

        return CredentialLeakageReport(
            file_path=file_path,
            filename=filename or (os.path.basename(file_path) if file_path else "memory_buffer"),
            hashes=source_hashes or {},
            total_packets_scanned=len(packets),
            total_credentials_leaked=len(extracted_creds),
            total_unencrypted_files=len(unencrypted_files),
            total_protocol_exposures=len(protocol_exposures),
            credentials=extracted_creds,
            unencrypted_files=unencrypted_files,
            protocol_exposures=protocol_exposures,
            threat_score=threat_score,
            verdict=verdict,
            extracted_iocs=sorted(list(iocs)),
            executive_summary=exec_summary,
            remediation_guidance=remediation,
        )

    def analyze_pcap(self, pcap_source: Union[str, Path, bytes]) -> CredentialLeakageReport:
        """Parse packet capture container and execute cleartext credential forensics."""
        pcap_analyzer = NetworkPCAPAnalyzer(net_intel=self.intel_service)
        pcap_report: PCAPAnalysisReport = pcap_analyzer.analyze(pcap_source)

        return self.analyze_packets(
            packets=pcap_analyzer.last_parsed_packets,
            source_hashes=pcap_report.hashes,
            file_path=pcap_report.file_path,
            filename=pcap_report.filename,
        )
