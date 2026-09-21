# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-09-21

### Major Expansion: Unified Master Forensics Workstation & Multi-Modal DFIR Platform

#### Added
- **Unified Master CLI Routing (`eft`)**:
  - Unified command router with subcommands: `eft email`, `eft file`, `eft osint`, `eft pcap`, `eft log`, `eft mem`, `eft case`, and `eft serve`.
  - Consistent `--json`, `--output`, and `--format` options across all CLI commands.
- **Multi-Modal Air-Gapped Web Dashboard**:
  - Air-gapped single-page web application (`eft serve`) with workspace tab navigation across all 6 forensic domains.
  - Zero external CDN or internet dependencies.
  - Interactive transit map visualizer for email hops, memory triage, network packet views, and security log timelines.
- **Cross-Module Unified Evidence Ledger & Master Case Report**:
  - Ingests multi-modal evidence under a single Case ID and Examiner manifest.
  - Dual pre- and post-analysis multi-algorithm cryptographic hashing (`MD5`, `SHA-1`, `SHA-256`, `SHA-512`) verifying 100% zero-byte mutation.
  - Automatic cross-evidence IoC correlation, multi-stage attack killchain sequencing, and aggregate risk scoring.
  - Court-admissible export formats: PDF, STIX 2.1 Threat Intelligence Bundle, RFC 4180 CSV, and structured JSON.
- **Network PCAP Forensics**:
  - Wire-speed packet dissection for IPv4/IPv6, TCP, UDP, DNS, HTTP, and TLS.
  - Shannon entropy and volume-based DNS exfiltration and tunneling detection.
  - Cleartext credential and secret leakage extraction across unencrypted protocols.
- **Windows & Cloud Log Correlation**:
  - Windows EVTX and Sysmon event parsing (Logon Type 2/3/10, service installations, task creation).
  - Cloud audit log ingestion (Microsoft 365 Unified Audit Log & Google Workspace).
  - Malicious inbox forwarding, permission escalation, and account takeover detection.
- **Volatile Memory Dump Triage**:
  - Streaming raw memory dump parsing with memory-mapped chunks.
  - In-memory regex scanner for URLs, IP addresses, credentials, private keys, and cryptocurrency addresses.
  - Memory YARA scanner attributing malware beacons, reflective DLL injection, and credential dumping utilities.
- **Standalone Binary & Artifact Analysis**:
  - Deep magic byte signature engine with extension-mismatch and RLO deception detection.
  - Portable Executable (PE32/PE32+) header and section entropy analysis.
  - Microsoft OLE / VBA macro parser and payload risk classification.
  - Multi-format EXIF, PDF, and media metadata extraction.
- **Domain & IP OSINT Engine**:
  - Offline WHOIS parsing, passive DNS, MX/SPF/DKIM/DMARC auditing, and MaxMind GeoIP resolution.

---

## [1.0.0] - Initial Release
- Initial release of Email Forensic Tool (EFT) core email parser and header analyzer.
