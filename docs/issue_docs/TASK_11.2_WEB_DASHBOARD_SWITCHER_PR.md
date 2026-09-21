# Task 11.2: Multi-Tool Web Dashboard Workspace Switcher Pull Request Documentation

## 1. Summary & Objectives
This Pull Request delivers **Task 11.2: Multi-Tool Web Dashboard Workspace Switcher** under **Epic 11 (Phase 11 / v2.0.0): Unified Master Forensics Workstation & Multi-Modal Dashboard**.

It transforms the `eft serve` web dashboard into a comprehensive, multi-modal DFIR Master Workstation featuring a top workspace switcher across all 6 forensic domains:
1. ✉️ **Email Evidence Deep Triage** (`/api/analyze`, `/api/samples`, `/api/inspect`, `/api/map`, `/api/export/{fmt}`)
2. 📁 **File & Binary Inspector** (`/api/file/analyze`)
3. 🌐 **OSINT & Threat Intelligence** (`/api/osint/lookup`, `/api/osint/ip`)
4. 📡 **Network PCAP Analyzer** (`/api/pcap/analyze`)
5. 📜 **Windows & Cloud Log Correlator** (`/api/log/analyze`)
6. 🧠 **Volatile Memory Scanner** (`/api/mem/analyze`)

---

## 2. Key Changes & Features

### A. Frontend Architecture (`src/eft/server/templates/index.html`)
- **Master Workspace Switcher Bar:** Top-level navigation buttons (`#ws-btn-email`, `#ws-btn-file`, `#ws-btn-osint`, `#ws-btn-pcap`, `#ws-btn-log`, `#ws-btn-mem`) with dynamic glowing active states.
- **Dedicated Forensic Module Panes:**
  - **Email Evidence Deep Triage:** Multi-message MBOX/EML/MSG ingestion, cryptographic provenance, risk gauges, 8 sub-tabs (Auth, Transit Map, URLs, Attachments, BEC, Timeline, OSINT, Raw Headers), and PDF/STIX/CSV/JSON exports.
  - **File & Binary Inspector:** Dropzone for PE/ELF/Mach-O binaries and documents, Shannon entropy visual gauges, section tables, and EXIF/OLE metadata parsing.
  - **OSINT & Threat Intelligence:** Dual sub-tabs for domain posture (SPF, DMARC, DKIM, BIMI, homoglyph typosquatting) and IP intelligence (Geolocation, ASN, reverse DNS, RFC 1918 private IP tags).
  - **Network PCAP Analyzer:** Stream dissection, DNS exfiltration/tunneling indicators, fast-flux detection, and cleartext credential tables (HTTP, FTP, Telnet, POP3, SMTP, IMAP).
  - **Windows & Cloud Log Correlator:** Multi-format parser (EVTX, JSON, CSV, XML), Sysmon process execution trees, failed authentication brute force (Event 4625), and MITRE ATT&CK technique mapping.
  - **Volatile Memory Scanner:** Chunked stream analysis for regex IoCs, cryptocurrency addresses, process/thread artifacts, and compiled YARA rule malware attribution.
- **100% Air-Gapped Zero-CDN Compliance:** Built entirely using vanilla HTML5, CSS3, and modern ES6+ JavaScript. Zero external CDNs, fonts, or tracking scripts.
- **Full Session State Persistence:** Complete caching across browser refreshes via `localStorage` for active workspace selection, analysis results, and form inputs.

### B. Backend REST API Endpoints (`src/eft/server/routes.py`)
- `POST /api/osint/ip`: Inspect IP Geolocation, ASN ownership, reverse DNS, and RFC 1918 classification via `NetworkIntelligenceService.lookup_ip()`.
- `POST /api/file/analyze`: Static binary, artifact, and metadata inspection via `BinaryStaticAnalyzer`, `FileArtifactAnalyzer`, and `MetadataExtractor`.
- `POST /api/pcap/analyze`: Network flow, DNS tunneling, and credential leak dissection via `NetworkPCAPAnalyzer`, `DNSThreatAnalyzer`, and `CredentialLeakAnalyzer`.
- `POST /api/log/analyze`: Event log correlation via `WindowsLogAnalyzer`, `WindowsSecurityAnalyzer`, and `CloudAuditAnalyzer`.
- `POST /api/mem/analyze`: Volatile memory inspection via `MemoryArtifactAnalyzer`, `MemoryIoCMatcher`, and `MemoryYARAScanner`.

---

## 3. Verification & Quality Gates
- **Comprehensive Test Suite:** Added `tests/test_web_workstation_switcher.py`.
- **Test Results:** 384 tests passing (100% pass rate).
- **Code Coverage:** Overall codebase coverage at 88% (exceeds the 80% threshold).
- **Type Checking:** `mypy src tests` passed with 0 errors across 109 source files.
- **Linting & Formatting:** `ruff check` and `ruff format` passed with 0 warnings/errors.
- **Packaging:** `poetry build` successfully generated source distribution and wheel packages.
