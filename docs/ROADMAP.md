# Email Forensic Tool (EFT) - Tasks & Epics Roadmap

This document serves as the master source for creating GitHub Issues and tracking phase completions.

---

## Epic 1 (Phase 1): Ingestion & Core Parsing Engine

### Task 1.1: Multi-Format Email Ingestion Engine
* **What needs to be built, and why:**
  * Build an ingestion pipeline capable of reading standard `.eml` (RFC 822/5322), `.msg` (Microsoft Outlook OLE format), and `.mbox` archives in strict read-only mode.
  * *Why:* Digital forensics requires handling diverse email formats from different clients and mail servers without modifying original timestamps or metadata.
* **Done when:**
  - [ ] Parser correctly ingests valid `.eml`, `.msg`, and `.mbox` files into an internal canonical data model.
  - [ ] Original file is accessed in read-only mode with zero file mutation.
  - [ ] Error handler gracefully rejects corrupt/truncated files with clear forensic diagnostic logs.
  - [ ] Unit tests cover all three formats.

### Task 1.2: Raw Header & MIME Tree Decomposition
* **What needs to be built, and why:**
  * Build a MIME parser that traverses multi-part message trees (`multipart/mixed`, `multipart/alternative`, `multipart/related`) and extracts standard, non-standard (`X-*`), and raw headers.
  * *Why:* Hidden headers and deeply nested MIME structures are commonly used by attackers to hide payloads or bypass filtering.
* **Done when:**
  - [ ] Extracted MIME hierarchy is mapped as an object/tree showing all parent-child parts and character encodings (UTF-8, ISO-8859-1, base64, quoted-printable).
  - [ ] All `Received`, `Authentication-Results`, `DKIM-Signature`, and custom `X-*` headers are extracted as an ordered list.
  - [ ] Plaintext and HTML body contents are extracted and isolated into separate artifacts.

### Task 1.3: Attachment Extractor & Cryptographic Fingerprinting
* **What needs to be built, and why:**
  * Build an automated module that extracts all embedded attachments and inline objects, computes cryptographic hashes (MD5, SHA-1, SHA-256), and validates true file types via magic byte inspection.
  * *Why:* Forensic investigators need cryptographic hashes for threat intelligence matching and must detect extension-spoofing techniques (e.g., `.exe` disguised as `.pdf`).
* **Done when:**
  - [ ] All attachments and inline assets are extracted to an isolated evidence folder.
  - [ ] MD5, SHA-1, and SHA-256 hashes are generated for each attachment.
  - [ ] File headers/magic bytes are checked against file extension, raising a forensic alert if mismatched.

---

## Epic 2 (Phase 2): Header & Authentication Analysis

### Task 2.1: Relay Hop & Transit Route Reconstruction
* **What needs to be built, and why:**
  * Build an algorithm to parse and reverse-order all `Received:` headers to reconstruct the chronological transit path from the originating client to the recipient Mail Transfer Agent (MTA).
  * *Why:* Identifying the origin IP and calculating hop-by-hop latency reveals forged headers and abnormal transmission delays.
* **Done when:**
  - [ ] Each hop captures: hop sequence number, sending host/IP, receiving host/IP, timestamp (UTC), and transmission protocol (ESMTP, etc.).
  - [ ] Transit time (delay) between consecutive hops is computed in seconds.
  - [ ] Anomalies (e.g., negative transit times or non-routable private IPs in external hops) trigger forensic flags.

### Task 2.2: IP Geolocation, ASN & Network Intelligence
* **What needs to be built, and why:**
  * Build a network intelligence service to enrich extracted IP addresses with GeoIP (Country, City, Coordinates), Autonomous System Number (ASN), ISP name, and proxy/VPN flags.
  * *Why:* Investigators must immediately see the geographic path and hosting infrastructure used by the sender.
* **Done when:**
  - [ ] Originating IP and relay IPs are enriched with GeoIP, ISP, and ASN data.
  - [ ] Relays identified as cloud providers (AWS, Azure, DigitalOcean, etc.), Tor exit nodes, or public VPNs are tagged.
  - [ ] Offline fallback or cached database is supported for air-gapped forensic environments.

### Task 2.3: Email Authentication Validation (SPF, DKIM, DMARC, ARC)
* **What needs to be built, and why:**
  * Build an authentication evaluation engine that parses `Authentication-Results` / `Received-SPF` headers and performs live DNS validation checks for SPF, DKIM public keys, DMARC policies, and ARC seals.
  * *Why:* Spoofed emails almost always exhibit SPF/DKIM/DMARC alignment failures; verifying these is the foundation of anti-spoofing forensics.
* **Done when:**
  - [ ] SPF status (`Pass`, `Fail`, `SoftFail`, `Neutral`, `None`) is evaluated along with Return-Path alignment.
  - [ ] DKIM signature parameters (`d=`, `s=`, `b=`, `bh=`) are extracted and verified against DNS public keys.
  - [ ] DMARC policy (`none`, `quarantine`, `reject`) and alignment mode (strict vs. relaxed) are calculated.
  - [ ] Full summary verdict (e.g., `AUTHENTICATION: FAILED (SPF Fail, DMARC Reject)`) is generated.

---

## Epic 3 (Phase 3): Content, Phishing & Threat Forensics

### Task 3.1: URL Extraction, Defanging & Homograph Detection
* **What needs to be built, and why:**
  * Build an engine that extracts all URLs from the HTML/plaintext body, identifies anchor text mismatches (displayed link != actual href), unshortens redirected URLs, detects IDN/punycode homograph attacks, and defangs URLs (`hxxp://...`).
  * *Why:* Phishing campaigns rely on deceiving hyperlinks and link-masking tactics.
* **Done when:**
  - [ ] Every URL in the body is extracted with its anchor/display text.
  - [ ] Anchor text mismatches (e.g., displayed as `https://bank.com` but pointing to `http://evil.com`) are flagged as high-risk.
  - [ ] Internationalized Domain Names (IDN) with Cyrillic/homoglyph characters are converted to Punycode and flagged.
  - [ ] Defanged versions of all extracted URLs are generated for safe report export.

### Task 3.2: Spoofing & Business Email Compromise (BEC) Detector
* **What needs to be built, and why:**
  * Build heuristic analyzers to detect Display Name spoofing, Cousin/Typosquatted domain names, and discrepancies between `From`, `Reply-To`, `Sender`, and `Return-Path` addresses.
  * *Why:* BEC attacks manipulate display names and cousin domains (e.g., `micros0ft.com`) to trick victims into financial transactions.
* **Done when:**
  - [ ] System detects when `From` header display name resembles an executive/brand but sender domain differs.
  - [ ] Mismatch between `From` and `Reply-To` triggers an automatic suspicious reply-routing warning.
  - [ ] Levenshtein distance check compares the sender domain against a configurable list of target/legitimate domains.

### Task 3.3: Content Obfuscation & Hidden Text Analysis
* **What needs to be built, and why:**
  * Build a DOM/HTML scanner that detects hidden text tricks (zero-pixel fonts, white text on white backgrounds, CSS `display:none`, `visibility:hidden`, and excessive off-screen padding) and extracts embedded base64/hex blobs.
  * *Why:* Threat actors insert invisible text to dilute spam Bayesian filters and hide prompt injection payloads.
* **Done when:**
  - [ ] HTML body is inspected for CSS rules hiding text (`font-size: 0px`, `color: transparent`, `display: none`).
  - [ ] Hidden content is isolated and displayed in the forensic report under an Obfuscated Content section.
  - [ ] Base64, hex, and URL-encoded script blocks found within the body are automatically decoded.

### Task 3.4: Attachment Static Analysis & YARA Rule Scanner
* **What needs to be built, and why:**
  * Build an attachment threat engine that runs customizable YARA rules against extracted attachments and checks hashes against known threat intelligence feeds.
  * *Why:* Identify malicious macros (VBA), embedded executables, exploit payloads, or malicious PDFs.
* **Done when:**
  - [ ] YARA engine compiles and executes default DFIR rule files against all extracted attachments.
  - [ ] Matching YARA rule names and metadata tags are appended to the attachment's forensic record.
  - [ ] Dangerous attachment extensions (`.exe`, `.scr`, `.vbs`, `.iso`, `.hta`, `.xlsm`) are flagged.

---

## Epic 4 (Phase 4): Evidence Integrity, Chain of Custody & Reporting

### Task 4.1: Chain of Custody & Cryptographic Evidence Ledger
* **What needs to be built, and why:**
  * Build an evidence manifest generator that records the examiner's identity, case ID, acquisition timestamp (UTC), file size, and raw file SHA-256 hash.
  * *Why:* Legal defensibility requires proving the evidence was never altered during analysis.
* **Done when:**
  - [ ] Case initialization creates a cryptographically signed/hashed `evidence_manifest.json`.
  - [ ] Tool validates original evidence hash before and after analysis to prove zero evidence contamination.

### Task 4.2: Visual Chronological Timeline Generator
* **What needs to be built, and why:**
  * Build a timeline synthesis engine that merges all extracted timestamps (creation date, client sent date, intermediate MTA relay times, delivery timestamp) into an event sequence.
  * *Why:* Visualizing the timeline clarifies the sequence of events and exposes time-travel/timestamp tampering anomalies.
* **Done when:**
  - [ ] Standardized UTC chronological timeline is produced.
  - [ ] Clock drift or out-of-order timestamps between hops are explicitly highlighted.

### Task 4.3: Multi-Format Forensic Report Exporter
* **What needs to be built, and why:**
  * Build an automated report exporter supporting **PDF** (executive/court-ready report), **JSON** (full structured evidence), **CSV** (indicators of compromise), and **STIX/TAXII** (threat intelligence sharing).
  * *Why:* Forensic investigators need to share findings with both non-technical stakeholders (court/management) and automated SIEM/SOAR pipelines.
* **Done when:**
  - [ ] PDF report is generated containing executive summary, threat score, header hops, and indicator tables.
  - [ ] JSON and CSV exports contain 100% of extracted metadata, indicators, and hashes.
  - [ ] STIX 2.1 bundle export contains all extracted IPs, domains, and attachment hashes as observables.

---

## Epic 5 (Phase 5): UI/UX & Visualization Dashboard

### Task 5.1: Dual-Pane Email & Header Inspector UI
* **What needs to be built, and why:**
  * Build an interactive interface with a safe, sandboxed email preview on one side and a deep-dive header/MIME inspector on the other.
  * *Why:* Investigators need to visually correlate what the recipient saw with the underlying forensic artifacts.
* **Done when:**
  - [ ] HTML email preview is completely sandboxed (scripts disabled, external tracker image loading blocked).
  - [ ] Header inspector allows searching, filtering, and copy-pasting raw or decoded headers.

### Task 5.2: Interactive Hop & Transit Map Visualizer
* **What needs to be built, and why:**
  * Build a graphical network/map view rendering the transit hops from source IP across intermediate MTAs to final destination.
  * *Why:* Enhances cognitive clarity for investigators and makes evidence presentation intuitive.
* **Done when:**
  - [ ] Hop route is visually rendered as a node-link diagram with transit times and flags per node.
  - [ ] World map displays the geographic path traced by GeoIP coordinates.

### Task 5.3: Threat Score & Composite Risk Indicator Card
* **What needs to be built, and why:**
  * Build an overarching risk scoring algorithm (0 to 100) that aggregates SPF/DKIM failures, suspicious links, spoofed display names, and attachment flags.
  * *Why:* Allows triage analysts to instantly determine whether an email is benign, suspicious, or malicious.
* **Done when:**
  - [ ] Composite risk score is calculated and displayed with color-coded risk level (Low, Medium, High, Critical).
  - [ ] Breakdown explains exactly which factors contributed to the score.

---

## Epic 6 (Phase 6 / v1.1.0): Domain & Email Address OSINT Inspector

### Task 6.1: Standalone Domain & Email OSINT Intelligence Engine
* **What needs to be built, and why:**
  * Build a dedicated analyzer `DomainOSINTAnalyzer` that accepts raw email addresses (e.g., `user@domain.com`) or domain strings without requiring an ingested `.eml`/`.msg` file.
  * Evaluates DNS MX records, SPF (`v=spf1`) presence/strictness, DMARC (`v=DMARC1; p=reject|quarantine|none`) policy enforcement, DKIM selector discovery, and BIMI records.
  * Integrates IDN/Homoglyph transliteration, typosquatting Levenshtein distance against protected brand watchlists, and disposable/temporary email provider catalogs.
  * *Why:* Enables SOC analysts and investigators to perform fast pre-triage, verify lookalike domains, and check domain authentication posture before receiving full headers.
* **Done when:**
  - [ ] `DomainOSINTAnalyzer` queries DNS (or offline cache) for MX, SPF, DMARC, and BIMI.
  - [ ] Homoglyph and lookalike score calculated against `watchlist.json`.
  - [ ] Disposable email provider detection returns true/false with provider classification.
  - [ ] Outputs a structured `DomainOSINTReport` with a composite 0-100 reputation score.

### Task 6.2: Unified CLI Lookup Command (`eft lookup` / `eft osint`)
* **What needs to be built, and why:**
  * Implement CLI command `eft lookup <email_or_domain>` with options `--json`, `--dns-timeout`, and `--offline`.
  * *Why:* Provides rapid command-line triage for incident responders directly in their terminal.
* **Done when:**
  - [ ] `eft lookup user@example.com` outputs rich color-coded terminal tables for DNS, SPF/DMARC posture, and brand risk.
  - [ ] Comprehensive automated tests cover CLI options and report formats.

### Task 6.3: Web Dashboard Quick OSINT Inspector Tab
* **What needs to be built, and why:**
  * Add an interactive "OSINT & Domain Inspector" panel in the `eft serve` web dashboard with a search bar allowing analysts to paste any email address or domain.
  * Visualizes DNS MX/SPF/DMARC security badges, disposable mail warnings, and lookalike brand comparison cards.
  * *Why:* Delivers a complete, all-in-one workflow for both full-file forensic triage and rapid address reputation queries.
* **Done when:**
  - [ ] REST API endpoint `POST /api/osint/lookup` added to FastAPI router.
  - [ ] Web dashboard includes a dedicated OSINT Inspector tab with real-time analysis results.

