# EFT Project State & Handoff Context

## 1. Project Identity & Repository Status
* **Project Name:** Email Forensic Tool (EFT)
* **GitHub Remote:** `https://github.com/iaditya8/Email-Forensic-Tool-EFT`
* **Default / Protected Branch:** `main`
* **Active Working Branch:** `dev`

---

## 2. Core Operational & Development Rules
* 📊 **Visualization Rule:** **NEVER** use ASCII art diagrams; **ALWAYS** use Mermaid diagrams.
* 🌿 **Git Branching Rule:** 
  - Never push directly to `main`.
  - Always branch off `dev` for every task: `feature/<phase-slug>/<task-slug>`.
  - Create standard PR descriptions and review each task before merging into `dev`.
* 📝 **Task Definition Standards:** Every task must strictly contain:
  1. *What needs to be built, and why*
  2. *Done when* (Verifiable acceptance criteria)
* 🔒 **Forensic Immutability:** All file reading must be strict read-only (`open(path, 'rb')`), pre/post analysis hashes must match (zero byte mutation), and extracted artifacts must be isolated.

---

## 3. Master Documentation Index
* **Roadmap & Acceptance Criteria:** [`docs/ROADMAP.md`](ROADMAP.md)
* **Architecture & System Design:** [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
* **Evidence Integrity Specification:** [`docs/EVIDENCE_INTEGRITY.md`](EVIDENCE_INTEGRITY.md)
* **Contributing Guidelines:** [`docs/CONTRIBUTING.md`](CONTRIBUTING.md)
* **CI/CD Workflow:** [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)

---

## 4. Current Progress & Epics Summary
* **Phase 1 (Epic 1): Ingestion & Core Parsing Engine** — ✅ 100% COMPLETE & MERGED (`dev`)
  - Multi-Format Ingestion (.eml, .msg, .mbox)
  - MIME Decomposition & Isolated Body Extraction
  - Attachment Extraction & Cryptographic Fingerprinting (MD5, SHA-1, SHA-256)
* **Phase 2 (Epic 2): Header & Authentication Analysis** — ✅ 100% COMPLETE & MERGED (`dev`)
  - MTA Relay Hop & Transit Route Reconstruction
  - GeoIP, ASN & Network Intelligence Enrichment
  - Multi-Protocol Authentication Engine (SPF, DKIM, DMARC, ARC)
* **Phase 3 (Epic 3): Content, Phishing & Threat Forensics** — ✅ 100% COMPLETE & MERGED (`dev`)
  - URL Extraction, Defanging & IDN Homoglyph Detection
  - Business Email Compromise (BEC) & Display Name Spoofing Detector
  - Content Obfuscation & Hidden Text Analysis (Zero-width, hidden CSS, base64)
  - Attachment Threat Scanner & YARA Rule Engine
* **Phase 4 (Epic 4): Evidence Integrity, Chain of Custody & Reporting** — ✅ 100% COMPLETE & MERGED (`dev`)
  - Cryptographic Evidence Ledger & Chain of Custody Manifest
  - Visual Chronological Timeline Generator with Anti-Forensic Anomaly Detection
  - Multi-Format Forensic Exporter (PDF, JSON, CSV IoCs, STIX 2.1 Bundles)
* **Phase 5 (Epic 5): UI/UX & Visualization Dashboard** — ✅ 100% COMPLETE & MERGED (`dev`)
  - Dual-Pane Air-Gapped Email & Header Inspector UI with HTML Sanitizer
  - Interactive Hop & Transit Map Visualizer (Offline Vector World Map, Geodesic Arcs)
  - Composite Threat Scorer (0-100) & Risk Indicator Card (Speedometer Dial, Factor Trees)
* **Step 1: Forensic Sample Corpus & Performance Benchmarking** — ✅ 100% COMPLETE & MERGED (`dev`) (PR #39)
  - Realistic Corpus: Benign, Phishing Homoglyph, BEC Wire Fraud, Malware Double-Ext, Obfuscation Zero-Width, Transit Tor Anomaly, Mixed MBOX Archive.
  - End-to-End Pipeline Integration Test Suite (`tests/test_corpus_integration.py`).
  - Latency, Scalability, and Throughput Benchmarks (`tests/test_benchmarks.py`).

---

## 5. Next Steps (In Directed Order)
1. ⏳ **Step 2: v1.0.0 Production Release & Merge into `main`**
2. ⏳ **Step 3: Unified CLI Command-Line Suite (`eft`)**
3. ⏳ **Step 4: Unified Air-Gapped Web Server (`eft serve`)**
