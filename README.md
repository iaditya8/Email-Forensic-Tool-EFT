# Email Forensic Tool (EFT)

An advanced, digital forensics and incident response (DFIR) platform designed to ingest, analyze, reconstruct, and export email evidence with mathematical integrity verification and threat intelligence correlation.

---

## 🚀 Key Features

* **Multi-Format Ingestion:** Native, read-only parsing for `.eml`, `.msg` (Outlook), and `.mbox` archives.
* **Header & Route Reconstruction:** Chronological MTA relay hop reconstruction with latency calculation and origin IP isolation.
* **Authentication Verification:** Live SPF, DKIM signature verification, DMARC policy enforcement, and ARC chain validation.
* **Threat & Phishing Forensics:** URL defanging, anchor text mismatch detection, IDN homoglyph analysis, BEC/display name spoofing detection, and YARA static analysis.
* **Evidence Defensibility:** Cryptographic chain-of-custody manifests (`evidence_manifest.json`), timestamp sequence generation, and multi-format exports (PDF, JSON, CSV, STIX 2.1).

---

## 🏛 Architecture & Project Roadmap

* Detailed system architecture and sequence diagrams: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
* Epics, tasks, and acceptance criteria: [docs/ROADMAP.md](docs/ROADMAP.md)

---

## 🌿 Git Branching Strategy & Contribution Rules

1. **`main`**: Protected branch. Contains stable, production-ready releases. Direct pushes are **forbidden**.
2. **`dev`**: Integration branch for all active development.
3. **`feature/<epic-slug>/<task-slug>`**: Dedicated task branch (e.g., `feature/phase1-ingestion/task1.1-eml-parser`).
4. **Pull Requests (PRs):**
   - Create a PR targeting `dev`.
   - Use the standard PR template (`.github/PULL_REQUEST_TEMPLATE.md`).
   - Must reference the specific task issue (`Fixes #<issue_number>`).
   - Merge to `dev` only after CI tests pass and review is complete.

---

## 🛠 Directory Structure

```
Email Forensic Tool (EFT)/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── epic_template.md
│   │   └── task_template.md
│   ├── workflows/
│   │   └── ci.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── docs/
│   ├── ARCHITECTURE.md
│   └── ROADMAP.md
├── src/
│   └── eft/
├── tests/
├── data/
│   ├── evidence/
│   └── exports/
├── .gitignore
└── README.md
```
