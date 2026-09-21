# EFT Project State & Handoff Context

## 1. Project Identity & Repository Status
* **Project Name:** Email Forensic Tool (EFT)
* **GitHub Remote:** `https://github.com/iaditya8/Email-Forensic-Tool-EFT`
* **Current Production Release:** `v1.0.0` (Tagged & merged on `main`)
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

## 4. Current Progress & Milestones Summary
* **Phase 1 (Epic 1): Ingestion & Core Parsing Engine** — ✅ 100% COMPLETE & MERGED (`dev` & `main`)
* **Phase 2 (Epic 2): Header & Authentication Analysis** — ✅ 100% COMPLETE & MERGED (`dev` & `main`)
* **Phase 3 (Epic 3): Content, Phishing & Threat Forensics** — ✅ 100% COMPLETE & MERGED (`dev` & `main`)
* **Phase 4 (Epic 4): Evidence Integrity, Chain of Custody & Reporting** — ✅ 100% COMPLETE & MERGED (`dev` & `main`)
* **Phase 5 (Epic 5): UI/UX & Visualization Dashboard** — ✅ 100% COMPLETE & MERGED (`dev` & `main`)
* **Step 1: Forensic Sample Corpus & Performance Benchmarking** — ✅ 100% COMPLETE (PR #39)
* **Step 2: v1.0.0 Production Release & Merge into `main`** — ✅ 100% COMPLETE (PR #40, Tag `v1.0.0`)

---

## 5. Next Steps (In Directed Order)
1. ⏳ **Step 3: Unified CLI Command-Line Suite (`eft`)**
   - Implement Click / Typer CLI `eft scan`, `eft report`, `eft inspect`, `eft map`.
   - Provide command flags for custom `--geoip`, `--yara-rules`, `--ioc-hashes`, and `--config`.
2. ⏳ **Step 4: Unified Air-Gapped Web Server (`eft serve`)**
   - Implement local FastAPI / HTTP server serving the integrated dashboard.
