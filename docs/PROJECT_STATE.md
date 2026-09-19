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

## 4. Current Progress & Immediate Next Step

* **Phase 1 (Epic 1):** Ingestion & Core Parsing Engine
  * **Current Task to Execute:** **Task 1.1: Multi-Format Email Ingestion Engine**
  * **Target Branch to Create:** `feature/phase1-ingestion/task1.1-email-ingestion`
  * **Scope:**
    - Build `src/eft/ingestion/` parser supporting `.eml` (RFC 822/5322), `.msg` (Outlook), and `.mbox` in strict read-only mode.
    - Implement `CanonicalEmail` model.
    - Write unit tests in `tests/test_ingestion.py`.
    - Review task output & PR description before merging into `dev`.
