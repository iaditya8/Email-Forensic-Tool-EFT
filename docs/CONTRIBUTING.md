# Contributing to Email Forensic Tool (EFT)

Thank you for contributing to EFT! This document outlines our development process, branching model, coding standards, and forensic testing protocols.

---

## 1. Branching & Pull Request Workflow

We follow a strict **GitFlow** model:

1. **`main`**: Protected branch. Only updated through release PRs from `dev`.
2. **`dev`**: Active integration branch. All feature branches branch off and merge into `dev`.
3. **`feature/<phase-slug>/<task-slug>`**: Feature branches for specific tasks (e.g., `feature/phase1-ingestion/task1.1-email-ingestion`).

### Step-by-Step Feature Workflow:
1. Ensure your local `dev` branch is up to date:
   ```bash
   git checkout dev
   git pull origin dev
   ```
2. Create your task branch:
   ```bash
   git checkout -b feature/phase1-ingestion/task1.1-email-ingestion
   ```
3. Implement changes, write unit tests, and verify code standards.
4. Push your branch to GitHub:
   ```bash
   git push -u origin feature/phase1-ingestion/task1.1-email-ingestion
   ```
5. Open a Pull Request targeting `dev`. Include:
   * **Task Issue link** (`Fixes #<issue_number>`).
   * **Summary of changes**.
   * **Forensic Integrity checklist**.
   * **Test verification output**.

---

## 2. Forensic Development Standards

When developing modules for EFT, you must adhere to core forensic principles:

* **Zero Mutation:** Never modify the source evidence file or its operating system metadata. Always open files in binary read mode (`rb`).
* **Cryptographic Verification:** Any data extraction must maintain repeatable cryptographic hash tracking (MD5, SHA-1, SHA-256).
* **Defensive Error Handling:** Handle corrupt, truncated, or non-RFC compliant emails gracefully without crashing the analysis pipeline.

---

## 3. Code Style & Quality

* **Formatting & Linting:** We use `ruff` and `flake8`.
  ```bash
  ruff check .
  ```
* **Type Checking:** All functions and data structures should include type annotations (`mypy`).
  ```bash
  mypy src/
  ```
* **Testing:** All new features must include automated tests using `pytest`.
  ```bash
  pytest --cov=src tests/
  ```
