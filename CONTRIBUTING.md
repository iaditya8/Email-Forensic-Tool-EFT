# Contributing to Email Forensic Tool (EFT)

Thank you for your interest in contributing to **Email Forensic Tool (EFT)**! We welcome contributions from digital forensic practitioners, reverse engineers, security researchers, and software engineers.

To maintain the highest level of code quality, security, and court admissibility standards, all contributors are expected to adhere to the guidelines outlined below.

---

## 📋 Table of Contents
- [Code of Conduct](#-code-of-conduct)
- [Git Branching Strategy](#-git-branching-strategy)
- [Development Setup](#-development-setup)
- [Architectural & Forensic Standards](#-architectural--forensic-standards)
- [Coding Conventions & Style](#-coding-conventions--style)
- [Testing & Coverage Gates](#-testing--coverage-gates)
- [Commit Message Guidelines](#-commit-message-guidelines)
- [Pull Request Process](#-pull-request-process)

---

## 🤝 Code of Conduct
We are committed to providing a welcoming, respectful, and inclusive environment for all contributors. Please maintain professional, constructive, and ethical communication in all issues, pull requests, and discussions.

---

## 🌿 Git Branching Strategy

EFT follows a structured branching model:

```
  main (Production / Protected Release Branch)
    ▲
    │ (Release PR with 100% CI pass)
  dev  (Active Integration Branch)
    ▲
    │ (Feature PR targeting dev)
  feature/phase<X>-<domain>/task<X>.<Y>-<description>
```

- **`main`**: Represents the current production release (e.g. `v2.0.0`). Direct pushes to `main` are strictly prohibited.
- **`dev`**: The primary integration branch where completed features are merged and validated.
- **Feature Branches**: Branch from `dev` using the standard naming convention:
  - Format: `feature/phase<PHASE_NUMBER>-<DOMAIN>/task<TASK_ID>-<SHORT_DESC>`
  - Examples:
    - `feature/phase8-pcap/task8.2-dns-tunneling-detector`
    - `feature/phase10-memory/task10.3-memory-yara-scanner`
    - `fix/parser-ole-null-pointer`

---

## ⚙️ Development Setup

### 1. Prerequisites
- **Python**: `>=3.10` and `<4.0` (Tested on `3.10`, `3.11`, `3.12`)
- **Poetry**: `>=2.0.0`
- **Git**: `>=2.30`

### 2. Fork & Clone
```bash
git clone https://github.com/iaditya8/Email-Forensic-Tool-EFT.git
cd "Email Forensic Tool (EFT)"
git checkout dev
```

### 3. Environment Installation
Install the project dependencies and active development toolchain:
```bash
poetry install
```

---

## 🔒 Architectural & Forensic Standards

When adding or modifying code in EFT, you must strictly uphold the following core engineering principles:

1. **Forensic Immutability (ISO/IEC 27037)**:
   - **Zero-Byte Mutation**: Analyzers must **never** modify, write to, or overwrite an ingested evidence file or buffer.
   - Always open evidence files in binary read mode (`rb`) or memory-mapped read-only buffers.
   - Any mutation detected must immediately raise an `EvidenceTamperedException`.

2. **Air-Gapped & Offline Architecture**:
   - EFT must operate seamlessly in isolated, air-gapped forensic laboratories without an active internet connection.
   - **No external CDN dependencies**: All web UI assets (HTML, CSS, JS, SVG icons, fonts) must be bundled locally or embedded inline.
   - Network lookups (DNS/WHOIS/GeoIP) must gracefully fall back to offline caches when no uplink is present.

3. **Pydantic Data Models**:
   - All report structures, configuration objects, and forensic artifacts must be strictly typed using **Pydantic v2** (`BaseModel`).
   - Every model must provide a `.to_dict()` or `.model_dump(mode="json")` serialization method.

4. **Defensive Error Handling**:
   - Corrupt files, partial buffers, or maliciously malformed payloads must never crash the workstation or CLI.
   - Catch domain-specific exceptions, log the anomaly within the forensic findings list, and continue analysis.

---

## 🖋 Coding Conventions & Style

EFT enforces strict static analysis and code formatting rules:

- **Formatter & Linter**: **Ruff**
- **Type Checker**: **Mypy** (Strict type annotations required on all public functions, classes, and return signatures)

### Running Static Checks Locally
```bash
# Check code for lint issues
poetry run ruff check src tests

# Automatically fix fixable lint errors
poetry run ruff check --fix src tests

# Check code formatting
poetry run ruff format --check src tests

# Reformat code automatically
poetry run ruff format src tests

# Run Mypy static type verification
poetry run mypy src tests
```

---

## 🧪 Testing & Coverage Gates

All contributions require comprehensive automated tests.

1. **Test Location**: Place new test modules in the `tests/` directory prefixed with `test_` (e.g. `tests/test_pcap_analyzer.py`).
2. **Coverage Requirement**: Total codebase test coverage must remain **$\ge 80\%$**.
3. **No Mocking Overuse**: Use realistic, synthetic forensic fixtures (e.g., sample EMLs, PCAP byte streams, mock PE binaries) rather than over-mocking internal logic.

### Running Test Commands
```bash
# Run all tests
poetry run pytest -v

# Run with test coverage report and threshold gate
poetry run pytest --cov=eft --cov-report=term-missing --cov-fail-under=80

# Run a specific test module
poetry run pytest tests/test_case_aggregator.py -v
```

---

## 💬 Commit Message Guidelines

We adhere to the [Conventional Commits](https://www.conventionalcommits.org/) standard:

```
<type>(<scope>): <short description>

[optional body explaining motivation and technical approach]
```

### Supported Types
- `feat`: A new feature or forensic analyzer
- `fix`: A bug fix or parser patch
- `docs`: Documentation updates (README, ROADMAP, issue docs)
- `test`: Adding or refactoring test suites
- `refactor`: Code restructuring with no functional changes
- `chore`: Dependency bumps, CI configuration, release tasks

### Examples
- `feat(pcap): implement Shannon entropy DNS tunneling detector`
- `fix(mime): resolve attachment extraction crash on malformed boundary`
- `docs(roadmap): update completion status for task 11.3`
- `test(memory): add YARA process signature match integration tests`

---

## 🚀 Pull Request Process

1. **Branch from `dev`**:
   ```bash
   git checkout dev
   git pull origin dev
   git checkout -b feature/phase11-master-workstation/task11.3-unified-case-ledger-report
   ```
2. **Implement & Test**:
   - Write your implementation and corresponding tests under `tests/`.
   - Ensure all quality gates pass:
     ```bash
     poetry run ruff check src tests
     poetry run ruff format src tests
     poetry run mypy src tests
     poetry run pytest --cov=eft --cov-fail-under=80
     poetry build
     ```
3. **Document PR**:
   - Create a summary markdown document under `docs/issue_docs/TASK_<X.Y>_<TITLE>_PR.md` detailing objectives, changes, and test results.
4. **Open Pull Request**:
   - Submit your PR targeting the **`dev`** branch.
   - Ensure the title follows Conventional Commits.
   - Attach your issue document or fill out the PR description template.
5. **CI Review & Merge**:
   - GitHub Actions will run the test matrix across **Ubuntu** and **Windows** on **Python 3.10, 3.11, and 3.12**.
   - Once all checks pass and code review is complete, the branch will be squash-merged into `dev`.

---

Thank you for helping make Email Forensic Tool (EFT) a world-class, reliable DFIR solution!
