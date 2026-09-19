# Email Forensic Tool (EFT) - System Architecture

## 1. High-Level Architecture Overview

The Email Forensic Tool (EFT) is architected following clean, layered design principles for digital forensic readiness: **Immutability of Evidence**, **Determinism**, **Modular Extensibility**, and **Court-Defensible Reporting**.

```mermaid
graph TD
    subgraph Presentation["1. Presentation Layer"]
        CLI["Rich Terminal CLI"]
        WebUI["Web Dashboard"]
        API["RESTful APIs"]
    end

    subgraph AppCore["2. Application Core"]
        subgraph Ingestion["Ingestion & Extraction Layer"]
            Reader["Multi-Format Parser (.eml, .msg, .mbox)"]
            MIME["MIME Tree Decomposer"]
            AttHash["Attachment Extractor & Multi-Hashing"]
        end

        subgraph Engine["Forensic Analysis Engine"]
            Hops["Relay & Hop Analyzer"]
            Auth["SPF / DKIM / DMARC / ARC"]
            Geo["GeoIP & ASN Lookup"]
            Links["URL & Link Forensics"]
            BEC["BEC & Spoofing Detector"]
            YARA["YARA Rule Scanner"]
        end

        subgraph Reporting["Evidence & Reporting Pipeline"]
            Custody["Chain of Custody & Hash Validator"]
            Timeline["Chronological Timeline Engine"]
            Export["Multi-Format Exporters (PDF, JSON, CSV, STIX)"]
        end
    end

    subgraph Storage["3. Storage & Evidence Vault"]
        Vault[("Read-Only Evidence Vault")]
        Cache[("Metadata & Threat Cache")]
    end

    Presentation --> Ingestion
    Ingestion --> Engine
    Engine --> Reporting
    Ingestion -.-> Vault
    Reporting -.-> Vault
    Engine -.-> Cache
```

---

## 2. Core Subsystems

### 2.1 Ingestion & Normalization Subsystem
* **Purpose:** Ingest raw email files across multiple standards without touching file modified times or altering binary streams.
* **Outputs:** A structured, immutable `CanonicalEmail` model containing:
  - Raw header dictionary + ordered header list
  - Multi-part MIME nodes
  - Plaintext & sanitized HTML bodies
  - Payload attachments with MD5, SHA-1, and SHA-256 digests

### 2.2 Forensic Analysis Subsystem
* **Relay & Route Analyzer:** Parses `Received:` headers in reverse chronological order, measures hop latency, and isolates the true origin IP.
* **Authentication Verifier:** Queries DNS for live SPF and DKIM public keys; validates against recorded `Authentication-Results`.
* **Phishing & Content Inspector:**
  - Extracts all hyperlinks and parses anchor vs. destination mismatches.
  - Detects Unicode homoglyphs and Punycode spoofing.
  - Scans HTML DOM for zero-font, hidden CSS, and invisible tracking pixels.
* **Threat Scanner:** Applies static YARA rules and file type verification against all binary payloads.

### 2.3 Evidence & Reporting Subsystem
* **Chain of Custody:** Generates and validates an `evidence_manifest.json` ensuring cryptographic immutability from input to output.
* **Report Engine:** Converts the enriched forensic case model into PDF reports, structured JSON dumps, and STIX 2.1 intelligence bundles.

---

## 3. Data Flow

```mermaid
sequenceDiagram
    autonumber
    actor Examiner
    participant Ingestion as Ingestion Layer
    participant Manifest as Evidence Manifest
    participant Analyzer as Forensic Analysis Engine
    participant Exporter as Report Generator

    Examiner->>Ingestion: Submit target email file (.eml / .msg / .mbox)
    Ingestion->>Manifest: Compute baseline SHA-256 and lock read-only access
    Ingestion->>Analyzer: Emit CanonicalEmail object
    Analyzer->>Analyzer: Run Hop, Auth, URL, BEC & YARA analyzers in parallel
    Analyzer->>Exporter: Output EnrichedForensicReport
    Exporter->>Manifest: Verify evidence integrity remained unchanged
    Exporter->>Examiner: Deliver PDF, JSON, and STIX Reports
```
