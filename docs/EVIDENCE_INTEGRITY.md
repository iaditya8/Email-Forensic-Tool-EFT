# Evidence Integrity & Chain of Custody Specification

## 1. Principle of Digital Forensic Immutability

In digital forensics (DFIR), evidence must be acquired, preserved, analyzed, and presented without alteration. Any unintended modification invalidates forensic conclusions in legal, regulatory, or corporate investigations.

The **Email Forensic Tool (EFT)** enforces evidence integrity programmatically throughout the entire lifecycle.

---

## 2. Cryptographic Manifest (`evidence_manifest.json`)

Whenever a target email file is ingested, EFT generates a cryptographically signed manifest:

```json
{
  "manifest_version": "1.0",
  "case_id": "CASE-2026-001",
  "examiner_id": "EXAMINER-ADITYA",
  "acquisition_timestamp_utc": "2026-09-19T14:00:00Z",
  "source_file": {
    "file_name": "suspicious_invoice.eml",
    "file_size_bytes": 48291,
    "hashes": {
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  },
  "verification_status": "UNMODIFIED",
  "post_analysis_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

## 3. Defense Mechanisms in Code

1. **Read-Only Binary Streams:** Files are accessed exclusively using `open(path, "rb")` or OS-level read-locks. No in-place modification methods are permitted.
2. **Pre & Post Analysis Checksums:** SHA-256 hash is computed before entering the parser pipeline and re-verified after report generation. If a hash mismatch occurs, execution terminates immediately with an `EvidenceTamperedException`.
3. **Payload Isolation:** Extracted attachments are saved into an isolated, hashed subfolder with strict access permissions to prevent accidental execution.
