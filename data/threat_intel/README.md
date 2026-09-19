# Threat Intelligence Feeds Directory

This folder holds indicator-of-compromise (IoC) lists for air-gapped threat detection.

- **`iocs.txt`**: Curated MD5 and SHA-256 malicious file hashes from VirusTotal, AlienVault OTX, and DFIR feeds.
- Use via CLI: `eft scan <path> --ioc-file data/threat_intel/iocs.txt` (or `--ioc-file iocs.txt`).
