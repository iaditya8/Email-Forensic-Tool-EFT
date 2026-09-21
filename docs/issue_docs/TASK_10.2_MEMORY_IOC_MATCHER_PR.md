# Task 10.2: In-Memory Regex Pattern & IoC Matcher

## Summary of Changes
Implemented the **In-Memory Regex Pattern & IoC Matcher** (`MemoryIoCMatcher`) in pure Python, enabling automated DFIR triage of RAM images for active C2 network indicators, cryptocurrency wallets, unencrypted credentials, API tokens, obfuscated payloads, and known threat intelligence hashes.

### Key Capabilities & Architectural Components
1. **Multi-Pattern Memory Threat Detection Engine (`MemoryIoCMatcher`)**:
   - Ingests extracted memory strings or streams RAM images via `MemoryArtifactAnalyzer` to perform multi-pattern scanning with zero external C-dependencies.
   - Computes surrounding contextual window snippets (+/- 40 characters) for every detected finding to accelerate human analyst verification.

2. **Network Indicators of Compromise (IoCs)**:
   - **IPv4 Address Validation & Geolocation**: Matches IPv4 patterns, validates octet numerical boundaries (0-255), excludes non-routable/multicast, identifies private/internal subnets, and enriches public IPs with country, ASN, ISP, VPN, Tor exit node, and cloud hyperscaler metadata via `NetworkIntelligenceService`.
   - **IPv6 Address Validation**: Matches and validates standard and compressed IPv6 notations.
   - **C2 URLs & Web Protocols (`T1071.001`)**: Identifies `http://`, `https://`, `ftp://`, and `wss?://` URLs with punctuation defanging.
   - **Email Addresses (`T1566`)**: Matches and extracts email communication artifacts.

3. **Cryptocurrency Extortion & Ransomware Indicators (`T1486`)**:
   - **Bitcoin Addresses**: Identifies Legacy (`1...`), P2SH (`3...`), and Bech32 Native SegWit (`bc1...`) cryptocurrency wallet addresses.
   - **Ethereum Addresses**: Detects EVM-compatible hex addresses (`0x[a-fA-F0-9]{40}`).

4. **Credential & Secret Extraction (`T1552.001 / T1552.004`)**:
   - **JWT Tokens**: Identifies multi-part encoded JSON Web Tokens (`eyJ...`) and extracts decoded payload claims (`sub`, `aud`, `iss`, `exp`) without requiring verification keys.
   - **PEM Private Keys**: Identifies unencrypted RSA, EC, DSA, and OpenSSH private key headers (`-----BEGIN ... PRIVATE KEY-----`).

5. **Fileless Payloads & Obfuscated Execution (`T1027 / T1059.001`)**:
   - **Base64 MZ Executable Headers**: Detects embedded Base64-encoded PE binary headers (`TVqQAAMAAAAEAAAA...`).
   - **Obfuscated PowerShell Commands**: Detects `-encodedCommand` execution payloads and attempts UTF-16LE / UTF-8 Base64 payload decoding.

6. **Threat Intelligence Correlation**:
   - Matches MD5, SHA1, and SHA256 hex strings against built-in and user-customizable known malicious threat catalogues, assigning immediate `CRITICAL` risk ratings.

7. **Forensic Data Models (`src/eft/models/memory_forensics.py`)**:
   - Strongly-typed Pydantic models: `MemoryIoCType`, `MemoryIoCMatch`, and `MemoryPatternReport`.

---

## Verification & Quality Gates
- **Unit Tests**: 9 comprehensive unit tests in `tests/test_memory_ioc_matcher.py` covering IPv4/IPv6, GeoIP/Tor enrichment, URLs, emails, BTC/ETH wallets, JWT parsing, private keys, Base64 MZ headers, PowerShell decoding, threat hashes, and full streaming dump reports.
- **Full Test Suite**: 359 tests passing across the repository with 89% overall code coverage.
- **Code Coverage**: `src/eft/analysis/memory_ioc_matcher.py` achieves 90% statement coverage.
- **Linting & Formatting**: 100% clean with `ruff check` and `ruff format`.
- **Type Checking**: 100% clean with `mypy src tests` (0 errors across 105 files).
- **Packaging**: Verified via `poetry build` (`eft-1.3.0.tar.gz` and `eft-1.3.0-py3-none-any.whl`).
