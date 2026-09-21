# Task 9.1: Binary EVTX Parser & Sysmon Event Correlation Engine

## Summary of Changes
Implemented a pure-Python forensic Windows Event Log (`.evtx`) parser and Microsoft Sysmon event correlation engine without external native C/Windows OS dependencies.

### Key Capabilities & Architectural Components
1. **Binary EVTX Format Parser (`WindowsLogAnalyzer`)**:
   - Parses ELF binary EVTX format: File Header (`ElfFile\x00`, 4096 bytes), Chunk Headers (`ElfChnk\x00`, 65536 bytes), and Record Headers (`0x00002A2A` / `\x2a\x2a\x00\x00`).
   - Converts 64-bit Windows `FILETIME` nanosecond timestamps to ISO 8601 UTC `datetime`.
   - Pure-Python `BinXml` string and token extraction supporting UTF-16LE, ASCII, and XML fragment parsing.
   - Robust carving fallback for damaged or fragmented log files.
2. **Canonical Forensic Data Models (`src/eft/models/evtx.py`)**:
   - `SysmonEventType`: Enum covering Process Creation (1), Network Connect (3), Image Load (7), File Create (11), Security Process Creation (4688), etc.
   - `ProcessThreatClassification`: Categorized threats including Office Macro Spawns, Web Shells, LOLBAS, Suspicious Services, and Credential Dumping.
   - `SysmonProcessCreateEvent`, `SysmonNetworkEvent`, `SysmonImageLoadEvent`, `SysmonFileCreateEvent`.
   - `ProcessTreeNode`: Hierarchical tree linking parent to child processes with correlated network flows, loaded DLLs, created files, and behavioral anomalies.
   - `SuspiciousProcessAnomaly`: Actionable alert containing MITRE ATT&CK techniques and severity ratings.
   - `EVTXAnalysisReport`: Comprehensive DFIR report with timeline bounding, unique entity summaries, forensic threat scoring, and remediation guidance.
3. **Behavioral Anomaly & LOLBAS Detection Engine**:
   - **Office Macro Spawns (`T1204.002`)**: Detects `winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, etc. spawning interactive shells (`cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, etc.).
   - **Web Shell Spawns (`T1505.003`)**: Detects web servers (`w3wp.exe`, `httpd.exe`, `nginx.exe`, `tomcat.exe`, `php-cgi.exe`) spawning execution children.
   - **Critical System Service Spawns**: Detects `spoolsv.exe`, `services.exe`, `smss.exe`, `lsass.exe` spawning shells.
   - **LOLBAS Abuse Patterns**:
     - `certutil.exe` with `-urlcache`, `-split`, `-f` (`T1105 - Ingress Tool Transfer`).
     - `mshta.exe` executing inline `javascript:` / `vbscript:` or remote SCT scripts (`T1218.005`).
     - `regsvr32.exe` Squiblydoo scriptlet execution with `/s /u /i:` (`T1218.010`).
     - `rundll32.exe` executing inline scripts or suspicious DLL entrypoints (`T1218.011`).
     - `bitsadmin.exe` transfer jobs (`T1197`).
     - Volume shadow copy deletion via `vssadmin` or `wmic` (`T1490`).
   - **Obfuscated / Encoded Commands (`T1059.001`)**: Detects PowerShell `-enc`, `-w hidden`, `-ep bypass`, `downloadstring`, `iex`.
   - **Credential Dumping (`T1003`)**: Detects `procdump`, `comsvcs.dll` `MiniDump`, `mimikatz`, LSASS targeting.

---

## Verification & Quality Gates
- **Unit Tests**: 15 dedicated unit tests in `tests/test_evtx_analyzer.py` covering binary headers, chunk offset tables, BinXml UTF-16 extraction, carving damaged logs, Sysmon 1/3/7/11 events, Security 4688, and all threat detection rules.
- **Full Test Suite**: 317 tests passing across the repository with 88% overall code coverage.
- **Linting & Formatting**: Clean run with `ruff check` and `ruff format`.
- **Type Safety**: Passed `mypy src tests` with 0 issues.
- **Build**: Successfully packaged via `poetry build` (`eft-1.3.0.tar.gz` and `eft-1.3.0-py3-none-any.whl`).
