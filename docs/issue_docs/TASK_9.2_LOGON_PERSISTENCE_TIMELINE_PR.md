# Task 9.2: Logon Anomaly, Privilege Escalation & Persistence Timeline Engine

## Summary of Changes
Implemented the forensic **Logon Anomaly, Privilege Escalation & Persistence Timeline Engine** (`WindowsSecurityAnalyzer`) in pure Python, enabling automated DFIR triage of Windows Security and System logs without external Windows host APIs or native dependencies.

### Key Capabilities & Architectural Components
1. **Windows Security Event Log Analyzer (`WindowsSecurityAnalyzer`)**:
   - Parses and correlates Windows Security & System event records:
     - **Event 4624 (Logon Success)**: Analyzes Logon Types (Type 2 Interactive, Type 3 Network, Type 4 Batch, Type 5 Service, Type 7 Unlock, Type 8 NetworkCleartext, Type 9 NewCredentials, Type 10 RemoteInteractive/RDP, Type 11 CachedInteractive).
     - **Event 4625 (Logon Failure)**: Maps NTSTATUS SubStatus codes (e.g. `0xC000006A` bad password, `0xC0000064` user does not exist, `0xC0000234` account locked out, `0xC0000072` account disabled).
     - **Event 4672 (Special Privileges Assigned)**: Tracks administrative rights elevation (`SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`).
     - **Event 7045 / 4697 (Service Installed / Attempt)**: Detects service persistence artifacts, account contexts, and image paths.
     - **Event 4698 / 4702 (Scheduled Task Created / Updated)**: Extracts task XML definitions, actions, execution commands, and user credentials.
     - **Event 4720 (User Created)**: Tracks rogue account provisioning.
     - **Event 4728 / 4732 / 4756 (Security Group Member Added)**: Detects privilege escalation into `Administrators`, `Domain Admins`, `Enterprise Admins`, `Remote Desktop Users`, etc.
2. **Behavioral Threat & Anomaly Detectors**:
   - **Brute Force & Account Compromise (`T1110.001`)**: Correlates burst failed logon attempts (>5) against a single account, escalating to `CRITICAL` severity if followed by a successful authentication compromise.
   - **Password Spraying (`T1110.003`)**: Identifies single IP addresses targeting multiple distinct accounts with authentication failures.
   - **Pass-the-Hash / Overpass-the-Hash (`T1550.002`)**: Flags Logon Type 9 (`NewCredentials`) via `seclogo` or NTLM packages.
   - **Cleartext Network Authentication (`T1040`)**: Identifies Logon Type 8 (`NetworkCleartext`) transmissions.
   - **Suspicious Windows Service Persistence (`T1543.003`)**: Identifies services invoking script interpreters (`powershell.exe`, `cmd.exe`, `wscript.exe`), download cradles (`certutil`, `mshta`), or residing in writable directories (`AppData`, `Temp`, `Public`, `PerfLogs`).
   - **Suspicious Scheduled Task Persistence (`T1053.005`)**: Flags tasks executing obfuscated or encoded commands.
   - **Rogue Account Creation & Privilege Escalation (`T1136.001 / T1098`)**: Correlates new user creation with immediate addition to privileged security groups.
3. **Master Forensic Timeline Synthesis**:
   - Converts all security events, authentication transitions, service installations, and group modifications into canonical UTC `TimelineEvent` objects with delta timing calculations and anomaly attribution.
4. **Forensic Data Models (`src/eft/models/logon_persistence.py`)**:
   - Strongly-typed Pydantic models: `WindowsLogonType`, `SecurityThreatClassification`, `LogonEvent`, `PrivilegeAssignedEvent`, `ServiceInstalledEvent`, `ScheduledTaskEvent`, `AccountManagementEvent`, `SecurityAnomalyAlert`, and `SecurityLogonReport`.

---

## Verification & Quality Gates
- **Unit Tests**: 11 dedicated unit test suites in `tests/test_logon_persistence_analyzer.py` covering all event IDs, logon types, brute force correlation, PtH, persistence mechanisms, privilege escalation, and timeline synthesis.
- **Full Test Suite**: 328 tests passing across the repository with 89% overall code coverage.
- **Linting & Formatting**: 100% clean with `ruff check` and `ruff format`.
- **Type Checking**: 100% clean with `mypy src tests` (0 errors across 97 files).
- **Packaging**: Verified via `poetry build` (`eft-1.3.0.tar.gz` and `eft-1.3.0-py3-none-any.whl`).
