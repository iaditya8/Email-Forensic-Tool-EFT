# Task 9.3: Cloud Audit Log Ingestion (M365 & Google Workspace)

## Summary of Changes
Implemented the **Cloud Audit Log Ingestion & Threat Detection Engine** (`CloudAuditAnalyzer`) in pure Python, enabling automated DFIR triage of Microsoft 365 Unified Audit Logs (UAL) and Google Workspace Admin / Login audit logs without external cloud SDKs or live network dependencies.

### Key Capabilities & Architectural Components
1. **Multi-Format Ingestion & Normalization (`CloudAuditAnalyzer`)**:
   - Ingests JSON (raw list, Google Reports API nested structure, NDJSON line-delimited) and CSV exports from Microsoft 365 and Google Workspace.
   - Computes multi-algorithm cryptographic hashes (MD5, SHA-256) over raw audit evidence files for strict ISO/IEC 27037 chain of custody preservation.
   - Automatically unrolls nested `AuditData` JSON payloads and parses key-value parameter lists across disparate cloud schema representations.

2. **Microsoft 365 Forensic Telemetry Extraction**:
   - **Exchange Item Operations**: Ingests `MailItemsAccessed`, `Send`, `SendAs`, `SendOnBehalf`, `Create`, `Update`, `Move`, `MoveToDeletedItems`, `SoftDelete`, `HardDelete`.
   - **Malicious Inbox Rule Modification (`T1114.003 / T1564.008`)**: Extracts `New-InboxRule`, `Set-InboxRule`, `Enable-InboxRule` actions and decodes forwarding (`ForwardTo`, `RedirectTo`) and defensive hiding actions (`MoveToFolder` to RSS Subscriptions/Junk/Trash, `DeleteMessage`, `MarkAsRead`).
   - **Mailbox Delegation Backdoors (`T1098.002`)**: Ingests `Add-MailboxPermission` / `Add-RecipientPermission` operations granting high-privilege access rights (`FullAccess`, `SendAs`, `SendOnBehalf`).
   - **OAuth Consent & Application Grants (`T1528 / T1550.001`)**: Ingests `Consent to application` records and parses delegated/application permissions.
   - **Entra ID / M365 Authentication Logs**: Tracks `UserLoggedIn` / `UserLoginFailed` telemetry with client IP, user agent, client app, and geolocation metadata.

3. **Google Workspace Forensic Telemetry Extraction**:
   - Ingests Google Workspace Admin and Login audit events (`login`, `admin`, `token`).
   - Ingests `CHANGE_USER_SETTING` (email auto-forwarding, POP/IMAP, delegation), `GRANT_ADMIN_PRIVILEGE`, `CREATE_USER`, `SUSPEND_USER`, and `AUTHORIZE_TOKEN`.

4. **Cloud Behavioral Threat Detection Engine**:
   - **M365 Malicious Forwarding Rule (`T1114.003`)**: Flags automated external forwarding rules configured to exfiltrate email data.
   - **M365 Email Concealment Rule (`T1564.008`)**: Identifies rules configured to delete or divert incoming security notices or executive emails.
   - **Privileged Mailbox Delegation Backdoor (`T1098.002`)**: Detects `FullAccess` or `SendAs` permission assignments to external or untrusted delegates.
   - **Illicit OAuth Consent Grant (`T1528`)**: Flags high-risk OAuth scopes (`Mail.ReadWrite`, `Mail.Send`, `MailboxSettings.ReadWrite`, `Files.ReadWrite.All`, `full_access`).
   - **Google Workspace Auto-Forwarding Routing Rule**: Identifies forwarding address changes in user settings.
   - **Google Workspace Admin Role Elevation (`T1098`)**: Flags administrative privilege grants.
   - **Impossible Travel & Multi-Geo Login Anomalies (`T1078.004`)**: Calculates geographic delta velocities between successive user authentications across distinct countries within impossible transit windows (<4 hours).

5. **Forensic Data Models (`src/eft/models/cloud_audit.py`)**:
   - Strongly-typed Pydantic models: `CloudProvider`, `CloudThreatClassification`, `M365InboxRuleRecord`, `M365MailboxPermissionRecord`, `CloudOAuthConsentRecord`, `CloudLoginRecord`, `GoogleAdminAuditEvent`, `CloudAnomalyAlert`, and `CloudAuditReport`.

---

## Verification & Quality Gates
- **Unit Tests**: 10 comprehensive unit test suites in `tests/test_cloud_audit_analyzer.py` validating M365 UAL JSON/CSV parsing, Google Workspace Reports API unpacking, inbox rule exfiltration detection, mailbox backdoors, illicit OAuth consent, impossible travel, and file hashing.
- **Full Test Suite**: 338 tests passing across the repository with 89% overall code coverage.
- **Code Coverage**: `src/eft/analysis/cloud_audit_analyzer.py` achieves 88% statement coverage.
- **Linting & Formatting**: 100% clean with `ruff check` and `ruff format`.
- **Type Checking**: 100% clean with `mypy src tests` (0 errors across 100 files).
- **Packaging**: Verified via `poetry build` (`eft-1.3.0.tar.gz` and `eft-1.3.0-py3-none-any.whl`).
