# NetShield Enterprise Upgrade Engineering Handbook

## Welcome

This handbook explains the engineering journey behind the NetShield Enterprise Upgrade, also known as Phase 3A V2.

It is for someone who wants to understand the project without reading every Python file, database table or test.

The README presents the project and its results. This handbook focuses on the main decisions, improvements and lessons from building it.

Phase 3A V2 continues from the completed NetShield Phase 3 Automation project. It remains a Python and SQLite project inside a controlled Ubuntu VirtualBox sandbox.

Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design concepts only. No Microsoft services or real enterprise actions are used.

## Engineering Goals

The goal is to extend NetShield with enterprise security concepts without losing the controls already built in Phase 3.

The current work aims to:

- Preserve the existing Phase 3 foundation.
- Add simulated enterprise users, devices, applications and services.
- Process more enterprise-style security events.
- Improve device and asset identity.
- Preserve evidence and audit records.
- Reject malformed and duplicate data.
- Keep testing safe and repeatable.
- Confirm that earlier components still work.

The project follows a simple approach:

1. Understand the existing component.
2. Add one limited improvement.
3. Test it independently.
4. Run it with the existing project.
5. Review the actual result.
6. Correct genuine problems.
7. Test again.
8. Update the relevant documentation.

## Engineering Principles

### Continue from existing work

Phase 3A V2 extends NetShield instead of redesigning it.

Existing roles, permissions, logging, evidence controls and response boundaries remain in place unless a genuine engineering reason requires a change.

### Build in controlled stages

Each stage has a separate purpose.

Stage 1 extends the project foundation. Stage 2 extends the security data pipeline. Stage 3 adds enterprise device and asset identity.

### Validate before trusting

Events and inventory records are checked before they are used.

Invalid records remain outside the accepted-event table, and repeated records are not accepted again.

### Preserve evidence

Original event data is retained for investigation.

Sensitive values can be masked in suitable output without silently changing the original evidence.

### Correct genuine problems

A failed test is investigated before making a change.

The implementation is corrected when its behaviour is wrong. A test or validator is corrected when its expectation does not match the intended project behaviour.

### Maintain compatibility

New work must not break completed Phase 3 controls.

The full test suite and earlier validators are run again after important changes.

## What Was Built

### Enterprise foundation

The existing foundation was extended with:

- Simulated enterprise users.
- Simulated devices, applications and services.
- Existing Viewer, Analyst, Responder and Administrator roles.
- Data-retention settings.
- Sensitive-field masking.
- Enterprise upgrade metadata.
- Continued sandbox and approval boundaries.

### Extended security data pipeline

The pipeline was extended to accept:

- Identity-risk events.
- Access-policy decisions.
- Database events.
- Vulnerability findings.
- Incident events.
- Response events.

The original event sources remain supported.

The pipeline also gained schema-version identification, additional investigation fields, malformed-event quarantine and file-level failure reporting.

### Enterprise device identity

The CYOD inventory was extended with asset, ownership, system, registration, compliance, risk and last-seen information.

Device ID and asset ID provide the main references. MAC address, IP address, hostname, username and location provide supporting evidence.

The project can distinguish unknown, unregistered, stale and mismatched devices.

Registration changes and device-alert reviews are recorded for later investigation.

## Major Engineering Decisions

### Keep NetShield as one project

The enterprise upgrade reuses the completed Phase 3 foundation.

This keeps the project connected and avoids creating a second set of security controls.

### Keep enterprise platforms as concepts

Microsoft security products help explain the ideas being studied, but the implementation remains local Python and SQLite.

This keeps the project safe and makes the underlying logic easier to understand.

### Upgrade the database safely

Changing the tracked schema does not modify an existing SQLite database.

A repeatable migration was added so the working database could be extended without deleting earlier data.

### Keep one approved device source

The tracked CYOD inventory remains the authoritative approved-device record.

Enterprise context must agree with that inventory before a device is treated as registered and approved.

### Use several pieces of device evidence

A MAC address can be changed or spoofed.

Device ID and asset ID therefore provide the main references, while network and user information support the investigation.

### Keep tests portable

Unit tests should not depend on runtime files from one machine.

Sanitised fixtures were added so inherited tests could run without copied runtime outputs or machine-specific paths.

## Improvements Made

Several genuine improvements were made during testing:

- A missing registered device was added to the authoritative CYOD inventory.
- Compound event-source names were identified correctly.
- A repeatable migration was added for the existing database.
- Validators were corrected to support approved V2 sources and distinct malformed evidence.
- File-level ingestion failures were recorded separately from invalid records.
- Sanitised fixtures removed the test dependency on ignored runtime files.
- Device detection stopped treating database and web assets as endpoint devices.
- Known unregistered devices were separated from completely unknown devices.
- Compatible location labels were normalised to reduce unnecessary alerts.
- Earlier Phase 3 approval information was preserved in the extended inventory.
- Required local file permissions were reapplied and verified after repository separation.

These changes came from actual test failures and inspection of stored results.

## Lessons Learned

The project produced several useful engineering lessons:

- Existing projects need upgrades that preserve earlier data and controls.
- A tracked schema and a working database must both be considered.
- Authoritative records help prevent conflicting security decisions.
- Device identity should not depend on one changeable value.
- Similar context values may require careful normalisation.
- Known, unregistered and unknown devices require different decisions.
- Tests can contain incorrect assumptions as well as implementations.
- Repeated runs help confirm migrations and duplicate protection.
- Full regression testing is important after compatibility changes.
- Stored evidence is more reliable than a summary line alone.
- Documentation should describe only work that has been built and tested.

The current project results are:

- V2 Stage 1 validation passed 12 out of 12 checks.
- V2 Stage 2 validation passed 13 out of 13 checks.
- V2 Stage 3 validation passed 19 out of 19 checks.
- The V2 Stage 1–3 test group passed 31 tests.
- The complete project passed 116 unit tests.
- The original Phase 3 full-project validation passed.

## Future Expansion

The next work can use the existing identity, device, location, application and risk context when making local access decisions.

Later stages can extend detection, correlation, vulnerability handling, incident investigation, controlled response and recovery verification.

The implementation will remain local and simulated unless a future project explicitly introduces an approved integration.

The same working method will continue: build a limited component, test it, review the evidence, correct genuine problems and keep the documentation aligned with the project.
