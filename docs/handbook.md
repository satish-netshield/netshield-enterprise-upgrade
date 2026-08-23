# NetShield Phase 3 Engineering Handbook

## Welcome

Welcome to the NetShield Phase 3 Engineering Handbook.

This handbook explains the engineering approach used while building NetShield Phase 3. It is written in plain English for learners who want to understand the important decisions, lessons and improvements without reading every project file.

It complements the README by focusing on the engineering journey rather than explaining every technical detail.

This version records the work completed through Stage 5.

## Engineering Goals

The goal of NetShield Phase 3 is to build a security automation platform inside a controlled Ubuntu sandbox.

The project is developed one stage at a time. Each stage is built, tested, understood, documented and validated before the next stage begins.

Stage 1 created the safe environment and access controls.

Stage 2 created the security data pipeline needed to collect, validate, normalise and store events.

Stage 3 added identity and authentication detection.

Stage 4 added network, CYOD and Wi-Fi detection with MAC-based correlation.

Stage 5 added endpoint monitoring, CPU checks and wired-LAN access detection.

The remaining stages will add further correlation, incident handling and controlled response.

## Engineering Principles

The following principles guide the project:

- Understand before changing.
- Build one stage at a time.
- Test every component.
- Use default deny.
- Follow least privilege.
- Keep disruptive actions controlled.
- Preserve original evidence.
- Reject invalid or inconsistent data.
- Prevent duplicate records and alert flooding.
- Revalidate earlier work after changes.
- Fix genuine issues only.
- Record meaningful engineering decisions.
- Keep documentation aligned with the implementation.
- Let Git history reflect the engineering process.
- Write as the engineer who built the project.
- Keep the writing simple, honest and technically accurate.

## What Was Built

The following components have been completed.

### Stage 1 — Environment and Access Control

- Ubuntu VirtualBox sandbox
- Python virtual environment
- Project configuration
- SQLite database
- Application and audit logging
- File and directory permissions
- Viewer, Analyst, Responder and Administrator roles
- Role-Based Access Control
- CYOD device allowlist
- IP allowlist and simulated blocklist
- Automation-action ACL
- Evidence hashing and protection
- Stage 1 tests and validation

### Stage 2 — Security Data Pipeline

- Safe simulated security events
- Authentication, network, Wi-Fi, endpoint and application sources
- JSONL event collector
- Event validation and normalisation
- UTC timestamp handling
- Accepted-event storage
- Rejected-event storage
- Duplicate-event protection
- Import-batch tracking
- Raw-event preservation
- Stage 2 tests and validation

### Stage 3 — Identity and Authentication Detection

- Configurable identity-detection rules
- Repeated failed-login detection
- Possible brute-force detection
- Successful login after repeated failures
- MFA failure anomaly detection
- New-device detection
- Unusual-location detection
- Impossible-travel detection
- Suspicious role-change detection
- Known VPN exceptions
- Duplicate-alert protection
- False-positive investigation
- Identity-alert storage and audit records
- Stage 3 tests and validation

### Stage 4 — Network, CYOD and Wi-Fi Detection

- Controlled network and Wi-Fi event generation
- Suspicious IP detection
- Repeated connection detection
- Port-scanning detection
- Unknown CYOD and unregistered MAC detection
- MAC reuse or possible spoofing detection
- Wi-Fi zone checks
- WPA3 policy checks
- WPA2 downgrade detection
- Rogue access-point detection
- MAC-based alert correlation
- Duplicate-alert protection
- Stage 4 tests and validation

### Stage 5 — Endpoint and Wired-LAN Detection

- Controlled endpoint and wired-LAN event generation
- Endpoint CPU monitoring
- Approved and unauthorised CPU stress-test handling
- Repeated high-CPU activity detection
- Unknown endpoint-process detection
- Restricted wired-access detection
- Simulated Server Room privilege checks
- Endpoint-alert storage
- MAC-based endpoint correlation
- Repeated wired-observation grouping
- Duplicate-alert protection
- Stage 5 tests and validation

## Major Engineering Decisions

The following decisions kept the project safe, simple and easy to test:

- Ubuntu VirtualBox keeps testing separate from the Windows host and public systems.
- The Python standard library keeps the foundation small and easy to inspect.
- SQLite suits this single-VM learning environment.
- JSON configuration keeps security rules separate from program logic.
- Default deny prevents unknown roles, actions, sources and values from being trusted.
- CYOD provides a controlled device inventory for testing.
- The MAC address is the primary device-matching value, while IP, hostname, user and location provide supporting evidence.
- JSONL allows one malformed record to be rejected without stopping the complete file.
- Network, Wi-Fi, endpoint and wired-LAN files follow the existing source-type validation rules.
- Network and endpoint evidence is correlated after successful validation and storage.
- UTC timestamps provide one timeline for events from different sources and locations.
- Invalid input is preserved with a reason instead of being silently deleted.
- Alert keys prevent repeated detector runs from creating duplicate alerts.
- Repeated observations are grouped only when they belong to the same device and detection context.
- Approved CPU stress testing is recognised so legitimate testing is not reported as suspicious.
- Disruptive actions require verification and approval.
- A rogue access point is detected but not automatically stopped because shutdown requires approval.

## Improvements Made

The project improved as each stage was added:

- Expanded the SQLite schema for security events, identity alerts, network alerts and endpoint alerts.
- Added rejected-event and import-batch tracking.
- Added validation for timestamps, IP addresses, MAC addresses and CPU values.
- Added source-type verification.
- Added raw-event preservation.
- Added identity detection and false-positive investigation.
- Added network and Wi-Fi detection rules.
- Added MAC-focused alert correlation.
- Added detection for MAC reuse or possible spoofing.
- Added controlled test events for repeated connections and wireless policy violations.
- Added endpoint CPU and process detection.
- Added restricted wired-access detection.
- Added simulated role mappings for endpoint and Server Room testing.
- Added grouping for repeated restricted wired observations.
- Corrected the Stage 2 validator scope after Stage 3 added authentication events.
- Corrected Stage 4 file generation after Wi-Fi records were rejected from a mixed source file.
- Corrected the Stage 4 SQL placeholder count when four source files were supplied.
- Corrected Stage 3 initialisation so Stage 4 setup did not reset completed Stage 3 metadata.
- Corrected the Stage 5 wired-event filename so it matched the `network` source type.
- Added the Stage 5 endpoint-alert table to the tracked database schema.
- Corrected MAC-reuse logic so a location change alone does not create a spoofing alert.
- Re-ran earlier tests and validators after the Stage 5 changes.

## Testing Results

The completed regression run produced these results:

- 11 Stage 1 access-control tests passed.
- 11 Stage 2 normalisation tests passed.
- 6 Stage 2 pipeline tests passed.
- 11 Stage 3 identity-detection tests passed.
- 5 Stage 4 network-correlation tests passed.
- 8 Stage 5 endpoint-detection tests passed.
- 52 unit tests passed in total.
- Stage 1 validation passed 12/12.
- Stage 2 validation passed 14/14.
- Stage 3 validation passed 12/12.
- Stage 4 validation passed 12/12.
- Stage 5 validation passed 12/12.

Stage 5 accepted 14 events and produced 10 endpoint alerts.

The repeated detector run created no new duplicate alerts. Approved CPU stress testing, repeated high-CPU activity, unknown processes, restricted wired access and MAC-reuse safeguards were verified.

## Lessons Learned

The first five stages have provided several useful lessons:

- A safe foundation should be built before detection or automated response.
- Normalised data is easier to search and compare than inconsistent raw data.
- Source validation should happen before cross-source correlation.
- Network, Wi-Fi, endpoint and wired-LAN sources can be correlated without placing them in the same input file.
- A MAC address is useful for device matching but can be copied or spoofed.
- Hostname, username and event time are needed to support a MAC-reuse decision.
- A restricted location is evidence for investigation, not automatic proof of compromise.
- Approved activity must be represented in the test data so it is not incorrectly reported.
- High CPU usage is not automatically malicious.
- Repeated observations should be grouped without combining different devices.
- A security alert is not always proof of malicious activity.
- Duplicate protection reduces alert noise but does not replace continuous monitoring.
- Real test failures show where components do not connect correctly.
- Earlier validators must be checked when later stages add new data.
- A tracked schema is important because runtime initialization alone can hide setup problems.
- Documentation should be updated from the actual implementation and test results.

## Future Expansion

Stages 1–5 provide the foundation for the remaining NetShield Phase 3 work.

Future expansion will include:

- Last-seen and observation-count tracking
- Inventory verification requests
- Switch-port and VLAN authorisation
- More endpoint process baselines
- Correlation between identity, network and endpoint evidence
- Local SQL injection testing
- Indicator of Compromise extraction
- Incident records and evidence handling
- Controlled containment
- Eradication and recovery
- Complete clean-state project validation and sign-off
