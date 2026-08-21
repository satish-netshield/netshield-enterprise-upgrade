# NetShield Phase 3 Engineering Handbook

## Welcome

Welcome to the NetShield Phase 3 Engineering Handbook.

This handbook explains the engineering approach used while building NetShield Phase 3. It is written in plain English for learners who want to understand the important decisions, lessons and improvements without reading every project file.

It complements the README by focusing on the engineering journey rather than explaining every technical detail.

This version records the work completed through Stage 3.

## Engineering Goals

The goal of NetShield Phase 3 is to build a security automation platform inside a controlled Ubuntu sandbox.

The project is being developed one stage at a time. Each stage must be built, tested, understood, documented and validated before moving to the next.

Stage 1 created the safe environment and access controls.

Stage 2 created the security data pipeline needed to collect, validate, normalise and store events.

Stage 3 added identity and authentication detection using the accepted authentication events.

The remaining stages will add network and Wi-Fi detection, correlation, incident handling and controlled response.

## Engineering Principles

The following engineering principles guide the project:

- Understand before changing.
- Build one stage at a time.
- Test every component.
- Use default deny.
- Follow least privilege.
- Keep disruptive actions controlled.
- Preserve original evidence.
- Reject invalid or inconsistent data.
- Prevent duplicate accepted records and alert flooding.
- Revalidate earlier work after changes.
- Fix genuine issues only.
- Record meaningful engineering decisions.
- Keep documentation aligned with the implementation.
- Let Git history reflect the engineering process.
- Write as the engineer who built the project.
- Keep the writing simple, honest, technically accurate and easy to learn from.

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
- Stage 1 unit tests and validation

### Stage 2 — Security Data Pipeline

- Safe simulated security events
- Authentication event source
- Network event source
- Wi-Fi and CYOD event source
- Endpoint and CPU event source
- Application event source
- JSONL event collector
- Event validation and normalisation
- Accepted security-event storage
- Rejected-event storage
- Duplicate-event protection
- Import-batch tracking
- Raw-event preservation
- Stage 2 unit tests and validation

### Stage 3 — Identity and Authentication Detection

- Configurable identity-detection rules
- Simulated authentication scenarios
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
- Stage 3 unit tests and validation

## Major Engineering Decisions

The following decisions helped keep the project safe, simple and reliable.

- Ubuntu VirtualBox was used to keep testing separate from the Windows host and public systems.
- The Python standard library was used to keep the foundation small and easy to inspect.
- SQLite was selected because it is lightweight and suitable for a single-VM lab.
- JSON configuration files were used so project rules could be changed without rewriting the main program logic.
- Default deny was used so unknown roles, permissions, actions and event sources were not trusted automatically.
- RBAC was used to separate Viewer, Analyst, Responder and Administrator permissions.
- The automation ACL separated automatic, approval-required and manual-only actions.
- CYOD was selected because an approved device inventory is easier to test and explain than unrestricted BYOD.
- JSONL was selected because each event can be processed one line at a time.
- Event timestamps were converted to UTC so later stages can use one investigation timeline.
- Invalid input was preserved with a failure reason instead of being deleted silently.
- Duplicate events and duplicate alerts were prevented from flooding accepted records.
- Accepted events retained their original JSON as well as their normalised values.
- Identity rules were kept configurable so thresholds can be tuned after testing.
- Known VPN addresses were treated as exceptions for selected baseline and travel checks.
- A new-device alert was investigated instead of automatically containing the device.
- The approved replacement device was classified as a false positive because inventory registration was incomplete.
- Parameterised SQL was used so event values were treated as data rather than SQL instructions.

## Improvements Made

The project improved as each stage was added.

- Expanded the original SQLite schema to store security events and identity alerts.
- Added separate storage for rejected records.
- Added import-batch tracking and search indexes.
- Added validation for timestamps, IP addresses, MAC addresses and CPU values.
- Added source-type verification.
- Added duplicate-event protection.
- Added raw-event preservation.
- Added isolated pipeline tests using temporary databases.
- Added identity detection tests for thresholds, travel, VPN exceptions and role changes.
- Added duplicate-alert protection for repeated detector runs.
- Added false-positive classification with investigation notes and audit records.
- Corrected the Stage 2 validator so new Stage 3 authentication events did not break earlier validation.
- Re-ran all earlier tests after the Stage 3 changes.
- Confirmed that Stage 3 did not break the Stage 1 or Stage 2 security controls.
- Updated the project documentation to match the implemented stages.

## Testing Results

The current project testing produced these results:

- 11 Stage 1 access-control tests passed.
- 11 Stage 2 normalisation tests passed.
- 6 Stage 2 pipeline tests passed.
- 11 Stage 3 identity-detection tests passed.
- 39 unit tests passed in total.
- Stage 1 validation passed 12/12.
- Stage 2 validation passed 14/14.
- Stage 3 validation passed 12/12.

Stage 2 processed 19 simulated records:

- 15 valid records were accepted.
- 4 deliberately malformed records were rejected.
- Each original Stage 2 source stored 3 accepted events.

Stage 3 processed 16 additional authentication events and produced 11 identity alerts.

The second detection run created no duplicate alerts. The approved replacement-device alert was preserved and classified as a false positive.

## Lessons Learned

The first three stages have provided several useful engineering lessons.

- A safe foundation should be built before adding detection or automated response.
- Configuration files make security rules easier to review and change.
- Normalised data is easier to search and compare than inconsistent raw data.
- UTC timestamps are important when events come from different locations.
- Invalid data should be preserved and explained rather than silently ignored.
- One malformed JSONL record does not need to stop the complete file import.
- Duplicate protection prevents repeated detector runs from flooding the system.
- Duplicate protection also needs future last-seen tracking for unresolved conditions.
- A security alert is not always proof of malicious activity.
- A legitimate replacement device can appear suspicious when inventory registration is incomplete.
- Impossible travel and MFA anomalies should be correlated before final severity is assigned.
- Unit tests and validation should be repeated after every major stage.
- A validator must check the correct scope when later stages add new data.
- Real test failures and rejected records provide useful engineering evidence.
- Asking why each component exists makes the project easier to understand.
- Documentation is easier to maintain when it is updated with the actual work.

## Future Expansion

Stages 1, 2 and 3 provide the foundation for the remaining NetShield Phase 3 stages.

Future work will include:

- Network, CYOD and Wi-Fi detection
- Device consistency checks
- Suspicious IP and port-scanning detection
- WPA3 policy checks
- WPA2 downgrade attempts
- Wi-Fi heat-map zone investigation
- Unknown wired and wireless device detection
- Endpoint and high-CPU monitoring
- Local SQL injection testing
- Event correlation and risk scoring
- Indicator of Compromise extraction
- Incident records and evidence handling
- Inventory verification requests
- Controlled containment
- Eradication and recovery
- Complete clean-state project validation and sign-off
