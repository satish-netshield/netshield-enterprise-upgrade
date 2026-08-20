# NetShield Phase 3 Engineering Handbook

## Welcome

Welcome to the NetShield Phase 3 Engineering Handbook.

This handbook explains the engineering approach used while building NetShield Phase 3. It is written in plain English for learners who want to understand the important decisions, lessons and improvements without reading every project file.

It complements the README by focusing on the engineering journey rather than explaining every technical detail.

This version records the work completed through Stage 2.

## Engineering Goals

The goal of NetShield Phase 3 is to build a security automation platform inside a controlled Ubuntu sandbox.

The project is being developed one stage at a time. Each stage must be built, tested, understood, documented and validated before moving to the next.

Stage 1 created the safe environment and access controls.

Stage 2 created the security data pipeline needed to collect, validate, normalise and store events for later detection.

The remaining stages will build detections, correlation, incident handling and controlled response on top of this foundation.

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
- Prevent duplicate accepted records.
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

## Major Engineering Decisions

The following decisions helped keep the project safe, simple and reliable.

- Ubuntu VirtualBox was used to keep testing separate from the Windows host and public systems.
- The Python standard library was used for the first two stages to keep the foundation small and easy to inspect.
- SQLite was selected because it is lightweight and suitable for a single-VM lab.
- JSON configuration files were used so project rules could be changed without rewriting the main program logic.
- Default deny was used so unknown roles, permissions, actions and event sources were not trusted automatically.
- RBAC was used to separate Viewer, Analyst, Responder and Administrator permissions.
- The automation ACL separated automatic, approval-required and manual-only actions.
- CYOD was selected because an approved device inventory is easier to test and explain than unrestricted BYOD.
- JSONL was selected because each event can be processed one line at a time.
- Event timestamps were converted to UTC so later stages can use one investigation timeline.
- Invalid input was preserved with a failure reason instead of being deleted silently.
- Duplicate events were prevented from entering the accepted-event table.
- Accepted events retained their original JSON as well as their normalised values.
- Import batches were recorded so accepted and rejected totals could be checked.
- Parameterised SQL was used so event values were treated as data rather than SQL instructions.

## Improvements Made

The project improved as Stage 2 was added to the Stage 1 foundation.

- Expanded the original SQLite schema to store security events.
- Added separate storage for rejected records.
- Added import-batch tracking.
- Added indexes for common event searches.
- Added validation for timestamps, IP addresses, MAC addresses and CPU values.
- Added checks to confirm that the event source matches the source filename.
- Added duplicate-event protection.
- Added raw-event preservation.
- Added isolated pipeline tests using temporary databases.
- Added a complete Stage 2 validator.
- Re-ran the Stage 1 tests after the pipeline changes.
- Confirmed that Stage 2 did not break the Stage 1 security controls.
- Updated the project documentation to match the implemented pipeline.

## Testing Results

The current project testing produced these results:

- 11 Stage 1 access-control tests passed.
- 11 Stage 2 normalisation tests passed.
- 6 Stage 2 pipeline tests passed.
- 28 unit tests passed in total.
- Stage 1 validation passed 12/12.
- Stage 2 validation passed 14/14.

The first Stage 2 import processed 19 simulated records:

- 15 valid records were accepted.
- 4 deliberately malformed records were rejected.
- Each of the five event sources stored 3 accepted records.

## Lessons Learned

The first two stages have already provided several useful engineering lessons.

- A safe foundation should be built before adding detection or automated response.
- Configuration files make security rules easier to review and change.
- Normalised data is easier to search and compare than inconsistent raw data.
- UTC timestamps are important when events come from different locations.
- Invalid data should be preserved and explained rather than silently ignored.
- One malformed JSONL record does not need to stop the complete file import.
- Duplicate prevention protects the accuracy of later detections.
- Unit tests can check individual decisions without changing the working database.
- Revalidating Stage 1 helped confirm that Stage 2 did not introduce a regression.
- Real test failures and rejected records provide useful engineering evidence.
- Asking why each component exists makes the project easier to understand.
- Documentation is easier to maintain when it is updated with the actual work.

## Future Expansion

Stage 1 and Stage 2 provide the foundation for the remaining NetShield Phase 3 stages.

Future work will include:

- Identity and authentication detection
- Impossible-travel investigation
- Network, CYOD and Wi-Fi detection
- WPA3 policy checks
- Endpoint and high-CPU monitoring
- Local SQL injection testing
- Event correlation and risk scoring
- Indicator of Compromise extraction
- Incident records and evidence handling
- Controlled containment
- Eradication and recovery
- Complete project validation and sign-off

The next stage will use the accepted authentication events to build identity and authentication detections.
