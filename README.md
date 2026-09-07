# NetShield Enterprise Upgrade — Phase 3A V2

NetShield Enterprise Upgrade extends the completed NetShield Phase 3 Automation project.

It remains a Python and SQLite security-automation project inside a controlled Ubuntu VirtualBox sandbox.

The upgrade applies enterprise security concepts to simulated users, devices, applications, services and events. Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design references only.

No Microsoft tenants, cloud resources, real enterprise connectors, external targets or production containment actions are used.

## Current Project Status

The current upgrade contains:

- Stage 1 — Enterprise project foundation
- Stage 2 — Extended security data pipeline
- Stage 3 — Enterprise asset and device identity

Stages 1 and 2 were developed and documented together because the foundation supports the extended pipeline. They remain separate stages with their own purpose and validation result.

The completed Phase 3 components remain available and operational. Their detailed implementation is documented in the original Phase 3 project. This README concentrates on the Phase 3A V2 upgrade.

## Technologies

- Ubuntu VirtualBox sandbox
- Python 3
- SQLite
- JSON and JSONL
- Git and GitHub
- Python `unittest`
- Application and audit logging
- SHA-256 evidence hashing

---

## Stage 1 — Enterprise Project Foundation

### What the component does

Stage 1 extends the existing Phase 3 foundation with simulated enterprise users, devices, applications and services.

It also adds data-retention settings, sensitive-field masking and enterprise-upgrade metadata.

### Why it exists or how it behaves

The enterprise upgrade needs a controlled foundation before adding new security decisions.

The existing Phase 3 RBAC, automation ACL, SQLite database, logging, evidence controls and sandbox boundaries are reused instead of being redesigned.

Simulated users use the existing Viewer, Analyst, Responder and Administrator roles. They do not create Ubuntu accounts or Microsoft Entra identities.

Registered devices must also exist in the authoritative CYOD inventory.

### Information, rules and capabilities

Stage 1 provides:

- Simulated enterprise users
- Simulated devices
- Simulated applications and services
- Existing application RBAC
- Existing automation-action ACL
- CYOD inventory consistency
- Data-retention settings
- Sensitive-field masking
- V2 project metadata
- Application and audit records
- Safe sandbox boundaries
- Phase 3 compatibility checks

Retention periods are configured for raw events, processed events, audit records and incident reports.

Automatic data expiry is not implemented yet.

Sensitive-field masking protects configured values in suitable reports and logs. Original evidence remains unchanged.

### Workflow

1. Load the existing project settings.
2. Load the simulated enterprise context.
3. Reuse the existing SQLite database and security controls.
4. Register the simulated users with the existing roles.
5. Confirm that registered devices exist in the CYOD inventory.
6. Apply retention and masking settings.
7. Store V2 metadata in SQLite.
8. Record the initialisation in the audit trail.
9. Check sensitive file and directory permissions.
10. Revalidate the original Phase 3 foundation.

### Observed example output

```text
PASS: Phase 3A V2 Stage 1 foundation initialised
Simulated users registered: 4
Simulated devices available: 3
Applications and services available: 5
```

```text
PASS: Existing and V2 foundation files exist
PASS: V2 upgrade extends the existing Phase 3 project
PASS: Enterprise users, devices, applications and services exist
PASS: Simulated users use valid RBAC roles
PASS: Retention and sensitive-field policies are valid
PASS: Sensitive fields are masked without changing safe fields
PASS: Controlled testing boundaries remain enabled
PASS: V2 metadata is stored in SQLite
PASS: Simulated enterprise roles are stored correctly
PASS: V2 foundation initialisation is audited
PASS: Sensitive filesystem permissions remain correct
PASS: Original Phase 3 Stage 1 remains compatible

V2 STAGE 1 VALIDATION: PASS (12/12)
```

### Testing Notes

The Stage 1 tests checked:

- Enterprise upgrade metadata
- Simulated enterprise entities
- Role compatibility
- CYOD inventory consistency
- Positive retention periods
- Nested sensitive-field masking
- Safe fields remaining unchanged
- Repeated initialisation
- Audit records
- Local file permissions
- Original Phase 3 compatibility

V2 Stage 1 passed 12 out of 12 validation checks.

The complete project contained 91 passing unit tests after the Stage 1 extension.

### Engineering observations

- `CYOD-002` was marked as registered in enterprise context but was missing from the authoritative CYOD inventory.
- The inventory was corrected and a consistency test was added.
- Running validators directly caused a project import failure. Running them as modules with `python -m` preserved the project package path.
- Nested SQL injection lab runtime files appeared as untracked files. The relevant paths were added to `.gitignore`.
- Restoring `settings.json` from Git changed its local permission because Git does not preserve detailed non-executable permission modes.
- The required `640` permission was reapplied and validated.

### What I Learned

An enterprise configuration should not create a second source of truth. Device registration, user roles and security settings must agree with the project’s existing authoritative records.

Local file permissions must also be checked after tracked files are restored.

---

## Stage 2 — Extended Security Data Pipeline

### What the component does

Stage 2 extends the existing event pipeline to process more enterprise-style security data.

It adds schema-version and source-system identification, more investigation fields, malformed-event quarantine, database migration and file-level failure reporting.

### Why it exists or how it behaves

Later security decisions depend on reliable data from several sources.

The pipeline validates each record before accepting it. Malformed, incorrectly labelled and duplicate records stay outside the accepted-event table.

The original Phase 3 event sources remain supported.

### Information, rules and capabilities

The original pipeline sources are:

- Authentication
- Network
- Wi-Fi
- Endpoint
- Application

Phase 3A V2 adds:

- Identity risk
- Access policy
- Database
- Vulnerability
- Incident
- Response

Each accepted event includes the common fields needed for identification and investigation.

Supported V2 information includes:

- Schema version
- Source system
- Unique event ID
- UTC event time
- Source and event type
- User and device context
- Asset, application and service references
- Severity and risk score
- Access decision
- Vulnerability finding ID
- Incident ID
- Response action ID
- Original raw event

The pipeline also provides:

- Required-field validation
- Data-type validation
- Source-to-filename checking
- Duplicate-event protection
- Malformed-event quarantine
- Normalised SQLite storage
- Investigation indexes
- Ingestion statistics
- Failed-batch recording
- Audit events

### Workflow

1. Inspect the existing SQLite database.
2. Add missing V2 columns and indexes through a repeatable migration.
3. Preserve existing Phase 3 data.
4. Generate separate JSONL files for each V2 source.
5. Identify the complete source name.
6. Create an ingestion batch.
7. Read one record at a time.
8. Validate the schema, source, required fields and data types.
9. Convert accepted timestamps to UTC.
10. Store the normalised event.
11. Preserve the original event.
12. Quarantine malformed records.
13. Reject duplicate events.
14. Record batch totals and file failures.
15. Write the pipeline audit record.

### Observed example output

```text
PASS: V2 Stage 2 database migration completed
Security-event columns added: 12
Rejected-event columns added: 1
```

Running the migration again produced:

```text
PASS: V2 Stage 2 database migration completed
Security-event columns added: 0
Rejected-event columns added: 0
```

The controlled event generation and import produced:

```text
PASS: Generated 14 V2 events
Source files: 6
Expected valid events: 12
Expected quarantined events: 2

access_policy_v2_events.jsonl: accepted=2 rejected=1 status=completed_with_rejections
database_v2_events.jsonl: accepted=2 rejected=0 status=completed
identity_risk_v2_events.jsonl: accepted=2 rejected=1 status=completed_with_rejections
incident_v2_events.jsonl: accepted=2 rejected=0 status=completed
response_v2_events.jsonl: accepted=2 rejected=0 status=completed
vulnerability_v2_events.jsonl: accepted=2 rejected=0 status=completed

V2 STAGE 2 IMPORT: files=6 total=14 accepted=12 rejected=2 failed=0
```

A repeated import produced:

```text
V2 STAGE 2 IMPORT: files=6 total=14 accepted=0 rejected=14 failed=0
```

Stage 2 validation produced:

```text
PASS: Six V2 JSONL files contain 14 records
PASS: Configuration and normaliser source types match
PASS: V2 common event fields exist in SQLite
PASS: Rejected events include quarantine status
PASS: V2 investigation indexes exist
PASS: Twelve valid V2 events are stored
PASS: All six V2 sources contain two accepted events
PASS: Two malformed V2 events are quarantined
PASS: All accepted V2 timestamps are stored in UTC
PASS: All accepted V2 events identify their source system
PASS: Original V2 events are preserved
PASS: V2 ingestion batches and statistics are recorded
PASS: V2 pipeline completion is audited

V2 STAGE 2 VALIDATION: PASS (13/13)
```

### Testing Notes

The Stage 2 tests checked:

- Original and V2 source compatibility
- Compound source identification
- Schema-version validation
- Source-system preservation
- UTC timestamps
- Risk-score limits
- Supported access decisions
- Required fields and data types
- Malformed-event quarantine
- Duplicate-event protection
- Raw-event preservation
- SQLite columns and indexes
- Ingestion totals
- Failed import batches

Six V2 files contained 14 events. Twelve valid events were accepted and two malformed events were quarantined.

Running the import again accepted no duplicate events.

A temporary unreadable file confirmed that a file-level failure is recorded as a failed batch.

V2 Stage 2 passed 13 out of 13 validation checks.

The complete project contained 98 passing unit tests after the Stage 2 extension.

### Engineering observations

- Compound names such as `identity_risk` were initially shortened to the first filename word.
- Source identification was corrected to recognise the complete supported source name.
- Updating `schema.sql` did not modify the existing SQLite database.
- A repeatable migration was added without deleting earlier data.
- Repeated imports created more database rejection rows for the same malformed inputs.
- The validator was corrected to count distinct malformed evidence.
- The original validator expected exactly five event sources.
- It was corrected to require the original five while allowing approved V2 sources.
- Some inherited tests depended on ignored Phase 3 runtime outputs.
- Sanitised fixtures were added so the tests could run without copied runtime data or machine-specific paths.

### What I Learned

A database upgrade must support both a clean database and a database that already contains project data.

Duplicate events, malformed records and complete file failures are different outcomes and must be recorded separately.

---

## Stage 3 — Enterprise Asset and Device Identity

### What the component does

Stage 3 adds stronger asset and device identity to the enterprise upgrade.

It extends the CYOD inventory, synchronises approved devices with SQLite and checks relevant V2 events for device-identity problems.

### Why it exists or how it behaves

A MAC address alone is not reliable proof of device identity because it can be changed, reused or spoofed.

Device ID and asset ID provide the main references. Hostname, assigned user, IP address, location and MAC address provide supporting context.

The detector separates known but unregistered devices from completely unknown devices.

### Information, rules and capabilities

Stage 3 supports:

- Extended CYOD inventory records
- Unique device IDs and asset IDs
- Registration status
- Compliance status
- Risk status
- Asset criticality
- Last-seen information
- Unknown-device detection
- Unregistered-device detection
- Stale-device detection
- Inventory-mismatch detection
- Duplicate-safe device alerts
- Registration and removal history
- Controlled alert review
- Audit records

The stale-device threshold is 30 days.

### Workflow

1. Validate the tracked CYOD inventory.
2. Synchronise approved devices with SQLite.
3. Read relevant V2 device events.
4. Match events using device ID or approved asset ID.
5. Compare the observed and expected device context.
6. Create findings for genuine identity problems.
7. Store duplicate-safe alerts.
8. Record registration changes and alert reviews.
9. Run the Stage 3 tests and validator.

### Observed example output

```text
PASS: V2 Stage 3 device identity foundation initialised
Approved devices loaded: 2
Stale-device threshold: 30 days
MAC identity handling: supporting_evidence_only
```

```text
PASS: 3 relevant V2 device events are available
PASS: One meaningful Stage 3 device alert is stored
PASS: CYOD-003 is correctly classified as an unregistered device
PASS: Approved CYOD-002 activity creates no false alert
PASS: Database and web assets are not treated as devices
PASS: Device alert keys are duplicate-safe
PASS: Stage 3 initialisation is recorded in the audit trail
PASS: Stage 3 detection runs are recorded in the audit trail

Stage 3 validation: 19/19 checks passed
PASS: V2 Stage 3 enterprise asset and device identity validated
```

### Testing Notes

Three relevant V2 device events were evaluated.

One meaningful High-severity Unregistered Device alert remained for `CYOD-003`.

Approved `CYOD-002` activity created no false device alert.

Running the detector again did not create another stored alert.

Eighteen Stage 3 unit tests passed. Stage 3 validation passed 19 out of 19 checks.

### Engineering observations

- The first detector treated database and web assets as devices. It was corrected to evaluate only recognised device context.
- `CYOD-003` was initially classified as unknown. Enterprise context showed that it was known but unregistered.
- Compatible Auckland location labels initially created an unnecessary mismatch and were normalised.
- Removing the existing approval field broke Phase 3 compatibility, so the field was restored.

### What I Learned

Reliable device identity requires several pieces of context.

A known unregistered device is different from an unknown device, and a MAC address should support an investigation rather than decide identity by itself.

---

## System Validation

### Clean-state validation workflow

The current Phase 3A V2 validation followed this process:

1. Initialise the V2 Stage 1 foundation.
2. Run the repeatable Stage 2 database migration.
3. Generate and import the V2 security events.
4. Initialise the Stage 3 device inventory.
5. Run the Stage 3 device detector.
6. Run the V2 Stage 1–3 tests.
7. Run each V2 stage validator.
8. Run the complete unit-test suite.
9. Run the original Phase 3 full-project validator.
10. Check duplicate imports and repeated detector runs.
11. Check stored events, inventory records and alerts.
12. Check audit records and safe-testing boundaries.
13. Run `git diff --check`.
14. Review the Git working tree.

### Genuine end-to-end results

```text
V2 STAGE 1 VALIDATION: PASS (12/12)
V2 STAGE 2 VALIDATION: PASS (13/13)
Stage 3 validation: 19/19 checks passed

Ran 116 tests

OK

STAGE 11 VALIDATION: PASS
```

The V2 Stage 1–3 test group passed 31 tests.

The complete project passed 116 unit tests.

The original Phase 3 full-project validation passed after the enterprise device-identity work was added.

### Problems discovered

Testing found several genuine integration and validation problems:

- Enterprise context and the CYOD inventory did not initially agree.
- Detailed file permissions changed after restoring a tracked file.
- Compound source names were identified incorrectly.
- The tracked schema did not upgrade the existing database.
- Repeated malformed records affected validator totals.
- The original validator did not allow approved V2 source additions.
- Inherited tests depended on ignored runtime files.
- Non-device asset IDs entered the first device detection run.
- Known unregistered activity was classified as unknown.
- Compatible location labels created an unnecessary device mismatch.
- Removing an earlier inventory field broke Phase 3 compatibility.

### How the problems were fixed

- The CYOD inventory and enterprise context were aligned.
- Required local permissions were reapplied and verified.
- Complete source names were recognised.
- A repeatable database migration was added.
- Validators counted distinct evidence and preserved original-source requirements.
- Sanitised test fixtures removed the runtime-file dependency.
- Device-event selection was limited to relevant device context.
- Known unregistered devices received their own classification.
- Compatible locations were normalised.
- The earlier approval field was restored.

### Engineering observations

The most important compatibility problems appeared where new enterprise context met existing Phase 3 assumptions.

Repeated migrations, imports and detector runs were useful because they confirmed that the project did not create duplicate columns, accepted events or stored alerts.

The validation results were checked against SQLite records and test evidence rather than relying only on printed summaries.

### What I Learned

Extending a working project requires more than adding new files.

The existing database, inventories, validators, permissions and test dependencies must all continue to work after the upgrade.

Security decisions are also stronger when they use several pieces of context instead of relying on one username, IP address or MAC address.

### Next expansion scope

The next component can use the existing identity, device, location, application and risk context when making local access decisions.

Later Phase 3A V2 work can add:

- Zero Trust access decisions
- Identity-risk detection
- Policy-based restrictions
- Network and endpoint context
- Cross-source correlation
- Vulnerability prioritisation
- Incident investigation
- Approval-controlled response
- Recovery verification
- Continuous-monitoring concepts

The project will remain local, controlled and simulated unless a future phase explicitly introduces an approved integration.
