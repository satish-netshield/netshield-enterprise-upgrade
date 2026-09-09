# NetShield Enterprise Upgrade

NetShield Enterprise Upgrade extends the completed NetShield Phase 3 Automation project.

It remains a Python and SQLite security-automation project inside a controlled Ubuntu VirtualBox sandbox.

The upgrade applies enterprise security concepts to simulated users, devices, applications, services and events. Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design references only.

No Microsoft tenants, cloud resources, real enterprise connectors, external targets or production containment actions are used.

## Current Project Status

The current upgrade contains:

- Stage 1 — Enterprise project foundation
- Stage 2 — Extended security data pipeline
- Stage 3 — Enterprise asset and device identity
- Stage 4 — Identity monitoring and risk detection
- Stage 5 — Zero Trust and policy-based access decisions

Stages 4 and 5 were developed and tested together because the access-policy engine uses the identity, device and risk context produced by the earlier stages. They remain separate components with their own tests, validator and result.

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

Stage 3 adds stronger device identity and inventory context for later enterprise detections and access decisions.

It synchronises the tracked CYOD inventory with SQLite and checks relevant V2 events for meaningful device-identity problems.

### Why it exists or how it behaves

Device ID and asset ID are the main identity references.

Hostname, assigned user, IP address, location and MAC address provide supporting context. A MAC address is not treated as proof because it can be changed, reused or spoofed.

Known but unregistered devices remain separate from completely unknown devices.

### Information, rules and capabilities

Stage 3 provides:

- Registered device inventory
- Unique device and asset IDs
- Registration and compliance context
- Unknown, unregistered, stale and mismatched device findings
- Duplicate-safe alerts
- Registration history
- Controlled alert review
- Audit records

The stale-device threshold is 30 days.

### Workflow

1. Validate and synchronise the CYOD inventory.
2. Read relevant V2 device events.
3. Match the device or asset identity.
4. Compare the observed and expected context.
5. Store duplicate-safe findings.
6. Preserve registration and review history.
7. Run the Stage 3 tests and validator.

### Observed example output

```text
PASS: 3 relevant V2 device events are available
PASS: One meaningful Stage 3 device alert is stored
PASS: CYOD-003 is correctly classified as an unregistered device
PASS: Approved CYOD-002 activity creates no false alert
PASS: Database and web assets are not treated as devices
PASS: Device alert keys are duplicate-safe

Stage 3 validation: 19/19 checks passed
PASS: V2 Stage 3 enterprise asset and device identity validated
```

### Testing Notes

Three relevant V2 device events were evaluated.

One High-severity Unregistered Device alert remained for `CYOD-003`. Approved `CYOD-002` activity created no false alert.

Repeated detection did not create another stored alert.

Eighteen Stage 3 tests passed, and Stage 3 validation passed 19 out of 19 checks.

### Engineering observations

- Non-device assets entered the first device evaluation and were removed from the device-event boundary.
- `CYOD-003` was corrected from Unknown Device to Unregistered Device.
- Compatible Auckland location labels were normalised.
- An earlier inventory field was restored to preserve Phase 3 compatibility.

### What I Learned

Device identity requires several pieces of inventory and event context.

A MAC address can support an investigation, but it should not decide identity by itself.

---

## Stage 4 — Identity Monitoring and Risk Detection

### What the component does

Stage 4 adds wider identity monitoring across authentication and identity-risk events.

It creates V2 identity alerts containing user, device, location, time, severity, confidence, risk and reason-code context.

### Why it exists or how it behaves

One identity event may not show enough context to make a useful decision.

Stage 4 combines related events and user baselines so it can recognise repeated failures, shared-source activity, unusual sign-ins, risky account behaviour and suspicious identity changes.

The V2 alerts are stored separately from the original Phase 3 identity alerts. This preserves the earlier implementation while allowing stronger enterprise context.

### Information, rules and capabilities

Stage 4 detects:

- Repeated failed logins
- Possible brute-force activity
- Password spraying
- Successful login after repeated failures
- Multiple accounts accessed from one source
- Impossible travel
- New-device sign-in
- Unusual sign-in location
- Abnormal access time
- MFA failure or fatigue patterns
- Suspicious privilege changes
- Dormant-account activity
- Service-account interactive login
- High sign-in risk
- High user risk

Each alert includes:

- Detection type
- Severity
- Confidence
- Username
- Device ID
- IP address
- Location
- First and last event time
- Supporting event IDs
- Risk context
- Reason codes
- Investigation status

Severity describes the possible impact.

Confidence describes how strongly the available evidence supports the detection.

Known VPN and approved testing evidence can suppress relevant findings when the activity matches the configured exception.

### Workflow

1. Load the Stage 4 configuration and user baselines.
2. Read controlled authentication and identity-risk events.
3. Group related failures by user and source.
4. Check shared-source behaviour across accounts.
5. Compare successful sign-ins with device, location and time baselines.
6. Evaluate MFA, privilege, dormant-account and service-account activity.
7. Calculate impossible-travel evidence.
8. Apply known VPN and approved-testing exceptions.
9. Assign severity, confidence and reason codes.
10. Create a deterministic alert key.
11. Store only new alerts.
12. Record the detection run in the audit trail.
13. Allow authorised review without deleting the original alert.

### Observed example output

The first controlled run produced:

```text
[High] Possible Brute Force | user=analyst01 | confidence=85 | reasons=POSSIBLE_BRUTE_FORCE
[Medium] Repeated Failed Logins | user=analyst01 | confidence=70 | reasons=REPEATED_FAILED_LOGINS
[High] Successful Login After Failures | user=analyst01 | confidence=90 | reasons=SUCCESS_AFTER_REPEATED_FAILURES
[High] Password Spraying Pattern | user=multiple_accounts | confidence=85 | reasons=PASSWORD_SPRAYING_PATTERN
[High] Impossible Travel | user=analyst01 | confidence=80 | reasons=IMPOSSIBLE_TRAVEL_SPEED
[Medium] New-Device Sign-In | user=viewer01 | confidence=65 | reasons=DEVICE_NOT_IN_USER_BASELINE
[High] MFA Failure or Fatigue Pattern | user=analyst01 | confidence=85 | reasons=REPEATED_MFA_FAILURES
[Critical] Suspicious Privilege Change | user=viewer01 | confidence=95 | reasons=ROLE_CHANGE_OUTSIDE_BASELINE
[High] Dormant-Account Activity | user=dormant01 | confidence=90 | reasons=DORMANT_ACCOUNT_USED
[High] Service-Account Interactive Login | user=svc_ingestion01 | confidence=95 | reasons=SERVICE_ACCOUNT_INTERACTIVE_LOGIN
[Medium] Abnormal Access Time | user=viewer01 | confidence=60 | reasons=ACCESS_OUTSIDE_NORMAL_UTC_HOURS

V2 STAGE 4 IDENTITY MONITORING: events=24 detections=16 new=16 existing=0 vpn_exceptions=2 testing_exceptions=1
```

The complete detection totals were:

| Detection | Alerts |
|---|---:|
| Abnormal Access Time | 1 |
| Dormant-Account Activity | 1 |
| Impossible Travel | 1 |
| MFA Failure or Fatigue Pattern | 1 |
| Multiple Accounts From One Source | 1 |
| New-Device Sign-In | 1 |
| Password Spraying Pattern | 1 |
| Possible Brute Force | 1 |
| Repeated Failed Logins | 1 |
| Risky Sign-In Behaviour | 2 |
| Service-Account Interactive Login | 1 |
| Successful Login After Failures | 1 |
| Suspicious Privilege Change | 1 |
| Unusual Sign-In Location | 2 |

A repeated run produced:

```text
V2 STAGE 4 IDENTITY MONITORING: events=24 detections=16 new=0 existing=16 vpn_exceptions=2 testing_exceptions=1
```

The controlled false-positive review produced:

```text
PASS: V2 Stage 4 identity alert reviewed
Alert ID: 16
Detection: Abnormal Access Time
Username: viewer01
Classification: False Positive
Status: Closed
Reviewed by: analyst01 (analyst)
```

### Testing Notes

The Stage 4 monitoring tests checked:

- Repeated failures
- Brute-force activity
- Success after failures
- Password spraying
- Shared-source account activity
- Impossible travel
- New devices
- Unusual locations
- MFA failures
- Privilege changes
- Dormant and service accounts
- High-risk identity events
- Abnormal access time
- VPN and testing exceptions
- Duplicate-safe alert storage

The alert-review tests checked:

- Analyst review permission
- Viewer rejection
- Valid classifications
- Required notes
- Missing-alert rejection
- Status changes
- Audit records

The Stage 4 monitoring and review group passed 19 tests.

The database contained 16 alerts and 16 unique alert keys after the repeated run.

V2 Stage 4 passed 12 out of 12 validation checks.

### Engineering observations

- The first controlled events began at `00:00` UTC, outside the configured normal access period.
- This made ordinary test events appear abnormal even though the detector was following its rule correctly.
- Normal events were moved inside the approved period, while one deliberate event remained at `23:00` UTC.
- The earlier controlled source records and batches were removed before the corrected data was regenerated and imported.
- The abnormal-time alert was reviewed as a False Positive instead of being removed.
- VPN and testing exceptions were recorded so suppressed findings remained explainable.

### What I Learned

A correct detection rule can still produce misleading results when the test data does not match its configured baseline.

Identity alerts are more useful when they show the supporting user, device, source, location, time and risk context.

False-positive handling should preserve the original alert and investigation history.

---

## Stage 5 — Zero Trust and Policy-Based Access Decisions

### What the component does

Stage 5 adds a local policy engine that makes explainable access decisions from identity, device, application, network, location, MFA and risk evidence.

It supports Allow, Deny, Challenge and Restrict outcomes.

### Why it exists or how it behaves

A valid username or role is not enough to approve access.

The policy engine verifies the wider request context and applies default deny, least privilege, device requirements, application sensitivity, risk controls and temporary restrictions.

This stage applies Zero Trust, RBAC and Conditional Access concepts locally. It does not reproduce Microsoft Conditional Access or change access in a real system.

### Information, rules and capabilities

The policy engine evaluates:

- User identity
- Assigned role
- Requested permission
- Device registration
- Device compliance
- Application sensitivity
- Asset criticality
- Location
- Network
- Sign-in risk
- User risk
- MFA evidence
- Known VPN evidence
- Temporary access restrictions

Each decision includes:

- Request event ID
- User and role
- Device and application
- Decision
- Winning policy
- Reason codes
- Evaluated evidence
- Proposed response
- ACL control level
- Response status
- Evaluation time

The four outcomes are:

| Outcome | Meaning |
|---|---|
| Allow | The required conditions were satisfied. |
| Deny | The request was not permitted. |
| Challenge | Stronger verification or more evidence was required. |
| Restrict | Access should be limited because of serious risk. |

Policies use explicit numeric priority. A lower number represents a stronger policy.

When policies have the same priority, the more restrictive result wins:

1. Deny
2. Restrict
3. Challenge
4. Allow

An active temporary access restriction has the highest priority.

Unknown applications and unsupported conditions follow default deny.

### Workflow

1. Load the access-policy configuration.
2. Read controlled access requests.
3. Load user, role, device and application context.
4. Check active temporary restrictions.
5. Verify role permission.
6. Check restricted locations and networks.
7. Apply approved VPN evidence where relevant.
8. Evaluate identity and sign-in risk.
9. Check device registration and compliance.
10. Check MFA requirements.
11. Collect all matching policies.
12. Resolve priority and same-priority conflicts.
13. Record the winning policy and reason codes.
14. Check any proposed response against the automation ACL.
15. Store the duplicate-safe decision.
16. Record the policy run in the audit trail.

### Observed example output

The controlled run produced:

```text
[ALLOW] request=S45-POLICY-001 | user=analyst01 | device=CYOD-002 | application=APP-001 | policy=POL-011 | reasons=ACCESS_REQUIREMENTS_SATISFIED | response=not_required
[DENY] request=S45-POLICY-002 | user=viewer01 | device=CYOD-001 | application=APP-001 | policy=POL-003 | reasons=ROLE_PERMISSION_MISSING | response=not_required
[CHALLENGE] request=S45-POLICY-003 | user=analyst01 | device=CYOD-003 | application=APP-001 | policy=POL-007 | reasons=DEVICE_NOT_COMPLIANT,DEVICE_NOT_REGISTERED | response=simulated_automatic
[RESTRICT] request=S45-POLICY-004 | user=responder01 | device=CYOD-001 | application=APP-001 | policy=POL-006 | reasons=CRITICAL_IDENTITY_RISK | response=approval_required
[DENY] request=S45-POLICY-005 | user=admin01 | device=CYOD-001 | application=APP-001 | policy=POL-005 | reasons=RESTRICTED_NETWORK | response=not_required
[CHALLENGE] request=S45-POLICY-006 | user=analyst01 | device=CYOD-002 | application=APP-001 | policy=POL-010 | reasons=MFA_REQUIRED | response=simulated_automatic
[DENY] request=S45-POLICY-007 | user=admin01 | device=CYOD-001 | application=APP-001 | policy=POL-004 | reasons=RESTRICTED_LOCATION | response=not_required
[ALLOW] request=S45-POLICY-008 | user=analyst01 | device=CYOD-002 | application=APP-001 | policy=POL-011 | reasons=ACCESS_REQUIREMENTS_SATISFIED | response=not_required
[DENY] request=S45-POLICY-009 | user=responder01 | device=CYOD-001 | application=APP-002 | policy=POL-001 | reasons=TEMPORARY_ACCESS_RESTRICTION | response=not_required

V2 STAGE 5 ACCESS POLICY: requests=9 decisions=9 new=9 existing=0 allow=2 deny=4 challenge=2 restrict=1
```

A repeated run produced:

```text
V2 STAGE 5 ACCESS POLICY: requests=9 decisions=9 new=0 existing=9 allow=2 deny=4 challenge=2 restrict=1
```

The final outcome totals were:

| Decision | Count |
|---|---:|
| Allow | 2 |
| Deny | 4 |
| Challenge | 2 |
| Restrict | 1 |

### Testing Notes

The Stage 5 tests checked:

- All four access outcomes
- Verified access
- Missing role permission
- Unregistered devices
- Non-compliant devices
- Missing MFA
- Restricted locations
- Restricted networks
- Critical identity risk
- Temporary restrictions
- Unknown-application default deny
- Approved VPN exceptions
- Policy priority
- Same-priority conflict handling
- Duplicate-safe decision storage

The automatic Challenge response used `increase_monitoring`, which is allowed by the automation ACL.

The Restrict decision proposed `restrict_account`. This action required approval and was not executed.

The database contained nine decisions and nine unique decision keys after the repeated run.

The Stage 5 test group passed 13 tests.

V2 Stage 5 passed 14 out of 14 validation checks.

### Engineering observations

- Policy priority was made explicit so a general Allow rule could not override a stronger restriction.
- Same-priority conflicts required a fixed restrictive order to prevent the configuration sequence from changing the result.
- Access decisions and response permissions were kept separate.
- Approved VPN evidence bypassed only the matching network restriction. It did not bypass role, device, risk or MFA rules.
- Every decision retained its reason codes and winning policy so the outcome could be explained without reading the source code.

### What I Learned

An access decision needs more than an outcome.

The evidence, reason codes, winning policy and response permission must remain visible as separate parts of the result.

Zero Trust is not one Deny rule. It is a consistent process of verifying the complete request and requiring stronger evidence when the risk increases.

---

## SQLite Connection Lifecycle

### What the component does

A shared SQLite connection helper now manages transaction completion and explicit connection closure across the project.

### Why it exists or how it behaves

The earlier `with sqlite3.connect(...)` pattern handled commit and rollback but did not close the connection object.

Python 3.14 reported these unclosed connections as `ResourceWarning` messages.

The shared helper:

1. Opens the connection.
2. Commits successful work.
3. Rolls back failed work.
4. Closes the connection in every case.

### Observed example output

Before the correction, the full diagnostic found:

```text
Python files inspected: 100
SQLite connection calls: 89
Affected files: 38
Unclosed database warnings: 101
```

After the correction:

```text
Ran 151 tests in 0.517s

OK

RESOURCE WARNINGS: 0
```

Database checking returned:

```text
ok
```

No foreign-key violations were returned.

### Testing Notes

Three focused tests confirmed:

- Successful transactions are committed.
- Failed transactions are rolled back.
- Connections are closed after leaving the managed context.

The complete test suite then passed 151 tests with no unclosed-database warnings.

### Engineering observations

The functional tests passed before the correction, but the runtime warnings showed that database resources were not being closed explicitly.

Fixing the shared connection pattern now prevented the same warning from continuing into later project stages.

### What I Learned

Passing tests do not prove that resources are managed correctly.

Runtime warnings can expose reliability problems that functional assertions do not detect.

---

## System Validation

### Clean-state validation workflow

The Phase 3A V2 validation through Stage 5 followed this process:

1. Compile the project files.
2. Initialise the V2 foundation.
3. Apply the Stage 2 database migration.
4. Generate and import the Stage 2 events.
5. Initialise the Stage 3 device inventory.
6. Run the Stage 3 device detector.
7. Apply the Stage 4–5 database migration.
8. Generate and import the Stage 4–5 events.
9. Run Stage 4 identity monitoring.
10. Review the controlled false-positive alert.
11. Run the Stage 5 access-policy engine.
12. Repeat imports, detections and policy evaluation.
13. Run focused Stage 4 and Stage 5 tests.
14. Run the complete unit-test suite with resource warnings enabled.
15. Run every V2 Stage 1–5 validator.
16. Run the original Phase 3 Stage 11 validator.
17. Check SQLite integrity and foreign keys.
18. Check sensitive configuration permissions.
19. Run `git diff --check`.
20. Review staged files and runtime exclusions.

### Genuine end-to-end results

```text
V2 STAGE 1 VALIDATION: PASS (12/12)
V2 STAGE 2 VALIDATION: PASS (13/13)
Stage 3 validation: 19/19 checks passed
V2 STAGE 4 VALIDATION: PASS (12/12)
V2 STAGE 5 VALIDATION: PASS (14/14)

Ran 151 tests

OK

RESOURCE WARNINGS: 0

STAGE 11 VALIDATION: PASS
```

The final controlled state contained:

- 12 accepted Stage 2 V2 events
- 2 distinct quarantined malformed Stage 2 events
- 3 relevant Stage 3 device events
- 1 meaningful Stage 3 device alert
- 33 Stage 4–5 controlled events
- 16 unique Stage 4 identity alerts
- 9 unique Stage 5 access decisions
- 1 completed Stage 4 false-positive investigation
- 2 recorded Stage 4 VPN exceptions
- 1 recorded Stage 4 testing exception
- 0 unclosed SQLite connection warnings
- Passing SQLite integrity and foreign-key checks

### Problems discovered

Testing exposed genuine project problems:

- Enterprise context and the CYOD inventory did not initially agree.
- Detailed configuration permissions changed after tracked files were restored or created.
- Compound source names were identified incorrectly.
- The tracked schema did not upgrade the existing database.
- Repeated malformed inputs affected validator row counts.
- The original source validator did not allow approved V2 additions.
- Inherited tests depended on ignored runtime files.
- Non-device assets entered the first device evaluation.
- A known unregistered device was classified as unknown.
- Normal Stage 4 events were created outside normal access hours.
- Later Stage 4–5 events affected a broad Stage 3 validator query.
- SQLite transaction contexts did not explicitly close their connections.
- Access-policy conflicts required a deterministic priority rule.

### How the problems were fixed

- Enterprise context and the authoritative CYOD inventory were aligned.
- Required `640` configuration permissions were reapplied and verified.
- Complete source names were recognised.
- Repeatable database migrations were added.
- Validators were changed to count distinct evidence and allow approved V2 sources.
- Sanitised fixtures removed the inherited runtime-file dependency.
- Device evaluation was limited to recognised device context.
- Known unregistered activity received its own classification.
- Normal Stage 4 events were moved inside the approved time window.
- The Stage 3 validator was limited to its intended source files.
- A shared managed SQLite connection helper was added.
- Policy priority and restrictive same-priority handling were defined explicitly.

### Engineering observations

The most important problems appeared where new V2 context met assumptions made by an earlier stage.

The valid Stage 4–5 events were not removed to satisfy the Stage 3 validator. The validator’s evidence boundary was corrected instead.

Repeated migrations, imports, detections and policy runs confirmed that the upgrade did not create duplicate schema objects, accepted events, identity alerts or access decisions.

The database warnings also showed why full validation must include more than pass or fail results.

### What I Learned

Extending a working security project requires compatibility across data, configuration, permissions, validation and runtime behaviour.

Identity monitoring becomes more useful when alerts retain user, device, location, time, source and risk evidence.

Access control becomes more useful when every outcome explains which policy won and why.

Warnings, exception counts, duplicate checks and audit records are part of genuine validation, not additional decoration after the tests pass.

### Next expansion scope

Later Phase 3A V2 work can use the identity alerts and access decisions for:

- Wider cross-source correlation
- Vulnerability prioritisation
- Incident creation and investigation
- Approval-controlled response
- Recovery verification
- Continuous-monitoring concepts
- More detailed enterprise reporting

The project will remain local, controlled and simulated unless a future phase introduces an explicitly approved integration.
