# NetShield Enterprise Upgrade — Phase 3A V2

NetShield Enterprise Upgrade extends the completed Phase 3 Automation project.

It remains a Python and SQLite security-automation project inside the controlled Ubuntu VirtualBox sandbox. Enterprise security concepts are added without using real external targets, accounts or production services.

---

## Phase 3A V2 — Combined Stages 1 and 2

The first upgrade block adds:

- Simulated enterprise users, devices, applications and services
- Data-retention and sensitive-field protection settings
- Identity-risk and access-policy events
- Database, vulnerability, incident and response events
- Schema-version and source-system identification
- Malformed-event quarantine
- Repeatable database migration
- File-level failure reporting

```text
V2 STAGE 1 VALIDATION: PASS (12/12)
V2 STAGE 2 VALIDATION: PASS (13/13)
Ran 98 tests — OK
```

The original Phase 3 components and full-project validation remain operational.

---

## Stages 1 and 2 — Environment, Access Control and Security Data Pipeline

### What the components do

Stages 1 and 2 created the controlled foundation for the rest of the project.

Stage 1 manages configuration, roles, permissions, logging, evidence protection and safe testing boundaries.

Stage 2 receives simulated security events, validates them, normalises them and stores accepted events in SQLite for later detection.

### Why they exist and how they behave

Detection work should not begin with uncontrolled access or unreliable data.

Stage 1 uses default deny and least privilege so unknown users, actions, devices and IP addresses are not trusted automatically. Disruptive actions require approval.

Stage 2 validates data before it reaches the accepted-event table. This prevents malformed or incorrectly labelled records from influencing later detections.

The pipeline keeps source files separate and checks that the declared source type matches the filename. This preserves the collector’s existing source-verification rules and prevents older processing logic from receiving data under the wrong source type.

### Information, rules and capabilities

Stage 1 provides:

- Ubuntu VirtualBox sandbox
- Python virtual environment
- JSON configuration
- SQLite database
- Application and audit logging
- Viewer, Analyst, Responder and Administrator roles
- CYOD device allowlist
- IP allowlist and simulated blocklist
- Automation-action ACL
- SHA-256 evidence protection
- Protected file and directory permissions

Stage 2 provides:

- Authentication, network, Wi-Fi, endpoint and application event sources
- JSONL event collection
- Timestamp conversion to UTC
- IP, MAC and CPU validation
- Accepted-event storage
- Rejected-record storage
- Import-batch tracking
- Raw-event preservation
- Duplicate-event protection

### Workflow

1. Load configuration and create the SQLite database.
2. Apply roles, permissions and automation controls.
3. Check devices and IP addresses against the configured lists.
4. Generate controlled JSONL security events.
5. Read one record at a time.
6. Validate the JSON, source type, timestamp and required fields.
7. Convert accepted timestamps to UTC.
8. Store accepted records in SQLite.
9. Preserve rejected records with their original input and reason.
10. Reject duplicate source events.
11. Check the stored records and import totals against the source files.

### Observed example output

```text
PASS: RBAC follows least privilege
PASS: Automation ACL follows default deny
PASS: Evidence hash and read-only protection is valid

STAGE 1 VALIDATION: PASS (12/12)
```

```text
PASS: Generated 19 safe simulated records

STAGE 2 IMPORT: files=5 total=19 accepted=15 rejected=4
```

### Testing Notes

Stage 1 validation passed `12/12`. Eleven Stage 1 unit tests passed.

Stage 2 validation passed `14/14`. The Stage 2 normalisation and pipeline tests passed.

The tests checked:

- Required directories and configuration
- SQLite tables and audit records
- File permissions and evidence protection
- Five source files containing 19 records
- Fifteen accepted and four rejected records
- UTC timestamp conversion
- Invalid IP, MAC and CPU rejection
- Raw-event preservation
- Duplicate-event protection
- Import totals against the stored database records

The accepted-event table, rejected-event records and import-batch totals were checked directly rather than relying only on the printed script summary.

### Engineering observations

- The Stage 2 validator initially counted later Stage 3 authentication events as original Stage 2 data.
- The validator was changed to check only the original Stage 2 source files.
- Invalid JSON, missing event IDs, invalid IP addresses and CPU values above 100 were rejected.
- Rejected records remained available for troubleshooting and did not enter the accepted-event table.

### What I Learned

A controlled environment and reliable input are needed before detection logic can be trusted. JSONL is useful because one bad record can be rejected without stopping the rest of the file.

---

## Stage 3 — Identity and Authentication Detection

### What the component does

Stage 3 analyses authentication events and creates alerts for suspicious identity activity.

### Why it exists or how it behaves

Repeated login failures, unusual locations and unexpected role changes can provide early evidence of account compromise. The detector groups authentication events by user, address, device, location and time window before applying the rules.

Known VPN activity is handled as an exception for the relevant checks. An alert is treated as evidence for investigation, not automatic proof of compromise.

### Information, rules and capabilities

The detector checks for:

- Repeated failed logins
- Possible brute force
- Successful login after repeated failures
- MFA failure anomalies
- Logins from new devices
- Unusual locations
- Impossible travel
- Suspicious role changes
- Known VPN exceptions

A deterministic alert key prevents the same detection pattern from creating duplicate alert rows.

### Workflow

1. Import authentication events.
2. Load identity rules and baselines.
3. Group events by user, address and time.
4. Apply identity-detection rules.
5. Apply approved VPN exceptions.
6. Create unique alerts.
7. Preserve supporting evidence and audit activity.
8. Investigate and classify possible false positives.
9. Run the detector again to check duplicate protection.

### Observed example output

```text
[High] Possible Brute Force | user=analyst01
[High] Successful Login After Failures | user=analyst01
[High] MFA Failure Anomaly | user=analyst01
[Critical] Suspicious Role Change | user=trainee01

STAGE 3 DETECTION: events=19 detections=11 new=11 existing=0 vpn_exceptions=2
```

A repeated run produced:

```text
STAGE 3 DETECTION: events=19 detections=11 new=0 existing=11 vpn_exceptions=2
```

### Testing Notes

Sixteen Stage 3 authentication events were imported. Stage 3 validation passed `12/12`.

The tests checked:

- Expected identity detection types
- VPN exceptions
- Duplicate alert protection
- Alert totals against stored records
- Audit records
- False-positive classification

The replacement laptop was authorised but had not yet been registered in the CYOD inventory. Its new-device alert was preserved, investigated and classified as a false positive.

### Engineering observations

The Stage 2 validator needed to be corrected after Stage 3 added new authentication data. This showed that later stages can affect earlier validation assumptions.

### What I Learned

A detection is not always proof of malicious activity. Device inventory, approval records and supporting evidence must be reviewed before deciding what an alert means.

---

## Stages 4 and 5 — Network, Wi-Fi, Endpoint and Wired-LAN Detection

### What the components do

Stages 4 and 5 add network, Wi-Fi, endpoint and wired-LAN context to the earlier identity detections.

Stage 4 checks network connections, CYOD device identity and Wi-Fi policy.

Stage 5 checks endpoint CPU activity, endpoint processes and wired access in restricted zones.

### Why they exist and how they behave

Identity events show account activity but do not show how a device connects or what is happening on the endpoint.

The MAC address is used as the primary device identity because the CYOD inventory is based on approved device MAC addresses. Hostname, username, IP address, process, CPU, location, role, switch port, VLAN and event time provide supporting evidence.

Network and Wi-Fi files remain separate because the collector verifies that the source type matches the filename. Combining the files would cause valid records to be rejected or processed under the wrong rules. Correlation therefore occurs only after source validation and database storage.

A location change alone does not create a MAC-reuse alert. Conflicting hostname or username evidence with overlapping event times is required.

### Information, rules and capabilities

Stage 4 detects:

- Suspicious IP addresses
- Repeated connection attempts
- Port scanning
- Unknown CYOD devices
- Unregistered MAC addresses
- Possible MAC reuse or spoofing
- Wi-Fi zone violations
- WPA3 policy violations
- WPA2 downgrade attempts
- Rogue access points

Stage 5 detects:

- Unexpected CPU activity
- Repeated high CPU activity
- Unauthorised CPU stress tests
- Unknown endpoint processes
- Restricted wired access
- Possible MAC reuse or spoofing

Approved CPU stress testing is excluded only when the configured approval, test identifier and process match.

### Workflow

1. Generate controlled network, Wi-Fi, endpoint and wired-LAN events.
2. Write each source to the correct filename.
3. Validate the source type before import.
4. Store accepted events in the shared `security_events` table.
5. Compare MAC addresses with the CYOD inventory.
6. Apply network, Wi-Fi, CPU, process and wired-zone rules.
7. Compare hostname, username, location and event time for possible MAC reuse.
8. Correlate related observations by MAC address and detection context.
9. Group repeated matching observations.
10. Save unique alerts and record the detection run.
11. Re-import and rerun detection to check duplicate protection.

### Observed example output

```text
[High] MAC Address Reuse or Possible Spoofing | mac=08:00:27:cf:49:71
[High] Port Scanning | mac=02:42:ac:11:00:25
[Critical] Rogue Access Point | mac=02:42:ac:11:00:88
[Medium] Repeated Connection Attempts | mac=02:42:ac:11:00:55

STAGE 4 DETECTION: events=23 raw_detections=43
correlated_alerts=12 new_alerts=12 existing_alerts=0
```

```text
[High] Repeated High CPU Activity | identity=02:42:ac:11:00:25
[Critical] Unexpected CPU Activity | identity=02:42:ac:11:00:25
[High] Unauthorised CPU Stress Test | identity=02:42:ac:11:00:77
[High] Unknown Endpoint Process | identity=02:42:ac:11:00:99
[High] Restricted Wired Access | identity=02:42:ac:11:00:25

STAGE 5 DETECTION: events=14 detections=10 new_alerts=10 existing_alerts=0
```

### Testing Notes

Stage 4 validation passed `12/12`. Twenty-three Stage 4 events were accepted and twelve correlated alerts were produced.

Stage 5 validation passed `12/12`. Fourteen Stage 5 events were accepted and ten alerts were produced.

The tests checked:

- Accepted-event totals and source counts
- MAC-based correlation
- Port scanning and rogue access-point detection
- WPA3 and WPA2 policy checks
- CPU thresholds and process detection
- Approved CPU testing creating no alert
- Restricted wired access
- Location-only movement not creating MAC reuse
- Repeated wired observations being grouped
- Duplicate imports and repeated detector runs
- Endpoint-alert storage and database records

Re-importing the Stage 5 events rejected all fourteen records as duplicates. A repeated detector run created zero new alerts and counted ten existing alerts.

### Engineering observations

- Wi-Fi records were initially placed in a network-named file and six records were rejected by source validation.
- The generator was changed to create separate network and Wi-Fi files.
- The Stage 4 runner supplied more files than its SQL query accepted. Dynamic SQL placeholders were added for the changing file list.
- Stage 4 setup initially reset completed Stage 3 metadata. The initializer was corrected to preserve earlier status.
- The Stage 5 wired filename initially did not match the `network` source type. The generator was corrected.
- The endpoint-alert table was added to the tracked schema.
- The first MAC-reuse rule treated a location change alone as spoofing. It was changed to require conflicting identity evidence and time overlap.
- Simulated role mappings were added because the application role table contains only the project administrator.

### What I Learned

Source validation must happen before correlation. CPU activity and MAC address are useful evidence, but neither should be interpreted without supporting device, identity, approval and time information.

---

## Stage 6 — SQL Injection Detection

### What the component does

Stage 6 uses an isolated local Python application and SQLite database to demonstrate SQL injection detection and secure-code remediation.

### Why it exists or how it behaves

The lab shows how a vulnerable query can change authentication behaviour when user input is joined directly into SQL. The same input is then tested against a parameterised query.

The lab uses one test account and controlled local requests. No external target, public system or real account is used.

### Information, rules and capabilities

The lab demonstrates:

- Safe local SQL injection testing
- Suspicious-input detection
- Repeated abnormal requests
- Authentication-bypass attempts
- Database-error monitoring
- Source-IP tracking
- Vulnerable query behaviour
- Parameterised-query remediation
- Retesting after remediation
- Database-integrity verification

### Workflow

1. Create the isolated SQLite database.
2. Create the local test account.
3. Run normal and controlled injection requests.
4. Record authentication results, returned rows and database errors.
5. Track suspicious patterns and source IP addresses.
6. Archive the previous cumulative application log.
7. Run the clean seven-request set.
8. Test the same injection input against the parameterised query.
9. Check the raw request evidence, application log and SQLite users table.
10. Write and validate the detection report.

### Observed example output

```text
STAGE 6 SQL INJECTION DETECTION
REQUESTS ANALYSED: 7
VULNERABLE BYPASSES: 4
DATABASE ERRORS: 1
REMEDIATION RETESTS BLOCKED: 1
REPEATED ABNORMAL SOURCES: 1
LOGGED EVENTS: 7
```

### Testing Notes

Seven Stage 6 unit tests passed. Stage 6 validation passed `15/15`.

The clean run produced:

- Seven controlled requests
- Four vulnerable authentication bypasses
- One database error
- One repeated abnormal source IP
- One blocked parameterised-query retest
- Seven application events

The raw request evidence, application-event log and detection report were checked. The SQLite users table remained present and the test account remained available.

### Engineering observations

- The first request summary reported two vulnerable bypasses although four vulnerable requests authenticated.
- The summary logic was corrected to count actual vulnerable authentication results.
- One test used a fixed application-log path.
- The application and test were changed to accept an isolated log path.
- The previous application log contained 36 cumulative events.
- The old log was archived before the clean run so historical events did not contaminate the new totals.

### What I Learned

Secure SQL testing should demonstrate the original weakness, the correction and the retest. Parameterised queries treat input as data instead of executable SQL syntax.

---

## Stage 7 — Event Correlation, Risk Scoring and IoCs

### What the component does

Stage 7 combines related events into context-rich incidents, calculates a risk score and extracts observable Indicators of Compromise.

### Why it exists or how it behaves

An isolated alert may have limited meaning. Several related indicators from identity, network, endpoint and application sources can provide stronger evidence.

The engine groups events using shared identity and context. It applies approved-device and known-VPN exceptions, separates suspicious behaviours from IoCs and leaves automatic containment disabled.

### Information, rules and capabilities

Events are correlated using:

- Username
- IP address
- MAC address
- Device approval status
- Hostname
- Process
- Time window
- Location
- Detection type
- Source type

The engine:

- Combines related events.
- Reduces isolated low-value activity.
- Increases risk when indicators appear together.
- Assigns Low, Medium, High or Critical severity.
- Extracts observable IP, MAC, hostname and process values.
- Keeps username as context rather than automatically treating it as an IoC.
- Separates suspicious behaviours from IoCs.
- Does not perform automatic containment.

### Workflow and scoring model

1. Load the controlled Stage 7 events.
2. Validate fields and timestamps.
3. Group events sharing device, user, address, location and time context.
4. Apply detection severity and supporting indicators.
5. Increase risk for related multi-source evidence.
6. Reduce risk for approved-device and known-VPN exceptions.
7. Extract observable IoCs.
8. Record suspicious behaviours separately.
9. Create one incident for each related event group.
10. Validate the incident count, severity, IoCs and boundaries.

### Observed example output

```text
STAGE 7 CORRELATION
EVENTS ANALYSED: 7
INCIDENTS CREATED: 3
[Critical] score=30 events=4 iocs=4 behaviours=1
[Low] score=1 events=2 iocs=0 behaviours=0
[Low] score=3 events=1 iocs=0 behaviours=1
```

### Testing Notes

Five Stage 7 correlation tests passed. Stage 7 validation passed `15/15`.

The validation confirmed:

- Seven events were analysed.
- Three incidents were created.
- Four related events were combined.
- Identity, network, endpoint and application evidence formed one Critical incident.
- Four observable IoCs were extracted.
- Username remained context rather than an IoC.
- Approved-device and VPN exceptions reduced risk.
- Isolated low-value activity was reduced to Low.
- Suspicious behaviours remained separate from IoCs.
- No external targets were used.
- Automatic containment remained disabled.

### Engineering observations

- The first engine incorrectly extracted username as an IoC. Username was kept as context instead.
- The first scoring version rated an isolated Medium event too highly. Isolated low-value activity was reduced to Low.
- Direct execution of the Stage 7 runner initially failed because the project root was not available on the import path.
- The runner was corrected so it could import the correlation engine when executed directly.

### What I Learned

Correlation makes an incident easier to understand, but it should not turn every suspicious value into an IoC or automatically trigger containment.

---

## Stages 8 and 9 — Incident Management, Evidence and Controlled Containment

### What the components do

Stage 8 converts Stage 7 incidents into traceable incident records.

Stage 9 uses those incident records to perform controlled, simulated containment actions.

Together, these stages preserve evidence, record the investigation, apply approval controls and document the result of each containment action.

### Why they exist and how they behave

A detection or correlated incident is not enough to show what happened during an investigation. Stage 8 adds incident IDs, statuses, investigation notes, analyst decisions, evidence references, integrity hashes and audit records.

Containment can limit suspicious activity, but disruptive actions can affect legitimate users or systems. Stage 9 therefore preserves evidence before action, checks the existing automation ACL and requires approval for disruptive actions.

The status lifecycle is:

```text
New → Investigating → Contained → Eradicated → Recovered → Closed
```

Stages 8 and 9 record the incident and simulated containment process. Eradication and recovery are handled in Stage 10.

### Information, rules and capabilities

Stage 8 provides:

- Unique incident IDs
- Detection name, severity and risk score
- Controlled incident statuses
- Investigation notes
- Analyst decisions
- False-positive classification
- Preserved Stage 7 evidence
- SHA-256 evidence hashes
- Incident timelines
- IoC references
- JSON incident records
- Human-readable incident reports
- Audit entries

Stage 9 provides:

- Simulated IP blocklist action
- Unknown CYOD device quarantine
- Temporary account restriction
- Simulated session revocation
- Suspicious-process isolation
- Non-compliant Wi-Fi rejection
- Evidence preservation before action
- Approval checks
- Success and failure recording
- Containment audit entries

### Workflow

1. Read the Stage 7 correlation report.
2. Create one Stage 8 incident record for each correlated incident.
3. Assign a unique incident ID.
4. Preserve the Stage 7 report as evidence.
5. Calculate and store its SHA-256 hash.
6. Record the detection, severity, risk score and initial status.
7. Record investigation notes, analyst decisions, IoCs and false-positive fields.
8. Create the incident timeline and audit trail.
9. Read the Stage 8 incident summary.
10. Preserve the supporting evidence before containment.
11. Check whether each containment action is allowed.
12. Check whether approval is required.
13. Run only the simulated action.
14. Record the target, approval state, evidence hash and result.
15. Write the containment audit entry and report.

### Approval model

- Adding an IP address to the simulated blocklist is allowed automatically.
- Device quarantine requires approval.
- Account restriction requires approval.
- Session revocation requires approval.
- Process isolation requires approval.
- Non-compliant Wi-Fi rejection requires approval.
- Undefined actions are denied.
- An action without approval fails safely and remains in the audit trail.

### Observed example output

```text
STAGE 8 INCIDENT MANAGEMENT
STAGE 7 INCIDENTS RECEIVED: 3
INCIDENT RECORDS CREATED: 3
AUDIT ENTRIES: 9
EVIDENCE SHA256: 10e94c774ace7897059c2a3713e1cb74697f3c1eb037efa98fcdd394e1a4efef
AUTOMATIC CONTAINMENT: false
```

```text
STAGE 9 CONTROLLED CONTAINMENT
ACTIONS ATTEMPTED: 6
ACTIONS SUCCEEDED: 5
ACTIONS FAILED: 1
EVIDENCE PRESERVED BEFORE ACTION: 10e94c774ace7897059c2a3713e1cb74697f3c1eb037efa98fcdd394e1a4efef
EXTERNAL TARGETS USED: false
REAL ACCOUNTS USED: false
```

The Wi-Fi rejection failed because approval was not granted. This was the expected controlled result.

### Testing Notes

Ten Stage 8 unit tests passed. Stage 8 validation confirmed:

- Three incident records
- Three human-readable reports
- Unique incident IDs
- Correct severity and risk values
- Investigation notes and analyst decisions
- False-positive fields
- IoC tables
- Valid evidence hashes
- Nine audit entries
- Incident timeline entries
- Valid and invalid status-transition handling

Eleven Stage 9 unit tests passed. Stage 9 validation confirmed:

- Six containment actions
- Five successful actions
- One failed action
- Evidence preservation before every action
- SHA-256 integrity
- Approval-required actions
- Safe rejection without approval
- One audit entry per action
- No external targets or real accounts

### Engineering observations

- Stage 8 used the existing Stage 7 report instead of creating a separate, unrelated incident source.
- The Stage 7 report was preserved as evidence for the incident records.
- All three Stage 8 incidents initially started in `New` status.
- Stage 9 preserved evidence before both successful and failed actions.
- The automatic blocklist action succeeded without approval according to the existing ACL.
- The Wi-Fi rejection failed safely because the required approval was not granted.
- Stage 8 and Stage 9 kept containment simulated and did not change real devices, accounts or networks.

### What I Learned

Incident handling needs more than a detection result. Evidence, decisions, status, timelines and action outcomes must remain connected.

Containment should be controlled and reversible where possible. A failed action is still an important result and must remain visible in the audit trail.

---

## Stage 10 — Eradication and Recovery

### What the component does

Stage 10 moves the incident process beyond containment by recording simulated eradication and recovery actions.

It removes or corrects the simulated causes identified in earlier stages, restores affected services and retests the original threats.

### Why it exists or how it behaves

Containment limits suspicious activity, but it does not remove the cause. Stage 10 records what was corrected, what was restored and whether the original threat still worked afterwards.

The stage uses preserved evidence, records every action in an audit trail and progresses the incident through:

```text
Contained → Eradicated → Recovered → Closed
```

All actions remain simulated inside the project sandbox.

### Information, rules and capabilities

Stage 10 covers:

- Simulated credential reset
- Removal of unauthorised privileges
- Registration of an unknown device
- WPA3 configuration correction
- Rogue access-point removal
- Suspicious-process removal
- Replacement of vulnerable SQL with parameterised SQL
- Simulated account, device and service restoration
- Increased monitoring after recovery
- Threat retesting
- Lessons-learned recording

### Workflow

1. Read the Stage 9 containment report.
2. Preserve the pre-eradication evidence.
3. Record the simulated eradication actions.
4. Correct the simulated credentials, privileges, devices and network settings.
5. Remove the simulated rogue access point and suspicious process.
6. Confirm the parameterised SQL path.
7. Restore the simulated account and services.
8. Increase monitoring after recovery.
9. Record every action in the audit trail.
10. Retest the original SQL injection, network, endpoint and access conditions.
11. Confirm that the original threats no longer succeed.
12. Record the lifecycle through `Eradicated`, `Recovered` and `Closed`.
13. Record lessons learned.

### Observed example output

```text
STAGE 10 ERADICATION AND RECOVERY
ACTIONS ATTEMPTED: 10
ACTIONS SUCCEEDED: 10
ACTIONS FAILED: 0
ORIGINAL THREATS BLOCKED: true
EXTERNAL TARGETS USED: false
REAL ACCOUNTS USED: false
```

### Testing Notes

Seven Stage 10 unit tests passed. Stage 10 validation passed.

The validation confirmed:

- Ten eradication and recovery actions
- Ten successful actions
- No failed actions
- Four original-threat retests
- All original threats blocked after remediation
- Evidence preservation before every action
- Fourteen audit entries
- Lifecycle completion through `Closed`
- Lessons learned recorded
- No external targets or real accounts

### Engineering observations

The Stage 10 implementation keeps eradication and recovery separate from containment. This makes it possible to show that limiting activity is not the same as removing the cause.

The retests are important because a successful action result alone does not prove that the original threat has been removed.

### What I Learned

Eradication should be followed by recovery checks and threat retesting. An incident should not be closed only because the response script completed successfully.

---

## Stage 11 — Full Project Validation

### What the component does

Stage 11 validates the complete NetShield Phase 3 project after the implementation stages are present.

It combines syntax checks, regression tests, stage validators, evidence checks, response checks and documentation-presence checks.

### Why it exists or how it behaves

Individual stage tests can pass while integration problems remain. Stage 11 checks that earlier components still work after later stages have been added.

The validator reports each check with a clear label so that a passing result can be understood and reviewed.

### Validation workflow

1. Check the required project files and current project state.
2. Compile the source, scripts, tests and lab code.
3. Run the combined Stage 1–10 regression.
4. Run each Stage 1–10 validator.
5. Check Stage 7 incidents and IoCs.
6. Check Stage 8 evidence integrity.
7. Check Stage 9 containment results.
8. Check Stage 10 eradication and recovery results.
9. Check normal, confirmed-threat, false-positive and malformed-input coverage.
10. Check duplicate-event handling and ACL enforcement.
11. Check evidence integrity and audit-trail outputs.
12. Check that previous components remain operational.
13. Check that the documentation files are present.
14. Record the final validation result.

### Observed example output

```text
STAGE 11 FULL PROJECT VALIDATION
PASS: Python syntax compilation passed
PASS: Combined Stage 1–10 regression passed
PASS: Stage 1 validator passed
PASS: Stage 2 validator passed
PASS: Stage 3 validator passed
PASS: Stage 4 validator passed
PASS: Stage 5 validator passed
PASS: Stage 6 validator passed
PASS: Stage 7 validator passed
PASS: Stage 8 validator passed
PASS: Stage 9 validator passed
PASS: Stage 10 validator passed
PASS: Clean-state validation completed
PASS: Normal activity checks completed
PASS: Confirmed-threat checks completed
PASS: False-positive checks completed
PASS: Malformed-input checks completed
PASS: Duplicate-event handling completed
PASS: ACL enforcement completed
PASS: Evidence-integrity checks completed
PASS: Containment actions completed
PASS: Eradication and recovery completed
PASS: IoC extraction completed
PASS: Audit-trail checks completed
PASS: Previous components remain operational
PASS: Documentation files remain present

STAGE 11 VALIDATION: PASS
```

### Testing Notes

The final Stage 1–10 regression run passed 92 tests.

Stage 11 confirmed that:

- Python syntax compilation passed.
- All Stage 1–10 validators passed.
- Stage 7 incidents and IoCs remained available.
- Stage 8 incident records and evidence hashes remained valid.
- Stage 9 containment actions and approval rejection remained recorded.
- Stage 10 eradication actions and blocked retests remained recorded.
- The incident lifecycle reached `Closed`.
- Clean-state, normal-activity, confirmed-threat, false-positive and malformed-input checks passed.
- Duplicate-event handling and ACL enforcement passed.
- Evidence, IoC and audit-trail checks passed.
- Earlier components remained operational.
- The required documentation files were present.

### Engineering observations

- The first Stage 11 validator displayed blank validator names because it used incorrect command indexes.
- The validator was corrected to print the actual validator name.
- The regression check was corrected to handle unittest output written to standard error.
- The corrected Stage 11 validation run passed.

### What I Learned

Full-project validation is different from running one script successfully. The complete system must be checked after later stages are added, including evidence, repeated processing, response boundaries and earlier functionality.

---

## System Validation

### Clean-state validation workflow

The final validation followed the complete engineering cycle:

1. Activate the Python virtual environment.
2. Compile the source, script, test and lab files.
3. Run the combined Stage 1–10 regression.
4. Run every Stage 1–10 validator.
5. Run the Stage 11 full-project validator.
6. Check duplicate imports and repeated detector runs.
7. Check accepted, rejected and raw database records.
8. Check the clean Stage 6 log after archiving the historical log.
9. Check the Stage 6 users table and test account.
10. Check Stage 7 incidents, risk scores, IoCs and behaviours.
11. Check Stage 8 incident records, evidence hashes, reports and audit entries.
12. Check Stage 9 approval decisions, action results and containment audit entries.
13. Check Stage 10 eradication actions, retests, recovery results and lifecycle closure.
14. Check documentation files are present.
15. Run `git diff --check`.

### Genuine end-to-end results

```text
Ran 92 tests

OK

STAGE 1 VALIDATION: PASS (12/12)
STAGE 2 VALIDATION: PASS (14/14)
STAGE 3 VALIDATION: PASS (12/12)
STAGE 4 VALIDATION: PASS (12/12)
STAGE 5 VALIDATION: PASS (12/12)
STAGE 6 VALIDATION: PASS (15/15)
STAGE 7 VALIDATION: PASS (15/15)
STAGE 8 VALIDATION: PASS
STAGE 9 VALIDATION: PASS
STAGE 10 VALIDATION: PASS
STAGE 11 VALIDATION: PASS
```

The final Stage 1–10 regression passed 92 tests. The Stage 11 full-project validation also passed.

### Problems discovered and how they were solved

- The Stage 2 validator counted later-stage events and was limited to the original Stage 2 files.
- Wi-Fi records were rejected from a mixed source file and were moved to separate source files.
- Dynamic SQL placeholders were added for changing Stage 4 file lists.
- Stage metadata preservation was corrected after Stage 4 setup reset earlier completion data.
- The Stage 5 wired filename was corrected to match its `network` source type.
- The Stage 5 endpoint-alert table was added to the tracked schema.
- MAC-reuse logic was strengthened to require conflicting identity evidence and overlapping times.
- The Stage 6 bypass summary was corrected to count actual authenticated vulnerable requests.
- Stage 6 logging was changed to support an isolated log path.
- The cumulative 36-event log was archived before the clean Stage 6 run.
- Stage 7 IoC extraction was corrected so username remained context.
- Stage 7 isolated-event scoring was reduced to Low.
- The Stage 7 import path was corrected for direct script execution.
- Stage 8 added incident records and evidence references based on the Stage 7 output.
- Stage 9 added approval checks and recorded failed containment when approval was missing.
- Stage 10 added simulated eradication, recovery and threat retesting.
- Stage 11 validator labels were corrected so each validator result is identified clearly.
- The Stage 11 regression check was corrected to handle unittest output correctly.

### Engineering observations

The project uses simulated data and local applications rather than live feeds or external systems.

The Stage 6 database is separate from the main NetShield database. Stage 8 preserves the Stage 7 report as evidence, Stage 9 preserves evidence before simulated containment and Stage 10 preserves evidence before simulated eradication.

Database files, logs, generated reports, raw runtime data and cache files remain outside the Git commit.

The final validation checks the project as a learning implementation. It does not replace production monitoring, enterprise change control or real incident-response procedures.

### What I Learned

Full regression testing found integration problems that isolated tests did not reveal. File naming, schema setup, SQL parameters, import paths, log state, evidence handling, approval decisions and response retesting all affected the final result.

A printed summary is not enough evidence by itself. The underlying events, database records, logs, hashes, incident records, action results, retests and audit entries must also be checked.

Containment, eradication and recovery are separate decisions. A threat should be retested after remediation before an incident is closed.

### Next expansion scope

The next phase can build on the completed events, alerts, incidents, preserved evidence, containment records and recovery results by adding:

- Approved enterprise integrations
- More realistic live-test data sources
- A persistent incident-management database
- Formal evidence-chain controls
- Investigation ownership and case management
- More detailed recovery dependencies
- Longer-term monitoring and dashboards
- Further risk-score tuning with a larger dataset
- Cloud security operations using the same engineering principles
