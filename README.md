# NetShield Phase 3 — Automation

NetShield Phase 3 is a Python security-automation project built inside an Ubuntu VirtualBox sandbox.

The project was built gradually. Each component was tested in isolation, checked with the existing project, corrected when problems were found, and then validated again. The project uses simulated security events and local test data. It does not contact external targets or use real accounts.

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

Stage 2 validation passed `14/14`. Eleven normalisation tests and six pipeline tests passed.

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

Sixteen Stage 3 authentication events were imported. Stage 3 validation passed `12/12`, and the complete Stage 3 regression run passed 39 tests.

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
- The first scoring version rated an isolated Medium event too high. Isolated low-value activity was reduced to Low.
- Direct execution of the Stage 7 runner initially failed because the project root was not available on the import path.
- The runner was corrected so it could import the correlation engine when executed directly.

### What I Learned

Correlation makes an incident easier to understand, but it should not turn every suspicious value into an IoC or automatically trigger containment.

---

## System Validation

### Clean-state validation workflow

The final validation followed the complete engineering loop:

1. Activate the Python virtual environment.
2. Compile the source, script, test and lab files.
3. Run the combined Stage 1–7 test set.
4. Run every stage validator.
5. Check duplicate imports and repeated detector runs.
6. Check accepted, rejected and raw database records.
7. Check the clean Stage 6 log after archiving the historical log.
8. Check the Stage 6 users table and test account.
9. Check Stage 7 incidents, risk scores, IoCs and behaviours.
10. Run `git diff --check`.
11. Review the documentation against the actual implementation and output.
12. Commit the Stage 6 and Stage 7 work together.

### Genuine end-to-end results

```text
Ran 64 tests

OK

STAGE 1 VALIDATION: PASS (12/12)
STAGE 2 VALIDATION: PASS (14/14)
STAGE 3 VALIDATION: PASS (12/12)
STAGE 4 VALIDATION: PASS (12/12)
STAGE 5 VALIDATION: PASS (12/12)
STAGE 6 VALIDATION: PASS (15/15)
STAGE 7 VALIDATION: PASS (15/15)
```

Stage 6 and Stage 7 were committed together:

```text
dfa2e39 Build Stage 6 SQL injection and Stage 7 correlation
```

The commit was pushed successfully to GitHub.

### Problems discovered and how they were fixed

- The Stage 2 validator counted later-stage events and was limited to the original Stage 2 files.
- Wi-Fi records were rejected from a mixed source file and were moved to a separate source file.
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

### Engineering observations

The project remains inside the Ubuntu VirtualBox sandbox and uses simulated events and local test applications.

The main NetShield database was kept separate from the Stage 6 SQL injection database. Database files, logs, generated reports, raw runtime data and cache files were not added to Git.

The Stage 7 correlation engine combines evidence but does not perform automatic containment. Disruptive response remains outside the completed scope.

### What I Learned

A script passing its own checks is not enough. The underlying database records, raw evidence, log state, duplicate behaviour and repeated-run results also need to be checked.

Full regression testing found integration problems that isolated tests did not show. File routing, schema setup, SQL placeholders, import paths, historical logs and scoring assumptions all affected the final result.

### Next expansion scope

The next stage can build on the completed events, alerts and incidents by adding:

- Incident records
- Evidence references and handling
- Last-seen and observation-count tracking
- Inventory verification requests
- Switch-port and VLAN authorisation
- Stronger endpoint process baselines
- Controlled containment requests
- Approval handling
- Eradication records
- Recovery records
- Final clean-state project sign-off
