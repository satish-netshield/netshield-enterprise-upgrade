# NetShield Phase 3 — Automation

NetShield Automation is a Python cybersecurity project built inside an Ubuntu VirtualBox sandbox.

The project is built in stages. Each stage adds one part of a controlled security-automation workflow: environment controls, data processing, identity detection, network and Wi-Fi detection, endpoint monitoring, wired-LAN checks, SQL injection detection and cross-source event correlation.

The current implementation is complete through Stage 7.

---

## Stage 1 — Environment and Access Control

### What the component does

Stage 1 creates the controlled foundation for later security components. It manages configuration, access decisions, logging, evidence protection and safe testing boundaries.

### Why it exists and how it behaves

Security automation should not begin with unrestricted access or uncontrolled response actions. Stage 1 uses default deny, least privilege and approval controls before detection logic is added.

### What was built

- Ubuntu VirtualBox sandbox
- Python virtual environment
- JSON project configuration
- SQLite database
- Application and audit logging
- File and directory permissions
- Viewer, Analyst, Responder and Administrator roles
- CYOD device allowlist
- IP allowlist and simulated blocklist
- Automation-action ACL
- SHA-256 evidence protection
- Safe test boundaries

### Observed Output

```text
PASS: RBAC follows least privilege
PASS: Automation ACL follows default deny
PASS: Evidence hash and read-only protection is valid

STAGE 1 VALIDATION: PASS (12/12)
```

### Testing Notes

- Eleven Stage 1 unit tests passed.
- Stage 1 validation passed 12/12.
- Configuration, database metadata, roles, audit records, permissions and evidence integrity were verified.

### What I Learned

A safe foundation makes later detection work easier to test and reduces the risk of accidentally creating disruptive automation.

---

## Stage 2 — Security Data Pipeline

### What the component does

Stage 2 receives simulated security events, validates them, normalises them and stores them in SQLite for later detection.

### Why it exists and how it behaves

Security events may contain missing, invalid or inconsistent values. Detection becomes less reliable when data is not checked before storage.

### Event sources

- Authentication
- Network
- Wi-Fi and CYOD
- Endpoint and CPU
- Application

### Pipeline workflow

1. Generate safe simulated events.
2. Write each source to a separate JSONL file.
3. Read one record at a time.
4. Parse and validate each JSON object.
5. Confirm the source type matches the filename.
6. Convert timestamps to UTC.
7. Validate IP addresses, MAC addresses and CPU values.
8. Store accepted events in SQLite.
9. Preserve rejected records with their reasons.
10. Record import totals and audit activity.

### Observed Output

```text
PASS: Generated 19 safe simulated records

STAGE 2 IMPORT: files=5 total=19 accepted=15 rejected=4
```

### Testing Notes

- Eleven normalisation tests passed.
- Six pipeline tests passed.
- Stage 2 validation passed 14/14.
- Fifteen records were accepted and four were rejected.
- UTC conversion, raw-event preservation, duplicate protection and import totals were verified.

### Engineering Observation

The Stage 2 validator initially counted new Stage 3 authentication events. It was corrected to check only the original Stage 2 source files.

### What I Learned

JSONL allows one malformed record to be rejected without stopping the rest of the file.

---

## Stage 3 — Identity and Authentication Detection

### What the component does

Stage 3 groups authentication events by user, address, device, location and time window, then creates alerts when activity matches an identity rule.

### Why it exists and how it behaves

Identity attacks can provide early evidence of account compromise. Detecting suspicious login behaviour supports earlier investigation and controlled response.

### Detection rules

- Repeated failed logins
- Possible brute force
- Successful login after repeated failures
- MFA failure anomaly
- Login from a new device
- Login from an unusual location
- Impossible travel
- Suspicious role change
- Known VPN exceptions

### Initial severity

| Detection | Initial severity |
| --- | --- |
| Repeated Failed Logins | Medium |
| Possible Brute Force | High |
| Successful Login After Failures | High |
| MFA Failure Anomaly | High |
| Login From New Device | Medium |
| Login From Unusual Location | Medium |
| Impossible Travel | High |
| Suspicious Role Change | Critical in the current baseline |

These are initial labels, not a final numerical risk score.

### Observed Output

```text
[High] Possible Brute Force | user=analyst01
[High] Successful Login After Failures | user=analyst01
[High] MFA Failure Anomaly | user=analyst01
[Critical] Suspicious Role Change | user=trainee01

STAGE 3 DETECTION: events=19 detections=11 new=11 existing=0 vpn_exceptions=2
```

### Duplicate protection

A deterministic SHA-256 alert key prevents the same detection pattern from creating duplicate alert records.

```text
STAGE 3 DETECTION: events=19 detections=11 new=0 existing=11 vpn_exceptions=2
```

### False-positive investigation

The replacement laptop created a new-device alert because it was authorised but not yet registered in the CYOD inventory.

The alert was preserved, investigated, classified as a false positive and recorded in the audit trail.

### Testing Notes

- Sixteen Stage 3 authentication events were imported.
- Eleven identity-detection tests passed.
- The full Stage 3 regression run passed 39 tests.
- Stage 1, Stage 2 and Stage 3 validation passed.
- VPN exceptions and the false-positive audit record were verified.

### What I Learned

A detection is not always proof of malicious activity. A legitimate device can still require investigation when inventory information is incomplete.

---

## Stage 4 — Network, CYOD and Wi-Fi Detection

### What the component does

Stage 4 checks network connections, CYOD device identity, Wi-Fi policy and repeated activity. Related alerts are correlated using the MAC address and supporting evidence.

### Why it exists and how it behaves

Identity events show account activity, but they do not show how a device connects to the network. Stage 4 adds network and Wi-Fi context while preserving source validation.

The MAC address is the primary device identity. IP address, hostname, username, location, event time and event type provide supporting evidence.

### Detection rules

- Suspicious IP address
- Repeated connection attempts
- Port scanning
- Unknown CYOD device
- Unregistered MAC address
- MAC reuse or possible spoofing
- Wi-Fi zone violation
- WPA3 policy violation
- WPA2 downgrade attempt
- Rogue access point

### Workflow

1. Generate controlled network and Wi-Fi events.
2. Keep network and Wi-Fi records in separate source files.
3. Validate each source before storage.
4. Import both sources into `security_events`.
5. Compare MAC addresses with the CYOD inventory.
6. Apply network and Wi-Fi rules.
7. Group related evidence by MAC address.
8. Preserve high-impact detections.
9. Save unique alerts.
10. Record the detection run.

### Wi-Fi zones

- `Lab Zone A`: approved test zone
- `Lab Zone B`: restricted test zone
- `Parking Lot`: restricted test zone
- `Public Area`: restricted test zone

A restricted-zone event is evidence for investigation, not automatic proof of compromise.

### Observed Output

```text
[High] MAC Address Reuse or Possible Spoofing | mac=08:00:27:cf:49:71
[High] Port Scanning | mac=02:42:ac:11:00:25
[Critical] Rogue Access Point | mac=02:42:ac:11:00:88
[Medium] Repeated Connection Attempts | mac=02:42:ac:11:00:55

STAGE 4 DETECTION: events=23 raw_detections=43
correlated_alerts=12 new_alerts=12 existing_alerts=0
```

### Testing Notes

- Twenty-three Stage 4 events were accepted.
- Twelve correlated network alerts were produced.
- MAC reuse, port scanning, repeated connections, WPA3, WPA2 and rogue access-point detections were verified.
- A repeated run created zero new alerts and counted 12 existing alerts.
- Stage 4 validation passed 12/12.

### Engineering Observations

- A mixed network and Wi-Fi file initially caused six Wi-Fi records to fail source verification.
- Separate source files preserved the existing collector rules.
- The detection runner initially used the wrong SQL placeholder count.
- The Stage 3 initializer initially reset completed metadata during Stage 4 setup.
- Each issue was corrected and retested.

### What I Learned

Network and Wi-Fi sources can be correlated without placing them in the same input file. Source validation must happen before correlation.

---

## Stage 5 — Endpoint and Wired-LAN Detection

### What the component does

Stage 5 monitors endpoint CPU activity, endpoint processes and wired-LAN access. It uses the MAC address as the primary device identity and adds endpoint and physical-zone evidence.

### Why it exists and how it behaves

Network and Wi-Fi alerts do not show what is happening on the endpoint or whether a wired connection is allowed in a restricted area. Stage 5 adds CPU, process, user, role and wired-zone checks.

Approved CPU stress testing is recognised so authorised testing is not reported as suspicious.

### Detection rules

- Unexpected CPU activity
- Repeated high CPU activity
- Unauthorised CPU stress tests
- Unknown endpoint processes
- Restricted wired access
- MAC reuse or possible spoofing

### Workflow

1. Generate endpoint and wired-LAN events.
2. Store endpoint events in `endpoint_stage5_events.jsonl`.
3. Store wired events in `network_stage5_events.jsonl`.
4. Validate both sources before storage.
5. Apply CPU and process rules.
6. Check wired access against zone and role rules.
7. Correlate supporting evidence by MAC address.
8. Group repeated observations from the same device and context.
9. Save unique alerts.
10. Record the detection run.

### Wired-LAN rules

- `Lab Zone A` is approved for the simulated test roles.
- The simulated Server Room permits responder and administrator access.
- Analyst access to the Server Room creates a High alert.
- Approved responder access does not create an alert.
- Different MAC addresses remain separate investigations.
- A restricted wired event is evidence for investigation, not automatic proof of compromise.

### MAC-reuse rule

A location change alone does not create a MAC-reuse alert.

Possible MAC reuse requires the same MAC, conflicting hostname or username evidence and overlapping event times.

### Observed Output

```text
[High] Repeated High CPU Activity | identity=02:42:ac:11:00:25
[Critical] Unexpected CPU Activity | identity=02:42:ac:11:00:25
[High] Unauthorised CPU Stress Test | identity=02:42:ac:11:00:77
[High] Unknown Endpoint Process | identity=02:42:ac:11:00:99
[High] Restricted Wired Access | identity=02:42:ac:11:00:25
events=LAN5-002, LAN5-003

STAGE 5 DETECTION: events=14 detections=10 new_alerts=10 existing_alerts=0
```

### Testing Notes

- Ten endpoint events and four wired-LAN events were generated.
- Fourteen Stage 5 events were accepted.
- Ten endpoint alerts were produced.
- Approved CPU stress testing created no alert.
- Repeated high-CPU activity and restricted wired access were grouped.
- Location change alone did not create MAC reuse.
- Re-importing the same events rejected all 14 duplicates.
- A repeated run created zero new alerts and counted 10 existing alerts.
- Eight Stage 5 detector tests passed.
- Stage 5 validation passed 12/12.

### Engineering Observations

- The first wired filename did not match its `network` source type.
- The generator was corrected to create `network_stage5_events.jsonl` directly.
- The endpoint-alert table was added to the tracked schema.
- Simulated role mappings were needed because the application role table contains only the project administrator.
- MAC-reuse logic was corrected to require conflicting identity evidence with time overlap.
- Repeated wired observations were grouped by MAC, detection type, location and time window.

### What I Learned

High CPU usage is not automatically malicious because approved testing must be recognised. MAC address is useful as a baseline, but hostname, username and event time are needed to assess possible spoofing.

---

## Stage 6 — SQL Injection Detection

### What the component does

Stage 6 creates an isolated local application and SQLite database to demonstrate SQL injection detection and secure query remediation.

### Why it exists and how it behaves

Network and endpoint detections do not show whether an application safely handles user input before sending it to a database.

Stage 6 compares a deliberately vulnerable query with a corrected parameterised query.

### What was built

- Separate SQL injection lab
- Separate SQLite test database
- Local Python test application
- One isolated test account
- Vulnerable string-concatenated login query
- Corrected parameterised login query
- Suspicious-input detection
- Source-IP tracking
- Database-error logging
- Repeated abnormal-request analysis
- JSONL request evidence
- Structured application-event logging
- Detection report generation
- Remediation retesting
- Database-integrity verification

### Safety boundary

- Testing uses only the local Ubuntu application.
- The lab database is separate from the main NetShield database.
- No external target is contacted.
- No public system is tested.
- No real account or credential is used.
- The vulnerable function is used only for controlled demonstration.

### Vulnerable query behaviour

The vulnerable function joins username and password values directly into the SQL statement.

The controlled input:

```text
' OR 1=1 --
```

changed the query behaviour and caused the vulnerable function to authenticate incorrectly.

### Secure remediation

The corrected function uses:

```sql
WHERE username = ? AND password = ?
```

The same injection input failed against the corrected function.

### Observed Output

```text
PASS: Generated 7 local SQL test requests
VULNERABLE_AUTHENTICATION_BYPASSES: 4
DATABASE_ERRORS: 1
PARAMETERISED_REMEDIATION_BLOCKS: 1
REQUEST_FILE: /home/netshield01/netshield-phase3/lab/sql_injection/data/stage6_requests.jsonl
```

```text
STAGE 6 SQL INJECTION DETECTION
REQUESTS ANALYSED: 7
VULNERABLE BYPASSES: 4
DATABASE ERRORS: 1
REMEDIATION RETESTS BLOCKED: 1
REPEATED ABNORMAL SOURCES: 1
LOGGED EVENTS: 7
REPORT: /home/netshield01/netshield-phase3/lab/sql_injection/outputs/stage6_detection_report.json
```

### Clean evidence

```text
Vulnerable request IDs:
SQL6-002
SQL6-003
SQL6-004
SQL6-005

Database-error request ID:
SQL6-006

Blocked parameterised retest:
SQL6-007

Repeated abnormal source:
192.0.2.44
```

### Problems discovered and fixed

- The first bypass summary counted two events although four vulnerable requests authenticated. The summary logic was corrected.
- One test did not genuinely verify the application log because the application used a fixed path. The application and test were corrected to accept an isolated log path.
- Earlier test runs left 36 cumulative application events in the log. The previous log was archived.
- The clean run then produced seven requests and seven application events.

### Testing Notes

- Seven Stage 6 unit tests passed.
- Four vulnerable authentication bypasses were demonstrated.
- One malformed vulnerable request produced a database error.
- Three abnormal requests from `192.0.2.44` were identified as repeated activity.
- One parameterised retest blocked the bypass.
- The SQLite users table remained present.
- Stage 6 validation passed 15/15.

### What I Learned

Secure query construction should be tested by demonstrating the original weakness, applying the correction and repeating the same controlled test after remediation.

---

## Stage 7 — Event Correlation, Risk Scoring and IoC Extraction

### What the component does

Stage 7 connects related security events from earlier stages and turns them into context-rich incidents.

### Why it exists and how it behaves

Earlier stages produced alerts from individual security areas. Stage 7 combines related identity, network, endpoint and application evidence so risk can be assessed with more context.

Events are correlated using:

- Username
- IP address
- MAC address
- Hostname
- Event time

Process, location, source type and detection type provide supporting context.

### What was built

- Stage 7 correlation configuration
- Controlled cross-source events
- Time-window matching
- Shared-identity field matching
- Multi-source event grouping
- Risk-score calculation
- Low, Medium, High and Critical severity bands
- Approved-device exceptions
- Known-VPN exceptions
- IoC extraction
- Behaviour classification
- Separation of IoCs from behaviours
- Isolated low-value alert reduction
- Deterministic incident keys
- JSON correlation report
- Stage 7 tests and validation

### Correlation behaviour

Related events are combined when they share configured identity evidence and occur within the configured time window.

Unrelated events remain separate investigations.

### Risk-scoring behaviour

Risk points are added for detection severity and stronger conditions such as:

- Authentication-bypass evidence
- Database errors
- Repeated abnormal activity
- Unknown endpoint processes
- Suspicious IP activity
- Evidence from multiple source types

Approved-device and known-VPN exceptions reduce risk when the activity has a known explanation.

One isolated Low or Medium event is reduced when stronger related evidence is absent.

### IoC and behaviour separation

Observable values such as IP address, MAC address, hostname and process name are extracted as IoCs.

Usernames remain incident context.

Repeated failed logins and repeated connection attempts are classified as behaviours rather than IoCs.

### Observed Output

```text
STAGE 7 CORRELATION
EVENTS ANALYSED: 7
INCIDENTS CREATED: 3
[Critical] score=30 events=4 iocs=4 behaviours=1
[Low] score=1 events=2 iocs=0 behaviours=0
[Low] score=3 events=1 iocs=0 behaviours=1
REPORT: /home/netshield01/netshield-phase3/lab/sql_injection/outputs/stage7_correlation_report.json
```

### Correlation evidence

```text
Main incident:
events=4
source types=authentication, network, endpoint, application
severity=Critical
risk score=30
IoCs=4
behaviours=1

Approved-device and known-VPN incident:
events=2
severity=Low
risk score=1

Isolated low-value network event:
events=1
severity=Low
risk score=3
```

### Problems discovered and fixed

- The first IoC extraction included the username. The extraction logic was corrected so usernames remain incident context.
- An isolated medium network event was initially scored too strongly. The scoring logic was corrected to reduce isolated low-value activity.
- The corrected engine preserved the Critical multi-source incident while applying the approved-device and VPN exceptions.

### Testing Notes

- Seven controlled events were analysed.
- Three incidents were created.
- Four related events were combined into one multi-source incident.
- Four observable IoCs were extracted from the main incident.
- Repeated failed logins remained a behaviour.
- Approved-device and known-VPN exceptions reduced risk.
- Automatic containment remained disabled.
- Five Stage 7 correlation tests passed.
- Stage 7 validation passed 15/15.

### What I Learned

Several related alerts can provide stronger context than disconnected alerts, but one isolated low-value event should not automatically become high risk.

IoCs and behaviours should be kept separate because they support different investigation decisions.

---

## System Validation

### Clean-state validation workflow

1. Activate the Python virtual environment.
2. Compile the project and Stage 6–7 lab files.
3. Run the complete Stage 1–7 unit-test set.
4. Run the Stage 1–7 validators.
5. Check duplicate imports and repeated detector runs.
6. Check VPN exceptions and false-positive classification.
7. Check MAC correlation and repeated wired grouping.
8. Check the Stage 6 vulnerable and parameterised query comparison.
9. Check the clean Stage 6 application log.
10. Check the Stage 6 database remains intact.
11. Check Stage 7 event grouping and risk scoring.
12. Check IoC and behaviour separation.
13. Check approved-device and VPN exceptions.
14. Check isolated low-value alert reduction.
15. Check that automatic containment remains disabled.
16. Check documentation and schema consistency.
17. Run `git diff --check`.

### Observed Results

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

### Stage 6 results

```text
requests analysed=7
vulnerable bypasses=4
database errors=1
repeated abnormal sources=1
parameterised remediation blocks=1
logged events=7
users table intact
```

### Stage 7 results

```text
events analysed=7
incidents created=3
main incident severity=Critical
main incident score=30
main incident IoCs=4
isolated low-value severity=Low
approved-device and VPN exception applied
automatic containment disabled
```

### Problems discovered and fixed

- The Stage 2 validator initially counted new Stage 3 authentication events.
- Wi-Fi records were initially placed in a network-named file and rejected.
- The Stage 4 runner initially had the wrong SQL placeholder count.
- The Stage 3 initializer reset completed metadata during Stage 4 setup.
- Stage 5 wired events initially used the wrong filename for their source type.
- The Stage 5 endpoint-alert table was missing from the tracked schema.
- MAC-reuse logic initially treated a location change as sufficient evidence.
- The Stage 6 bypass summary initially undercounted authenticated vulnerable requests.
- The Stage 6 application log initially mixed previous test runs with the current run.
- Stage 7 initially classified username as an IoC.
- Stage 7 initially scored an isolated medium event too strongly.
- Each issue was corrected and retested.

### Engineering Observations

- Complete regression testing exposed integration issues not visible in isolated tests.
- The shared event model allows validated sources to be examined together later.
- Duplicate protection prevents repeated imports and detector runs from increasing totals.
- Application-layer testing adds visibility that network and endpoint events cannot provide by themselves.
- Cross-source correlation provides more context than disconnected alerts.
- Risk scoring is useful for prioritisation but depends on the quality of the rules and evidence.
- IoC extraction and behaviour classification should remain separate.
- The project still uses simulated events and local testing rather than live feeds.

### What I Learned

Testing each component separately is important, but full regression testing shows whether the stages work together.

Small integration problems can remain hidden until the complete workflow is run again.

Security results must be checked against the underlying records, not only the summary printed by a script.

### Known Limitations

- Stages 1–5 use local simulated events rather than live feeds.
- Stage 6 uses a deliberately vulnerable local function for demonstration.
- Pattern-based input detection may not identify every injection technique.
- Source IP does not prove the identity of the requester.
- Stage 7 risk scoring uses the current learning-project rules and requires further tuning.
- Stage 7 does not yet create incidents in the main NetShield database.
- The project does not yet use a production web server or password-hashing system.
- Incident response, containment, eradication and recovery are not yet implemented.

### Next Expansion Scope

The next stage should add:

- Incident records
- Evidence references and preservation
- Investigation status
- Controlled containment requests
- Approval handling
- Simulated containment
- Eradication records
- Recovery records
- Final clean-state project validation and sign-off
