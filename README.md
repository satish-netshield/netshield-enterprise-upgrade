# NetShield Phase 3 — Automation

NetShield Automation is a Python cybersecurity project built inside an Ubuntu VirtualBox sandbox.

The project is being developed in stages. Each stage adds one part of a controlled security-automation workflow: foundation, data pipeline, identity detection, network detection, correlation, incident handling and response.

The current implementation is complete through Stage 3.

---

## Stage 1 — Environment and Access Control

Stage 1 created the controlled foundation required by the later security components.

### What it does

It establishes the project environment, access rules, audit records, evidence protection and safe testing boundaries.

### Why it exists

Security automation must not begin with unrestricted access or uncontrolled response actions. Stage 1 uses default deny, least privilege and approval controls before any detection logic is added.

### What was built

- Ubuntu VirtualBox sandbox
- Python virtual environment
- JSON project configuration
- SQLite database
- Application and audit logging
- File and directory permissions
- Viewer, Analyst, Responder and Administrator roles
- Role-Based Access Control
- CYOD device allowlist
- IP allowlist and simulated blocklist
- Automation-action ACL
- SHA-256 evidence protection
- Safe test boundaries

### Access and response model

- Unknown roles and permissions are denied.
- Unknown devices and IP addresses are not automatically trusted.
- Low-risk actions may run automatically.
- Disruptive actions require approval.
- Physical and infrastructure changes remain manual.

### Testing notes

- Eleven Stage 1 unit tests passed.
- Stage 1 validation passed all 12 checks.
- JSON configuration loaded successfully.
- Database metadata, role assignments and audit records were created.
- File permissions and evidence integrity were verified.

### Example output

```text
PASS: RBAC follows least privilege
PASS: Automation ACL follows default deny
PASS: Evidence hash and read-only protection are valid

STAGE 1 VALIDATION: PASS (12/12)
```

### What I learned

A safe foundation makes later detection work easier to test and reduces the risk of accidentally creating disruptive automation.

---

## Stage 2 — Security Data Pipeline

Stage 2 created the pipeline that receives, validates, normalises and stores security events.

### What it does

The pipeline reads simulated JSONL events from five sources and prepares consistent records for detection.

### Why it exists

Security events arrive in different formats and may contain missing, invalid or inconsistent values. Detection becomes less reliable when the data is not checked before storage.

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

### Rejected data

The pipeline deliberately rejected:

- Invalid JSON
- A missing event ID
- An invalid IP address
- CPU usage above 100 percent

Rejected input was kept with its source filename, line number, original content and failure reason.

### Genuine output

```text
PASS: Generated 19 safe simulated records

application_events.jsonl: accepted=3 rejected=1 status=completed_with_rejections
authentication_events.jsonl: accepted=3 rejected=1 status=completed_with_rejections
endpoint_events.jsonl: accepted=3 rejected=1 status=completed_with_rejections
network_events.jsonl: accepted=3 rejected=1 status=completed_with_rejections
wifi_events.jsonl: accepted=3 rejected=0 status=completed

STAGE 2 IMPORT: files=5 total=19 accepted=15 rejected=4
```

### Testing notes

- Eleven Stage 2 normalisation tests passed.
- Six Stage 2 pipeline tests passed.
- Stage 2 validation passed all 14 checks.
- Fifteen records were accepted and four were rejected.
- Timestamps were normalised to UTC.
- Accepted raw events were preserved.
- Duplicate-event protection was verified.
- Import-batch totals reconciled correctly.

### Engineering observation

When Stage 3 added more authentication events, the original Stage 2 validator counted them as if they were Stage 2 records. The validator was corrected to check only the original Stage 2 source files. Stage 2 then passed 14/14 again.

### What I learned

JSONL is useful for this stage because one malformed line can be rejected without stopping the rest of the file. Keeping rejected input made the validation problems visible instead of silently removing them.

---

## Stage 3 — Identity and Authentication Detection

Stage 3 uses accepted authentication events to identify suspicious identity activity.

### What it does

The identity detector groups authentication events by user, address, device, location and time window, then creates alerts when activity matches a detection rule.

### Why it exists

Identity attacks can provide early evidence of account compromise. Detecting suspicious login behaviour before network or endpoint impact supports earlier investigation and controlled response.

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

### Alert severity

Current Stage 3 severity is rule-based:

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

These are initial labels, not a final numerical risk score. Later correlation should reassess combined indicators.

### Genuine output

```text
[High] Possible Brute Force | user=analyst01 |
events=AUTH-BF-001, AUTH-BF-002, AUTH-BF-003, AUTH-BF-004, AUTH-BF-005

[High] Successful Login After Failures | user=analyst01 |
events=AUTH-BF-001, AUTH-BF-002, AUTH-BF-003, AUTH-BF-004, AUTH-BF-005, AUTH-BF-006

[High] MFA Failure Anomaly | user=analyst01 |
events=AUTH-MFA-001, AUTH-MFA-002, AUTH-MFA-003

[Critical] Suspicious Role Change | user=trainee01 |
events=AUTH-ROLE-001

STAGE 3 DETECTION: events=19 detections=11 new=11 existing=0 vpn_exceptions=2
```

### Duplicate protection

A deterministic SHA-256 alert key prevents the same detection pattern from creating duplicate alert records.

The repeated detector run produced:

```text
STAGE 3 DETECTION: events=19 detections=11 new=0 existing=11 vpn_exceptions=2
```

The database remained at 11 alerts.

### False-positive investigation

The `Replacement-Laptop` event created a `Login From New Device` alert because the device was authorised but not yet registered in the CYOD inventory.

The alert was:

- Preserved
- Investigated
- Classified as a false positive
- Recorded in the audit trail

The alert was not deleted and the CYOD inventory was not automatically changed.

### Engineering observations

- The current five-minute authentication window may be too broad for rapid brute-force detection.
- Impossible travel combined with MFA failures, brute force or a suspicious successful login should receive stronger severity.
- Suspicious role changes should be assessed according to the actual privilege change and authorisation.
- An approved device can still create a valid new-device alert when inventory registration is incomplete.
- Duplicate protection prevents alert flooding but does not yet track unresolved inventory conditions over time.
- Future logic should update last-seen time, observation count, escalation state and alert reopening.
- Stage 4 should correlate identity alerts with CYOD, Wi-Fi, WPA3, IP and device-consistency evidence.

### Testing notes

- Sixteen Stage 3 authentication events were imported.
- Eleven Stage 3 detector tests passed.
- The full regression run passed 39 tests.
- Stage 1 validation passed 12/12.
- Stage 2 validation passed 14/14.
- Stage 3 validation passed 12/12.
- Two known VPN events were recorded as exceptions.
- The replacement-device false-positive audit record was verified.

### What I learned

A detection is not always proof of malicious activity. A new device can be legitimate but still require investigation when it is missing from the technical inventory. Duplicate prevention must also be combined with ongoing monitoring so unresolved conditions are not ignored.

---

## System Validation

The current system validation confirms that the completed foundation, data pipeline and identity detection components operate together.

### Current validation workflow

1. Compile the Python project files.
2. Run all Stage 1–3 unit tests.
3. Run the Stage 1 validator.
4. Run the Stage 2 validator.
5. Run the Stage 3 validator.
6. Check duplicate detection behaviour.
7. Check VPN exception handling.
8. Check false-positive investigation records.
9. Check the Git staged-file review.

### Genuine results

```text
Ran 39 tests

OK

STAGE 1 VALIDATION: PASS (12/12)

STAGE 2 VALIDATION: PASS (14/14)

STAGE 3 VALIDATION: PASS (12/12)
```

The Stage 3 VirtualBox snapshot was also captured:

```text
NetShield-Phase3-Stage3-Validated
```

### Problems discovered and fixed

- The Stage 2 validator initially counted the new Stage 3 authentication events.
- The validator was corrected to check only the original Stage 2 source files.
- Duplicate detector execution was tested and confirmed to create no additional alert records.
- The replacement-device alert was investigated and classified as a false positive.

### Current limitations

- Events are simulated rather than collected from live systems.
- Wi-Fi heat-map data is simulated because the VM does not use a physical Wi-Fi adapter.
- The VPN exception is simulated.
- The CYOD inventory currently contains one primary local test asset.
- Ping and traceroute do not prove a user’s physical location.
- Full network, Wi-Fi, WPA3, endpoint, SQL injection, correlation, containment and recovery work remains to be completed.
- SQLite is suitable for this local lab but not for distributed scaling.

### What comes next

The next component will build network, CYOD and Wi-Fi detection, including:

- Device consistency checks
- Suspicious IP detection
- Port-scanning behaviour
- WPA3 policy violations
- WPA2 downgrade attempts
- Unknown wired and wireless devices
- Wi-Fi heat-map zone investigation
- Rogue access-point scenarios
- Network-related false-positive handling

The completed identity foundation will provide context for those later network detections.
