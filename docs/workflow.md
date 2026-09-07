# Project Workflow

## Stage 1 — Environment and access control

Stage 1 created the controlled foundation before detection work began.

### Foundation

1. Load project settings.
2. Create the SQLite database from the tracked schema.
3. Save project metadata and assign the project-owner role.
4. Configure application and audit logging.
5. Apply protected file and directory permissions.

### Access decisions

1. Identify the user role.
2. Allow only explicitly assigned permissions.
3. Check the automation ACL before response actions.
4. Require approval for disruptive actions.
5. Deny unknown roles, permissions and actions.

### Device, IP and evidence decisions

1. Compare devices with the CYOD inventory.
2. Validate IP addresses.
3. Check the blocklist before the allowlist.
4. Preserve evidence and calculate its SHA-256 hash.
5. Protect the evidence and verify its hash.

---

## Stage 2 — Security data pipeline

Stage 2 prepared consistent events for later detection.

### Event workflow

1. Generate simulated authentication, network, Wi-Fi, endpoint and application events.
2. Write each source to a separate JSONL file.
3. Create an import batch.
4. Read one record at a time.
5. Parse and validate each record.
6. Confirm the source type matches the filename.
7. Convert timestamps to UTC.
8. Validate IP addresses, MAC addresses and CPU values.
9. Store accepted events in SQLite.
10. Preserve rejected records and their reasons.

### Duplicate handling

1. Compare the source filename and source event ID.
2. Accept the first valid occurrence.
3. Reject later duplicates.
4. Include duplicate records in the import totals.

### Problems and solutions

- Invalid JSON, missing event IDs, invalid IP addresses and invalid CPU values were rejected.
- Rejected records were preserved with their original input and failure reason.
- The Stage 2 validator initially counted later Stage 3 events as original Stage 2 data.
- The validator was corrected to check only the original Stage 2 source files.

---

## Stage 3 — Identity and authentication detection

Stage 3 used accepted authentication events to identify suspicious identity activity.

### Detection workflow

1. Load identity rules and user baselines.
2. Read accepted authentication events.
3. Group events by user, IP address and time window.
4. Detect repeated failures and possible brute force.
5. Detect successful login after repeated failures.
6. Detect MFA anomalies.
7. Detect new devices and unusual locations.
8. Detect impossible travel.
9. Detect suspicious role changes.
10. Apply known VPN exceptions.

### Alert and investigation workflow

1. Create a deterministic alert key.
2. Store the detection, severity, event IDs and evidence.
3. Ignore duplicate alerts.
4. Review suspicious activity.
5. Confirm whether the activity is authorised.
6. Classify legitimate activity as a false positive.
7. Record the investigation and audit event.

The replacement laptop showed that a legitimate device can still create an alert when inventory information is incomplete.

---

## Stage 4 — Network, CYOD and Wi-Fi detection

Stage 4 added network and wireless context to the identity detections.

### Event workflow

1. Generate controlled network and Wi-Fi events.
2. Keep network and Wi-Fi files separate.
3. Validate each source before storage.
4. Import accepted records into `security_events`.
5. Compare MAC addresses with the CYOD inventory.
6. Apply network and Wi-Fi detection rules.
7. Group related activity by MAC address.
8. Preserve the original evidence.
9. Save unique alerts.
10. Record the detection run.

### Detection workflow

1. Check suspicious IP addresses.
2. Detect repeated connections.
3. Detect port scanning.
4. Check unknown and unregistered devices.
5. Check Wi-Fi zones.
6. Check WPA3 and AES compliance.
7. Detect WPA2 downgrade attempts.
8. Detect rogue access points.
9. Check for conflicting MAC identity evidence.

### Problems and solutions

- Wi-Fi records were initially placed in a network-named file and rejected.
- Separate source files were created to preserve source validation.
- The detection runner supplied more source files than its SQL statement accepted.
- Dynamic SQL placeholders were added for the changing file list.
- Stage 4 setup initially reset Stage 3 metadata.
- The initializer was corrected to preserve earlier completion status.
- Repeated activity initially produced separate alerts.
- MAC-based correlation grouped related activity while keeping different devices separate.

---

## Stage 5 — Endpoint and wired-LAN detection

Stage 5 extended monitoring to endpoint activity and wired connections.

### Endpoint workflow

1. Generate controlled endpoint and wired-LAN events.
2. Store endpoint events in `endpoint_stage5_events.jsonl`.
3. Store wired events in `network_stage5_events.jsonl`.
4. Validate both sources.
5. Compare CPU activity with configured thresholds.
6. Exclude approved CPU stress testing.
7. Detect unapproved stress tests and unknown processes.
8. Preserve endpoint evidence.

### Wired-LAN workflow

1. Check the connection type.
2. Check the wired zone.
3. Check the user’s simulated role.
4. Check approval status.
5. Detect restricted access.
6. Group repeated observations only when the device and context match.
7. Keep different MAC addresses as separate investigations.

### MAC-reuse workflow

1. Group events by MAC address.
2. Compare hostnames and usernames.
3. Compare event times.
4. Ignore a location change by itself.
5. Create a possible-spoofing alert only when conflicting identity evidence overlaps.

### Problems and solutions

- The first wired filename did not match its `network` source type.
- The generator was corrected to create the correct filename.
- The endpoint-alert table was initially created only by the initializer.
- The table was added to the tracked schema.
- A location change initially created a MAC-reuse alert.
- The rule was changed to require conflicting hostname or username evidence with time overlap.
- The application role table contained only the project administrator.
- Simulated role mappings were added for endpoint and wired-LAN testing.
- Repeated wired observations were grouped by MAC, detection type, location and time window.

---

## Stage 6 — SQL injection detection

Stage 6 added application-layer testing inside a separate local lab.

### Lab workflow

1. Create the isolated SQL injection lab.
2. Create a separate SQLite database.
3. Create one local test account.
4. Confirm that no external target or real account is used.
5. Generate controlled requests.
6. Run the requests against the vulnerable and corrected functions.
7. Record authentication results, source IPs and database errors.
8. Save the request evidence and application events.
9. Generate the detection report.

### Vulnerable-query workflow

1. Send a normal login request.
2. Send controlled injection input to the vulnerable function.
3. Check whether authentication succeeds incorrectly.
4. Record suspicious input patterns.
5. Track repeated abnormal requests by source IP.
6. Record database errors.

The vulnerable function uses string concatenation only for local demonstration and is not suitable for real use.

### Remediation workflow

1. Replace string concatenation with parameterised SQL.
2. Run the same injection input against the corrected function.
3. Confirm the bypass fails.
4. Confirm the corrected query does not produce a database error.
5. Confirm the users table remains intact.
6. Record the retest result.

### Problems and solutions

- The first summary counted two vulnerable bypasses although four vulnerable requests authenticated.
- The summary was corrected to use the actual query result.
- One test did not genuinely verify the application log because the application used a fixed path.
- The application and test were corrected to accept an isolated log path.
- Earlier runs left 36 cumulative events in the log.
- The old log was archived before the clean run.
- The clean run then produced seven requests and seven application events.

---

## Stage 7 — Event correlation, risk scoring and IoC extraction

Stage 7 connected related events from earlier stages.

### Correlation workflow

1. Load the Stage 7 correlation configuration.
2. Load controlled identity, network, endpoint and application events.
3. Compare username, IP address, MAC address and hostname.
4. Check the configured time window.
5. Use process, location, source type and detection type as supporting context.
6. Group related events into one incident.
7. Keep unrelated events separate.
8. Create a deterministic incident key.
9. Write the correlation report.

### Risk-scoring workflow

1. Assign points from detection severity.
2. Add points for strong indicators.
3. Add points when several source types are involved.
4. Apply approved-device and known-VPN exceptions.
5. Reduce isolated low-value activity.
6. Map the final score to Low, Medium, High or Critical.
7. Preserve the reasons for the score.

### IoC and behaviour workflow

1. Extract observable values such as IP address, MAC address, hostname and process name.
2. Keep username as identity context.
3. Record repeated failures and repeated connections as behaviours.
4. Keep IoCs separate from behaviours.
5. Preserve the source event ID for each extracted IoC.

### Problems and solutions

- The first engine treated username as an IoC.
- The extraction logic was corrected so username remained context.
- An isolated Medium event was initially treated too strongly.
- Its risk was reduced to Low when no stronger related evidence existed.
- The direct Stage 7 runner initially failed to import the project package.
- The runner was corrected to load the project root.

---

## Stage 8 — Incident management and evidence handling

Stage 8 converted Stage 7 incidents into traceable incident records.

### Incident workflow

1. Read the Stage 7 correlation report.
2. Create one incident record for each Stage 7 incident.
3. Assign a unique incident ID.
4. Record the detection name, severity and risk score.
5. Start each incident in `New` status.
6. Preserve the Stage 7 report as evidence.
7. Calculate and store its SHA-256 hash.
8. Record investigation notes and analyst decisions.
9. Record false-positive classification fields and IoCs.
10. Create the incident timeline.
11. Generate JSON incident records.
12. Generate human-readable incident reports.
13. Write the audit trail.

### Status workflow

1. Create the incident in `New` status.
2. Move it to `Investigating` after review begins.
3. Move it to `Contained` only after approved containment.
4. Move it to `Eradicated` only after the cause has been removed.
5. Move it to `Recovered` after normal operation is restored.
6. Move it to `Closed` after the investigation is complete.

The project defines the permitted lifecycle. Current Stage 8 creation starts incidents in `New`, and the implementation validates permitted transitions. Persistent lifecycle updates are handled by later response stages.

### Engineering reasoning

Incident records keep the detection, evidence, decisions and actions connected. Evidence is preserved before later handling so the original report remains available for review.

---

## Stage 9 — Controlled containment automation

Stage 9 added simulated containment actions using Stage 8 evidence.

### Containment workflow

1. Read the Stage 8 incident summary and supporting evidence.
2. Preserve the evidence before taking action.
3. Calculate the evidence SHA-256 hash.
4. Check whether the requested action is allowed.
5. Check whether approval is required.
6. Run only the simulated containment action.
7. Record the target and approval state.
8. Record whether the action succeeded or failed.
9. Write one audit entry for each action.
10. Generate the containment report.

### Containment actions

1. Add a suspicious IP address to the simulated blocklist.
2. Quarantine an unknown CYOD device.
3. Restrict a suspicious account temporarily.
4. Revoke a simulated user session.
5. Isolate a suspicious process.
6. Reject a non-compliant Wi-Fi connection.

### Approval workflow

1. Allow the simulated blocklist action according to the existing ACL.
2. Require approval for device quarantine.
3. Require approval for account restriction.
4. Require approval for session revocation.
5. Require approval for process isolation.
6. Require approval before rejecting a Wi-Fi connection.
7. Deny actions that are not defined in the allowed action list.
8. Record failed actions when approval is missing.

### Engineering reasoning

Containment can limit suspicious activity, but disruptive actions can affect legitimate users or systems. Evidence is therefore preserved first, and approval is checked before disruptive actions.

The current runner applies the action plan to the primary Stage 8 incident record. Stage 9 remains simulated and does not change a real firewall, device, account, session, process or Wi-Fi network.

### Problems and solutions

The existing ACL did not contain a separate `reject_wifi_connection` entry. Because Wi-Fi rejection can disrupt access, Stage 9 treated it as an approval-required action and recorded the action as failed when approval was not granted.

---

## Stage 10 — Eradication and recovery

Stage 10 moved the controlled incident process beyond containment.

### Eradication workflow

1. Read the Stage 9 containment report.
2. Preserve the pre-eradication evidence.
3. Record the simulated eradication actions.
4. Reset the simulated compromised credentials.
5. Remove simulated unauthorised privileges.
6. Register the reviewed unknown device.
7. Correct the simulated WPA3 and AES configuration.
8. Remove the simulated rogue access point.
9. Remove the suspicious simulated process.
10. Confirm the parameterised SQL query path.
11. Restore the simulated account and services.
12. Increase post-recovery monitoring.
13. Record each action in the audit trail.

### Recovery and retest workflow

1. Confirm that eradication actions completed.
2. Restore the simulated affected services and accounts.
3. Increase monitoring after recovery.
4. Retest the original SQL injection input.
5. Retest the contained source IP.
6. Retest the suspicious endpoint process.
7. Retest the rogue access-point condition.
8. Confirm that the original threats no longer succeed.
9. Record the lifecycle path through `Eradicated`, `Recovered` and `Closed`.
10. Record lessons learned.

### Engineering reasoning

Containment limits activity, but eradication removes or corrects the cause. Recovery is not complete until the original threat is tested again.

All Stage 10 actions are simulated. No real credentials, devices, wireless configuration, processes or services are changed.

---

## Stage 11 — Full project validation

Stage 11 validated the complete project after the implementation stages were finished.

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
11. Check audit-trail outputs.
12. Check documentation files against the project structure.
13. Record the final validation result.

### Problems and solutions

- The first Stage 11 validator displayed blank validator names because it used incorrect command indexes.
- The validator was corrected to print the actual validator name.
- The corrected Stage 11 validation run passed.

### Engineering reasoning

Earlier validators were retained because they make failures easier to locate. The combined regression checks integration that isolated tests may not show.

Runtime databases, logs, generated reports and cache files remain outside Git tracking. Final sign-off is based on repeatable evidence rather than one successful command.

The next improvement would be to replace selected simulated response actions with approved integrations in a later project phase, while keeping the same approval and evidence controls.

---

## Complete workflow

Each stage follows the same operational cycle:

1. Build a limited component.
2. Test the component in isolation.
3. Run it with the existing project.
4. Review the actual output and stored evidence.
5. Investigate genuine failures.
6. Correct the implementation.
7. Re-run the affected tests.
8. Run the complete regression set.
9. Review the documentation against the actual work.
10. Sign off only after the required validation passes.

The project continues to use controlled simulated data inside the Ubuntu VirtualBox environment. Real external targets, real accounts and real disruptive actions remain outside the project scope.

## Phase 3A V2 — Combined Stages 1 and 2

The enterprise upgrade reuses the original controlled foundation and event pipeline.

### Combined workflow

1. Verify the completed Phase 3 project.
2. Register simulated users, devices, applications and services.
3. Apply retention and sensitive-field protection settings.
4. Upgrade the existing database without removing stored data.
5. Generate controlled V2 JSONL events.
6. Validate schema versions, sources, data types and context.
7. Store valid events and quarantine malformed records.
8. Reject duplicates and record file-level failures.
9. Record ingestion totals and audit events.
10. Revalidate the original Phase 3 workflow.

Stage 1 controls the environment. Stage 2 controls how enterprise-style security data enters and is stored.
