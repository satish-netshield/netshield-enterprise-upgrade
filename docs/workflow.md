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
5. Protect the evidence and verify its hash during validation.

## Stage 2 — Security data pipeline

Stage 2 prepared consistent events for later detection.

### Event workflow

1. Generate safe simulated authentication, network, Wi-Fi, endpoint and application events.
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

### Problems and lesson

Malformed data, invalid values and duplicate records were deliberately tested. JSONL allowed one bad record to be rejected without stopping the rest of the file.

## Stage 3 — Identity and authentication detection

Stage 3 used accepted authentication events to identify suspicious identity activity.

### Detection workflow

1. Load identity rules and user baselines.
2. Read accepted authentication events.
3. Group events by user, IP address and time.
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

- Wi-Fi records were initially placed in a network-named file and rejected. Separate source files were created.
- The detection runner supplied more source files than its SQL statement accepted. Dynamic placeholders were added.
- Stage 4 setup initially reset Stage 3 metadata. The initializer was corrected to preserve earlier status.
- Repeated activity initially produced separate alerts. MAC-based correlation grouped related activity while keeping different devices separate.

The main lesson was that source validation must happen before correlation.

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

- The first wired filename did not match its `network` source type. The generator was corrected.
- The endpoint-alert table was initially created only by the initializer. It was added to the tracked schema.
- A location change initially created a MAC-reuse alert. The rule was changed to require conflicting identity evidence with time overlap.
- The application role table contained only the project administrator. Simulated role mappings were added.
- Repeated wired observations were grouped by MAC, detection type, location and time window.

The main lesson was that CPU activity and MAC address require supporting context before they can be treated as suspicious.

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

- The first summary counted two vulnerable bypasses although four vulnerable requests authenticated. The summary was corrected to use the actual query result.
- One test did not genuinely verify the application log because the application used a fixed path. The application and test were corrected to accept an isolated log path.
- Earlier runs left 36 cumulative events in the log. The old log was archived before the clean run.
- The clean run produced seven requests and seven application events.

The main lesson was that secure query construction must be tested before and after remediation.

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

1. Assign points from the detection severity.
2. Add points for strong indicators.
3. Add points when several source types are involved.
4. Apply approved-device and known-VPN exceptions.
5. Reduce isolated low-value activity.
6. Map the final score to Low, Medium, High or Critical.
7. Preserve the reasons for the score.

### IoC and behaviour workflow

1. Extract observable values such as IP address, MAC address, hostname and process name.
2. Keep username as identity context.
3. Classify repeated failures and repeated connections as behaviours.
4. Keep IoCs separate from behaviours.
5. Preserve the source event ID for each extracted IoC.

### Problems and solutions

- The first engine treated username as an IoC. The extraction logic was corrected so username remained context.
- An isolated medium event was initially treated too strongly. Its risk was reduced to Low when no stronger related evidence existed.
- The corrected engine preserved the Critical multi-source incident while applying the approved-device and VPN exceptions.

The main lesson was that several related alerts can provide stronger context, but one isolated low-value event should not automatically become high risk.

## Complete validation principle

Each stage follows the same cycle:

1. Build a limited component.
2. Test the component in isolation.
3. Run it with the existing project.
4. Record genuine output.
5. Investigate failures.
6. Correct the implementation.
7. Re-run affected tests.
8. Run the complete regression set.
9. Review the documentation against the actual work.
10. Sign off only after clean validation passes.

For Stage 7, clean validation must also confirm:

- Related events are combined.
- Unrelated events remain separate.
- Risk increases when several indicators appear together.
- Approved-device and VPN exceptions are applied.
- Isolated low-value activity is reduced.
- IoCs are separated from behaviours.
- Automatic containment remains disabled.

The project remains inside the Ubuntu VirtualBox sandbox. Current detections use controlled simulated data, and disruptive or external actions remain outside scope.
