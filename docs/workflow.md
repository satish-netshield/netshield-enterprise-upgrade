# Project Workflow

## Stage 1 — Environment and access control

Stage 1 created the safe foundation before detection work began.

### Foundation

1. Load the project settings.
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

### Device and IP decisions

1. Compare observed devices with the CYOD inventory.
2. Check whether the device is approved.
3. Validate the IP address.
4. Check the blocklist before the allowlist.
5. Send unknown devices and IP addresses for investigation.

### Evidence

1. Preserve the evidence.
2. Calculate its SHA-256 hash.
3. Store the expected hash.
4. Protect the preserved file from casual modification.
5. Recalculate the hash during validation.

Result: a controlled sandbox with default-deny access and protected evidence.

## Stage 2 — Security data pipeline

Stage 2 prepared consistent events for later detection.

### Event generation

1. Generate safe simulated authentication, network, Wi-Fi, endpoint and application events.
2. Add deliberate malformed records for testing.
3. Write each source to a separate JSONL file.

### Import and normalisation

1. Create an import batch for each source file.
2. Read one JSONL record at a time.
3. Parse and validate the JSON object.
4. Confirm required fields and the approved source type.
5. Convert timestamps to UTC.
6. Validate IP addresses, MAC addresses and CPU values.
7. Store accepted events in SQLite.

### Rejected data

1. Keep malformed data out of the accepted-event table.
2. Preserve the original input, filename and line number.
3. Record the exact rejection reason.
4. Include rejected records in the batch totals.

### Duplicate events

1. Compare the source filename and source event ID.
2. Accept the first valid occurrence.
3. Reject later duplicates.
4. Preserve the duplicate and its rejection reason.

### Stage 2 validation

1. Compile the project files.
2. Run the Stage 1 and Stage 2 tests.
3. Confirm the five source files and 19 simulated records.
4. Reconcile accepted and rejected totals.
5. Confirm normalisation, raw-event preservation and audit logging.

Result: 15 accepted events and 4 rejected records were stored with their reasons.

## Stage 3 — Identity and authentication detection

Stage 3 used accepted authentication events to identify suspicious identity activity.

### Detection

1. Load the identity rules and user baselines.
2. Read accepted authentication events from SQLite.
3. Group related events by user, IP address and time.
4. Detect repeated failures and possible brute force.
5. Detect successful login after repeated failures.
6. Detect MFA anomalies.
7. Detect new devices and unusual locations.
8. Detect impossible travel.
9. Detect suspicious role changes.
10. Apply known VPN exceptions.

### Alert handling

1. Create a deterministic alert key.
2. Store the detection type, severity, events and evidence.
3. Ignore duplicate copies of the same alert.
4. Record detection activity in the audit trail.
5. Keep alerts available for investigation and later correlation.

### False-positive investigation

1. Review the alert and supporting event evidence.
2. Confirm whether the device or activity is authorised.
3. Classify legitimate activity as a false positive.
4. Preserve the investigation note.
5. Record the decision in the audit trail.

The replacement laptop was authorised but missing from the CYOD inventory, so its new-device alert was classified as a false positive.

### Engineering observations

- A five-minute failure window may be too broad and should be reviewed during later tuning.
- Severity should increase when strong detections occur together.
- An approved device can still create a valid new-device alert when inventory registration is incomplete.
- Duplicate protection prevents alert flooding but does not track unresolved conditions over time.
- Later stages should correlate identity alerts with CYOD, Wi-Fi, network and endpoint evidence.

### Stage 3 validation

1. Compile all project files.
2. Run the Stage 1–3 unit tests.
3. Re-run the Stage 1 and Stage 2 validators.
4. Confirm 16 Stage 3 events were imported.
5. Confirm 11 identity alerts were created.
6. Run the detector again to confirm duplicate protection.
7. Confirm VPN exceptions were recorded.
8. Confirm the false-positive investigation and audit record.
9. Run the Stage 3 validator.

Result: 39 unit tests passed, Stage 1 passed 12/12, Stage 2 passed 14/14 and Stage 3 passed 12/12.

## Stage 4 — Network, CYOD and Wi-Fi detection

Stage 4 used accepted network and Wi-Fi events to detect suspicious device and wireless activity.

### Event preparation

1. Generate controlled network and Wi-Fi events.
2. Keep network and Wi-Fi records in separate source files.
3. Import both sources into the shared `security_events` table.
4. Generate additional events for repeated connections and MAC reuse.
5. Import the correlation events without changing the earlier pipeline rules.

The files remained separate because the existing collector requires the event source type to match the source filename. Correlation takes place after both sources have been validated and stored.

### Network and device detection

1. Load accepted Stage 4 events from SQLite.
2. Compare MAC addresses with the CYOD inventory.
3. Check suspicious IP addresses.
4. Detect repeated connection attempts.
5. Detect port-scanning behaviour.
6. Detect unknown or unregistered devices.
7. Preserve the related source-event evidence.

### Wi-Fi detection

1. Check whether the MAC address is registered.
2. Check the observed Wi-Fi zone.
3. Check WPA3 and AES compliance.
4. Detect WPA3 policy violations.
5. Detect WPA2 downgrade attempts.
6. Detect unauthorised or open access points.
7. Detect rogue access points.
8. Preserve the original event evidence.

### Alert correlation

1. Group related alerts by MAC address.
2. Compare IP address, hostname, username, location and event time.
3. Preserve high-impact detections such as port scanning, WPA3 violations, WPA2 downgrade attempts and rogue access points.
4. Detect conflicting use of the same MAC address.
5. Create a MAC-reuse or possible-spoofing alert when the evidence supports it.
6. Save one correlated alert for each unique alert key.
7. Record the detection run in the audit trail.

### Problems found and solved

- Wi-Fi records were initially placed in a network-named file and were rejected by source verification.
- The event generator was changed to create separate network and Wi-Fi files.
- The detection runner initially supplied four source files to a query with only two placeholders.
- The runner was changed to create the correct number of placeholders dynamically.
- The Stage 3 initializer reset completed metadata while creating the Stage 4 table.
- The initializer was changed to preserve the completed Stage 3 status.

### Stage 4 validation

1. Compile all project files.
2. Run the Stage 1–4 unit tests.
3. Run the Stage 1, Stage 2, Stage 3 and Stage 4 validators.
4. Confirm 23 accepted Stage 4 events.
5. Confirm the expected network and Wi-Fi source totals.
6. Confirm 12 correlated network alerts.
7. Confirm MAC reuse detection.
8. Confirm repeated connections were grouped.
9. Confirm the rogue access point was classified as Critical.
10. Run the detector again to confirm duplicate protection.
11. Confirm Stage 4 audit records and metadata.

Result: 44 unit tests passed. Stage 1 passed 12/12, Stage 2 passed 14/14, Stage 3 passed 12/12 and Stage 4 passed 12/12.

### What was learned

- Network and Wi-Fi sources can be correlated without placing them in the same input file.
- Source validation should be completed before cross-source correlation.
- MAC address is useful as the primary CYOD identity, but supporting evidence is still required.
- A restricted location is evidence for investigation, not automatic proof of compromise.
- Duplicate protection reduces alert noise but does not replace continuous monitoring.
- Wired LAN checks, restricted server-room privileges and endpoint CPU correlation should be added in the next stage.

## Stage 5 — Endpoint and wired-LAN detection

Stage 5 used endpoint and wired network events to detect unusual CPU activity, unknown processes and restricted wired access.

### Event preparation

1. Generate controlled endpoint and wired-LAN events.
2. Write endpoint events to `endpoint_stage5_events.jsonl`.
3. Write wired events to `network_stage5_events.jsonl` so the source type matches the existing collector rules.
4. Import both files into the shared `security_events` table.
5. Preserve duplicate records and their rejection reasons when the same events are imported again.

### Endpoint detection

1. Load accepted endpoint and network events from SQLite.
2. Compare CPU usage with the configured warning and critical thresholds.
3. Ignore the approved CPU stress-test record.
4. Detect unapproved CPU stress tests.
5. Detect critical CPU activity.
6. Group repeated high-CPU activity for the same MAC within the configured time window.
7. Detect unknown endpoint processes.
8. Preserve the related event evidence.

### Wired access detection

1. Check the wired connection location.
2. Compare the observed user role with the approved role for that zone.
3. Detect analyst access to the restricted Server Room.
4. Allow approved responder access to the Server Room.
5. Group repeated restricted wired observations only when the MAC address, detection type, location and time window match.
6. Keep different MAC addresses as separate device investigations.

### MAC correlation

1. Use the MAC address as the primary device identity.
2. Use hostname and username as conflicting identity evidence.
3. Compare event times to confirm overlap.
4. Do not create MAC-reuse alerts from a location change alone.
5. Save one alert for each unique detection key.
6. Record the detection run in the audit trail.

### Problems found and solved

- The initial wired filename did not match the `network` source type, so the generator was corrected to create `network_stage5_events.jsonl` directly.
- The endpoint-alert table was initially created only by the Stage 5 initializer. It was added to the tracked database schema so clean setup creates the table as well.
- Simulated endpoint roles were added because the application role table contains only the project administrator.
- A location change alone initially risked creating a MAC-reuse alert. The rule was corrected to require conflicting hostname or username evidence with time overlap.
- Repeated restricted wired events were initially separate alerts. They were grouped by MAC, detection type, location and time window.
- Approved responder access was initially treated as unauthorised until the simulated role mapping was applied.
- Re-imported Stage 5 events were rejected as duplicates, confirming source-file and event-ID protection.

### Stage 5 validation

1. Compile all project files.
2. Run the Stage 1–5 unit tests.
3. Run the Stage 1–5 validators.
4. Confirm 14 accepted Stage 5 events.
5. Confirm 10 endpoint alerts.
6. Confirm repeated high-CPU activity was grouped.
7. Confirm repeated restricted wired access was grouped.
8. Confirm the approved CPU stress test created no alert.
9. Confirm location change alone did not create MAC reuse.
10. Run the detector again to confirm duplicate protection.
11. Confirm Stage 5 audit records and metadata.

Observed result: 52 unit tests passed. Stage 1 passed 12/12, Stage 2 passed 14/14, Stage 3 passed 12/12, Stage 4 passed 12/12 and Stage 5 passed 12/12.

### What was learned

- Endpoint activity adds useful context to network and identity alerts.
- High CPU usage is not automatically malicious because approved stress testing must be recognised.
- A restricted wired connection is evidence for investigation and requires user, role, zone and device context.
- MAC address remains a useful baseline, but hostname, username and time are needed to assess possible spoofing.
- Grouping repeated observations reduces alert noise without combining different devices.
- A clean tracked schema is important because runtime initialization alone can hide setup problems.
- The next stage should improve unresolved-condition tracking, inventory verification and controlled response.
