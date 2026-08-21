# Project Workflow

## Stage 1 — Environment and access control

Stage 1 created the safe foundation before security detection work began.

### Foundation

1. Load the project settings.
2. Create the SQLite database from the tracked schema.
3. Save project metadata and assign the project-owner role.
4. Configure application and audit logging.
5. Apply protected file and directory permissions.

### Access decisions

1. Identify the user role.
2. Allow only explicitly assigned permissions.
3. Check the automation ACL before every response action.
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
4. Confirm required fields and approved source type.
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
5. Keep alerts available for later investigation and correlation.

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
- An approved device can still be a valid new-device alert if inventory registration is incomplete.
- Duplicate protection prevents alert flooding but does not yet track unresolved conditions over time.
- Stage 4 should correlate identity alerts with CYOD, Wi-Fi, WPA3, IP and device-consistency evidence.

### Stage 3 validation

1. Compile all project files.
2. Run all Stage 1–3 unit tests.
3. Re-run the Stage 1 and Stage 2 validators.
4. Confirm 16 Stage 3 events were imported.
5. Confirm 11 identity alerts were created.
6. Run the detector again to confirm duplicate protection.
7. Confirm VPN exceptions were recorded.
8. Confirm the false-positive investigation and audit record.
9. Run the Stage 3 validator.

Result: 39 unit tests passed, Stage 1 passed 12/12, Stage 2 passed 14/14 and Stage 3 passed 12/12.
