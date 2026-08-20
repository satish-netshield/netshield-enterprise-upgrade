# Project Workflow

## Stage 1 — Environment and access control

### Initialisation

1. Load the project settings.
2. Create the SQLite database from the tracked schema.
3. Save project metadata.
4. Assign the project-owner role.
5. Configure application and audit logs.
6. Record the initialisation event.

### Access decision

1. Identify the user role.
2. Look up the requested permission.
3. Allow only explicitly assigned permissions.
4. Deny unknown roles and permissions.

### Automation decision

1. Receive the proposed response action.
2. Check the automation ACL.
3. Run approved low-risk automatic actions.
4. Require approval for disruptive actions.
5. Keep infrastructure and physical actions manual.
6. Deny undefined actions.

### Device decision

1. Collect the device MAC address.
2. Compare it with the CYOD inventory.
3. Confirm that its status is approved.
4. Send unmatched devices for investigation.

### IP decision

1. Validate the IP address.
2. Check the blocklist first.
3. Check the allowlist second.
4. Classify remaining valid addresses as unknown.
5. Reject malformed addresses.

### Evidence workflow

1. Collect the evidence.
2. Calculate its SHA-256 hash.
3. Store the expected hash.
4. Change the preserved copy to read-only.
5. Recalculate the hash during validation.
6. Confirm that the evidence has not changed.

## Stage 2 — Security data pipeline

### Pipeline initialisation

1. Load the existing project settings.
2. Apply the updated SQLite schema.
3. Create the import-batch table.
4. Create the accepted security-event table.
5. Create the rejected-event table.
6. Create indexes for common event searches.
7. Update the project version to `0.2.0`.
8. Record the Stage 2 initialisation event.

### Simulated event generation

1. Create authentication events.
2. Create network events.
3. Create Wi-Fi and CYOD events.
4. Create endpoint and CPU events.
5. Create local application events.
6. Add deliberate malformed records for testing.
7. Write each source to a separate JSONL file.

### File import

1. Find the JSONL files in `data/raw`.
2. Create an import batch for each source file.
3. Read each file one line at a time.
4. Count every input record.
5. Reject empty lines.
6. Parse each remaining line as JSON.
7. Send valid JSON objects to the normaliser.
8. Store accepted events in SQLite.
9. Preserve rejected records and their reasons.
10. Complete the batch with its processing totals.
11. Record the completed import in the audit trail.

### Event normalisation

1. Confirm that the event is a JSON object.
2. Require an event ID.
3. Require a timezone-aware event timestamp.
4. Require a source type and event type.
5. Accept only approved source types.
6. Confirm that the source type matches the filename.
7. Convert the timestamp to UTC.
8. Validate and normalise the IP address.
9. Validate and normalise the MAC address.
10. Validate CPU usage between 0 and 100 percent.
11. Clean the optional text fields.
12. Return one consistent event structure.

### Rejected-event handling

1. Do not place malformed data in the accepted-event table.
2. Record the source filename.
3. Record the line number.
4. Record the exact failure reason.
5. Preserve the original input.
6. Count the record as rejected in its import batch.

### Duplicate-event handling

1. Compare the source filename and source event ID.
2. Accept the first valid occurrence.
3. Reject later occurrences of the same event.
4. Preserve the duplicate input and rejection reason.
5. Keep only one accepted database record.

### Stage 2 validation

1. Compile the Python files.
2. Run the Stage 1 and Stage 2 unit tests.
3. Re-run the Stage 1 validator.
4. Confirm the Stage 2 settings and source files.
5. Confirm the SQLite tables and indexes.
6. Reconcile the import-batch totals.
7. Confirm all five source types were imported.
8. Confirm malformed records were preserved.
9. Confirm UTC timestamp normalisation.
10. Confirm IP, MAC and CPU field handling.
11. Confirm raw-event preservation.
12. Confirm duplicate-event protection.
13. Confirm project metadata.
14. Confirm the import audit record.
