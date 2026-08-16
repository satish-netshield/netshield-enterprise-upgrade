# Stage 1 Workflow

## Initialisation

1. Load the project settings.
2. Create the SQLite database from the tracked schema.
3. Save project metadata.
4. Assign the project-owner role.
5. Configure application and audit logs.
6. Record the initialisation event.

## Access decision

1. Identify the user role.
2. Look up the requested permission.
3. Allow only explicitly assigned permissions.
4. Deny unknown roles and permissions.

## Automation decision

1. Receive the proposed response action.
2. Check the automation ACL.
3. Run approved low-risk automatic actions.
4. Require approval for disruptive actions.
5. Keep infrastructure and physical actions manual.
6. Deny undefined actions.

## Device decision

1. Collect the device MAC address.
2. Compare it with the CYOD inventory.
3. Confirm that its status is approved.
4. Send unmatched devices for investigation.

## IP decision

1. Validate the IP address.
2. Check the blocklist first.
3. Check the allowlist second.
4. Classify remaining valid addresses as unknown.
5. Reject malformed addresses.

## Evidence workflow

1. Collect the evidence.
2. Calculate its SHA-256 hash.
3. Store the expected hash.
4. Change the preserved copy to read-only.
5. Recalculate the hash during validation.
6. Confirm that the evidence has not changed.
