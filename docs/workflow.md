# NetShield Enterprise Upgrade Workflow

## Project boundary

Phase 3A V2 extends the completed NetShield Phase 3 Automation project.

The project remains inside the controlled Ubuntu VirtualBox sandbox and uses Python, SQLite and simulated enterprise security data.

Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are used only as design references. No Microsoft services, production accounts or real response actions are used.

---

## Combined Stages 1 and 2

Stages 1 and 2 were completed together because the enterprise foundation supports the extended security data pipeline.

### Workflow

1. Verify the completed Phase 3 project.
2. Reuse the existing configuration, RBAC, automation ACL, logging and SQLite database.
3. Add simulated enterprise users, devices, applications and services.
4. Confirm that registered devices agree with the authoritative CYOD inventory.
5. Configure retention periods and sensitive-field masking.
6. Upgrade the existing database through a repeatable migration.
7. Generate enterprise-style JSONL events.
8. Validate schemas, sources, required fields and data types.
9. Convert accepted timestamps to UTC.
10. Preserve raw events and store normalised events.
11. Quarantine malformed records and reject duplicates.
12. Record ingestion totals, failures and audit events.
13. Revalidate the original Phase 3 project.

### Engineering reasoning

The upgrade reuses the original controls instead of creating a separate security model.

A migration updates the existing database safely. Updating `schema.sql` alone would only prepare a new database.

### Problems and solutions

- `CYOD-002` was registered in the enterprise context but missing from the CYOD inventory. The inventory and consistency tests were corrected.
- Compound source names such as `identity_risk` were shortened incorrectly. Source identification was changed to recognise the complete source name.
- Existing validation expected exactly five source types. It was corrected to retain the original sources while allowing approved V2 additions.
- Repeated malformed inputs created additional quarantine rows. Validation was changed to count distinct malformed evidence.

### Testing and lesson

Stage 1 passed 12 out of 12 validation checks. Stage 2 passed 13 out of 13 checks.

Six Stage 2 source files contained 14 events. Twelve were accepted and two malformed events were quarantined.

The main lesson was that an upgrade must preserve the original controls while extending the data and database structure.

---

## Stage 3 — Enterprise asset and device identity

Stage 3 added a controlled device inventory, device identity checks and device-alert review.

### Workflow

1. Synchronise the approved CYOD inventory with SQLite.
2. Match events using device and asset identifiers.
3. Check registration, compliance, ownership and last-seen evidence.
4. Treat MAC addresses as supporting evidence only.
5. Separate unknown, unregistered, stale and mismatched devices.
6. Preserve registration and removal history.
7. Store duplicate-safe alerts and review actions.

### Engineering reasoning

A device ID and asset ID provide stronger evidence than a MAC address alone. Device removal changes its state instead of deleting its history.

### Problems and solutions

Database and web assets were initially treated as devices. Device evaluation was limited to events containing a device ID or an asset ID already known to the device inventory.

`CYOD-003` was also corrected from Unknown Device to Unregistered Device because it already existed in the enterprise context.

### Testing and lesson

Three relevant device events produced one High-severity Unregistered Device alert for `CYOD-003`. Approved `CYOD-002` activity produced no false alert.

Stage 3 passed 19 out of 19 validation checks, and the project reached 116 passing unit tests.

The main lesson was that reliable device identity requires several matching pieces of inventory and event evidence.

---

## Combined Stages 4 and 5

Stages 4 and 5 were built together because access decisions depend on identity, device and risk evidence.

They remain separate components with separate tests, validation results, observations and lessons.

- Stage 4 detects identity and authentication risks.
- Stage 5 evaluates access requests using the identity, device, role and risk context.

---

## Stage 4 — Identity monitoring and risk detection

Stage 4 extended the existing authentication logic with enterprise identity-risk monitoring.

### Workflow

1. Generate controlled authentication and identity-risk events.
2. Import the events through the existing V2 pipeline.
3. Load the accepted Stage 4 events from SQLite.
4. Group related failures by user, source address and time window.
5. Compare successful sign-ins with device and location baselines.
6. Evaluate access time, MFA activity, privilege changes and account type.
7. Apply known VPN and approved-testing exceptions.
8. Calculate severity, confidence and optional MITRE ATT&CK mappings.
9. Create deterministic alert keys from the detection and source events.
10. Store alerts with user, device, location, time, risk and evidence.
11. Review a controlled alert through the existing RBAC permissions.
12. Record the detection and review actions in the audit trail.

### Detection workflow

The Stage 4 rules cover:

- Repeated failed logins
- Possible brute-force activity
- Password spraying
- Successful login after repeated failures
- Impossible travel
- New-device sign-in
- Unusual location
- Abnormal access time
- MFA failure or fatigue
- Suspicious privilege changes
- Dormant-account activity
- Service-account interactive login
- Multiple accounts accessed from one source
- Risky sign-in and user-risk activity

Known VPN activity can suppress device, location and impossible-travel findings when the source address is approved. Approved test activity is excluded only when both the user and event are marked for controlled testing.

### Engineering reasoning

The existing Phase 3 identity detector was preserved. Stage 4 uses separate V2 alert storage because the original alert table does not contain confidence, device ID, reason-code or MITRE fields.

Deterministic alert keys prevent repeated detection runs from storing the same alert again.

### Problems and solutions

The first controlled dataset placed normal sign-ins shortly after midnight UTC while the configured normal period began at 06:00 UTC. This would have created several unintended abnormal-time alerts.

The event times were corrected before the detector was completed. Normal sign-ins now occur during the configured period, with one deliberate after-hours event at 23:00 UTC.

### Testing

Twenty-four Stage 4 events produced 16 alerts covering all configured detection types.

The results recorded two VPN exceptions and one approved-testing exception.

One Abnormal Access Time alert was investigated by `analyst01`, classified as a False Positive and closed with investigation notes. The review was written to the audit trail.

A repeated detector run created zero new alerts and identified all 16 as existing.

Nineteen Stage 4 tests passed. Stage 4 validation passed 12 out of 12 checks.

### What I learned

Time-based detection data must agree with the configured time window. Otherwise, valid activity can create false alerts before the detection logic is properly assessed.

I also learned that exceptions should be narrow and recorded. They should suppress only the expected condition rather than bypassing unrelated security checks.

---

## Stage 5 — Zero Trust and policy-based access decisions

Stage 5 added a local policy engine inspired by Zero Trust, RBAC and Conditional Access concepts.

It does not reproduce Microsoft Conditional Access.

### Workflow

1. Load accepted access requests from SQLite.
2. Verify that the identity is active and has an active role.
3. Check the required RBAC permission and minimum role.
4. Load device registration, compliance, risk and asset evidence.
5. Check application sensitivity and asset criticality.
6. evaluate restricted locations and networks.
7. evaluate sign-in risk, user risk and MFA evidence.
8. Check temporary access restrictions.
9. Apply an approved VPN exception where configured.
10. Collect every matching policy and reason code.
11. Select the winning policy by priority.
12. Use the more restrictive outcome when priorities are equal.
13. Validate any simulated response action against the automation ACL.
14. Store the complete decision and supporting evidence.
15. Record the evaluation in the audit trail.

### Decision workflow

The engine can return four outcomes:

- `allow` when all required evidence is satisfied
- `deny` when access is not permitted
- `challenge` when stronger verification or monitoring is required
- `restrict` when critical risk requires a controlled restriction

Every decision records the matching policies, winning policy, reason codes, identity evidence, device evidence, risk evidence and ACL result.

The default decision is `deny`.

### Policy priority

Policies use lower numbers for higher priority.

A temporary restriction has higher priority than risk, device or MFA conditions. When policies have the same priority, the engine selects the more restrictive decision in this order:

1. `deny`
2. `restrict`
3. `challenge`
4. `allow`

### Engineering reasoning

Stage 5 reuses the existing RBAC roles and automation ACL rather than defining another permission system.

The policy decision and response action remain separate. A `restrict` decision can be produced immediately, but `restrict_account` remains approval-required and is not automatically executed.

### Testing

Nine controlled access requests produced:

- 2 allow decisions
- 4 deny decisions
- 2 challenge decisions
- 1 restrict decision

The tests covered role permissions, application requirements, registered and compliant devices, restricted networks, restricted locations, MFA, critical risk, VPN exceptions, temporary restrictions, default deny and policy conflicts.

Automatic monitoring remained simulated. Account restriction stopped at `approval_required`.

A repeated policy run created zero new decisions and identified all nine as existing.

Thirteen Stage 5 tests passed. Stage 5 validation passed 14 out of 14 checks.

### What I learned

An access decision should explain why access was allowed or blocked. The final outcome is easier to investigate when the winning policy, all matching reasons and the supporting evidence are stored together.

I also learned that access decisions should not bypass the response ACL. A high-risk result can request a restriction, but approval must still be enforced.

---

## Project-wide SQLite connection correction

The combined regression exposed repeated Python 3.14 `ResourceWarning` messages.

### Problem and solution

The project used `with sqlite3.connect(...)` for transaction handling. This commits or rolls back the transaction, but it does not explicitly close the connection.

A diagnostic scan found 89 connection calls across 38 files. The full test suite produced 101 unclosed-database warnings.

A shared connection manager was added to preserve commit and rollback behaviour while always closing the connection. All 89 call sites were updated.

The larger Stage 4–5 dataset also caused the Stage 3 validator to count 36 device-related V2 events instead of its original three. The Stage 3 query was restricted to its Stage 2 source filenames.

### Testing and lesson

After the correction:

- All 151 unit tests passed.
- SQLite resource warnings reduced from 101 to zero.
- V2 Stages 1–5 passed.
- The original Stage 11 validation passed.
- SQLite integrity returned `ok`.
- No database process remained open after testing.

The main lesson was that a passing transaction does not prove that its connection was closed. Resource handling must be tested separately, especially when the Python version reports stricter warnings.

---

## Next improvement

Future identity monitoring can use longer activity baselines, user-specific working hours and more detailed location history.

The policy engine can later support controlled policy administration and more application or asset scenarios while keeping default deny, reason codes, approval controls and complete audit evidence.

The same engineering process will continue:

1. Build a limited component.
2. Test it independently.
3. Run it with the existing project.
4. Review the actual output.
5. Record meaningful failures and decisions.
6. Correct genuine problems.
7. Run the affected tests and complete regression.
8. Update only the relevant documentation.
9. Sign off after final validation.
