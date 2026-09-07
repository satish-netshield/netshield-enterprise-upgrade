#  Notes from Testing

## Project baseline

- The completed Phase 3 Automation project passed 85 unit tests and all existing validators before the enterprise upgrade began.
- Phase 3A V2 continues from the existing Python, SQLite, logging, RBAC, evidence and response foundation.
- All testing remains inside the controlled Ubuntu VirtualBox environment.
- Microsoft security products remain design references only.

## Stage 1 — Enterprise foundation observations

- Simulated enterprise users were assigned to the existing Viewer, Analyst, Responder and Administrator roles.
- Repeated initialisation kept one role assignment for each simulated user.
- Sensitive-field masking protected configured nested values without changing safe fields.
- `CYOD-002` was marked as registered in enterprise context but was missing from the authoritative CYOD inventory.
- The inventory was corrected and a consistency test was added.
- Direct validator execution failed because the project package path was unavailable.
- Running validators as modules with `python -m` preserved the correct package path.
- SQL injection lab runtime files appeared as untracked because the original ignore rules covered only the main runtime directories.
- The nested lab runtime paths were added to `.gitignore`.
- During repository separation, restoring `settings.json` changed its local permission from `640` to `664`.
- Git does not preserve detailed non-executable permission modes, so `640` was reapplied and validated.
- V2 Stage 1 passed 12 out of 12 validation checks.
- The complete test suite contained 91 passing tests after the Stage 1 extension.

### Stage 1 lesson

Enterprise context must agree with the project’s existing authoritative inventories and access controls.

Local security permissions must also be checked after files are restored from Git.

## Stage 2 — Extended pipeline observations

- The existing pipeline already provided JSONL processing, validation, UTC conversion, rejected-event storage, raw-event preservation and duplicate protection.
- Compound sources such as `identity_risk` were initially shortened to the first filename word.
- Source identification was corrected to recognise the complete supported source name.
- Updating `schema.sql` alone did not upgrade the existing SQLite database.
- A repeatable migration was added to extend the working database without deleting Phase 3 data.
- Running the migration again added no duplicate columns.
- Six V2 source files produced 14 records.
- Twelve valid records were accepted and two malformed records were quarantined.
- Repeated imports accepted no duplicate events.
- Repeated imports created additional rejection rows for the same malformed inputs.
- The V2 validator was corrected to count distinct malformed evidence instead of cumulative rejection rows.
- The original Stage 2 validator required exactly five source types.
- It was corrected to require the original five sources while allowing approved V2 additions.
- A temporary unreadable file confirmed that file-level failures are recorded as failed ingestion batches.
- A source-only repository copy lacked ignored runtime evidence required by older tests.
- Sanitised Stage 7–9 fixtures were added so the unit tests could run without copied runtime outputs or machine-specific paths.
- V2 Stage 2 passed 13 out of 13 validation checks.
- The complete test suite contained 98 passing tests after the Stage 2 extension.

### Stage 2 lesson

A database upgrade must work with both a clean database and an existing database.

Validation must distinguish unique malformed evidence, duplicate events and file-level failures.

## Stage 3 — Device identity observations

- The CYOD inventory was extended with asset, ownership, operating-system, network, registration, compliance, risk, criticality and last-seen information.
- Removing the existing `approval_status` field broke a Phase 3 compatibility test.
- The field was restored so the upgrade extended the earlier control instead of replacing it.
- Device ID and asset ID became the main device references.
- MAC addresses remained supporting evidence because they can be changed or spoofed.
- The first detection run treated database and web asset IDs as device identities.
- The detector was corrected to evaluate events containing a device ID or an asset ID already known to the device inventory.
- `CYOD-003` was initially classified as Unknown Device.
- Enterprise context showed that it was known but unregistered, so it was correctly reclassified as Unregistered Device.
- `CYOD-002` initially produced an inventory mismatch because the event used `Auckland` while the inventory used `Auckland-NZ`.
- Compatible location values were normalised, removing the unnecessary alert.
- Three relevant V2 device events were evaluated after the corrections.
- One meaningful High-severity Unregistered Device alert remained for `CYOD-003`.
- Repeating the detector did not create another stored alert.
- Device removal preserved the inventory record and registration history instead of deleting them.
- False-positive review was tested in a temporary database so the real `CYOD-003` alert remained in `New` status.
- The first alert-review audit test expected an `audit_id` column that was not part of the established schema.
- The test was corrected to locate the audit event using its actor, action, target and result.
- Eighteen Stage 3 tests passed.
- Stage 3 validation passed 19 out of 19 checks.
- The complete project passed 116 unit tests after the Stage 3 work.

### Stage 3 lesson

Reliable device identity requires several pieces of inventory and event context.

Known unregistered devices must be separated from completely unknown devices, and a MAC address should never be treated as proof of identity by itself.

## Combined engineering decisions

- Existing Phase 3 controls are extended rather than redesigned.
- The tracked CYOD inventory remains the approved device source.
- SQLite provides operational storage for investigation and detection.
- Raw events and evidence remain unchanged.
- Sensitive-field masking applies only to suitable displayed output.
- Malformed events remain outside the accepted-event table.
- Duplicate events and alerts are retained as controlled rejections rather than accepted again.
- Test fixtures remain separate from generated runtime evidence.
- Real external targets, accounts and disruptive actions remain disabled.

## Current validation result

- V2 Stage 1 validation passed 12 out of 12 checks.
- V2 Stage 2 validation passed 13 out of 13 checks.
- V2 Stage 3 validation passed 19 out of 19 checks.
- The combined V2 Stage 1–3 test group passed 31 tests.
- The complete project passed 116 unit tests.
- The original Phase 3 full-project validation passed.
- `git diff --check` passed.

## Next improvement

The next project work can use identity, device, location, application and risk context when making local access decisions.

New controls should continue to preserve Phase 3 compatibility, use controlled test data and record genuine findings before documentation or stage sign-off.
