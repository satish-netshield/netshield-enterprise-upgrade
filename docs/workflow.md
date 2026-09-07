# NetShield Enterprise Upgrade Workflow

## Project boundary

Phase 3A V2 extends the completed NetShield Phase 3 Automation project.

The upgrade remains a Python and SQLite security-automation project inside the controlled Ubuntu VirtualBox sandbox. It uses simulated enterprise users, devices, applications, services and security events.

Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design concepts only. No Microsoft services or real enterprise actions are used.

---

## Combined Stages 1 and 2

Stages 1 and 2 were completed and documented together because the enterprise foundation supports the extended data pipeline.

They remain separate stages with their own purpose, implementation and validation result.

- Stage 1 controls the project foundation.
- Stage 2 controls how enterprise-style security data enters the project.

---

## Stage 1 — Enterprise project foundation

Stage 1 extended the existing Phase 3 foundation without replacing its controls.

### Workflow

1. Verify the completed Phase 3 project.
2. Load the existing project settings.
3. Reuse the SQLite database, logging, RBAC and automation ACL.
4. Register simulated enterprise users with the existing roles.
5. Define simulated devices, applications and services.
6. Confirm that registered devices exist in the CYOD inventory.
7. Configure retention periods and sensitive-field masking.
8. Preserve the existing sandbox boundaries.
9. Record V2 metadata and audit events.
10. Revalidate the original Phase 3 components.

### Engineering reasoning

Reusing the existing foundation keeps Phase 3A V2 connected to NetShield and avoids creating a second security model.

Retention settings define how long records should be kept, but automatic deletion is not implemented yet.

Sensitive-field masking protects suitable displayed output. Original evidence remains unchanged so its integrity can still be checked.

### Problems and solutions

- Nested SQL injection lab runtime files appeared as untracked files. The relevant paths were added to `.gitignore`.
- `CYOD-002` appeared as registered in enterprise context but was missing from the authoritative inventory. The inventory was corrected and a consistency test was added.
- Restoring `settings.json` from Git changed its local permission. The required `640` permission was reapplied and validated.

### Testing and lesson

V2 Stage 1 passed 12 out of 12 validation checks.

The main lesson was that new enterprise context must agree with the project’s existing authoritative records.

---

## Stage 2 — Extended security data pipeline

Stage 2 extended the existing pipeline to process additional enterprise-style events.

### Workflow

1. Inspect the existing SQLite database.
2. Add missing V2 columns and investigation indexes through a repeatable migration.
3. Preserve the existing Phase 3 records.
4. Generate separate JSONL files for each V2 source.
5. Identify the complete event-source name.
6. Validate schema versions, required fields and data types.
7. Convert accepted timestamps to UTC.
8. Store normalised events in SQLite.
9. Preserve the original event data.
10. Quarantine malformed records.
11. Reject duplicate events.
12. Record ingestion totals, file failures and audit events.

The additional sources cover identity risk, access decisions, database activity, vulnerabilities, incidents and response actions.

The original authentication, network, Wi-Fi, endpoint and application sources remain supported.

### Engineering reasoning

Updating `schema.sql` prepares a new database but does not modify an existing database. A repeatable migration was needed to upgrade the working database without deleting earlier data.

Malformed records remain outside the accepted-event table so invalid data cannot affect later detection and correlation.

### Problems and solutions

- Compound source names such as `identity_risk` were shortened incorrectly. Source identification was corrected to recognise the complete supported name.
- The original validator expected exactly five source types. It was corrected to require the original sources while allowing approved V2 additions.
- Repeated imports created more rejection rows for the same malformed input. Validation was corrected to count distinct malformed evidence.
- Older tests depended on ignored runtime outputs. Sanitised fixtures were added so tests could run without copied runtime files or machine-specific paths.
- An unreadable test file confirmed that file-level failures are recorded as failed ingestion batches.

### Testing and lesson

Six V2 files contained 14 events. Twelve valid events were accepted and two malformed events were quarantined.

A repeated import accepted no duplicate events.

V2 Stage 2 passed 13 out of 13 validation checks.

The main lesson was that database and validation changes must work with both new and existing project data.

---

## Stage 3 — Enterprise asset and device identity

Stage 3 added stronger device inventory and identity checks.

### Workflow

1. Extend the CYOD inventory with device and asset context.
2. Validate unique device IDs and asset IDs.
3. Synchronise the tracked inventory with SQLite.
4. Read relevant V2 device events.
5. Match events using device ID or approved asset ID.
6. Check registration state and last-seen time.
7. Compare hostname, user, IP address and location.
8. Use the MAC address as supporting evidence only.
9. Create duplicate-safe device alerts.
10. Preserve device registration and removal history.
11. Record alert reviews and audit events.

The detector separates Unknown Device, Unregistered Device, Stale Device and Inventory Mismatch findings.

### Engineering reasoning

Device ID and asset ID provide stronger identity references than a MAC address alone.

A known but unregistered device is different from a completely unknown device. Keeping these results separate makes the alert easier to investigate.

Removal changes the device’s registration state instead of deleting its inventory and history.

### Problems and solutions

- Removing the existing `approval_status` field broke Phase 3 compatibility. The field was restored.
- Database and web assets were initially treated as devices. The detector was limited to events containing a device ID or an asset ID known to the device inventory.
- `CYOD-003` was initially classified as unknown. Enterprise context showed that it was known but unregistered, so the classification was corrected.
- Different labels for the same Auckland location created an unnecessary mismatch. Compatible location values were normalised.
- An alert-review test expected a database column that did not exist. The test was corrected to use the established audit fields instead of changing the schema for the test.

### Testing and lesson

Three relevant V2 device events were evaluated.

One meaningful High-severity Unregistered Device alert remained for `CYOD-003`. Approved `CYOD-002` activity created no false alert.

Repeating the detector did not create another stored alert.

Eighteen Stage 3 tests passed, and Stage 3 validation passed 19 out of 19 checks.

The complete project passed 116 unit tests after the Stage 3 work.

The main lesson was that device identity requires several pieces of inventory and event context. A MAC address can support the decision, but it should not be trusted as proof by itself.

---

## Next improvement

The next stage can use the existing identity, device, location, application and risk context when making local access decisions.

The same engineering workflow will continue:

1. Build a limited component.
2. Test it independently.
3. Run it with the existing project.
4. Review the actual output and evidence.
5. Record genuine problems and decisions.
6. Correct the implementation.
7. Re-run affected tests and the complete regression.
8. Update only the relevant documentation.
9. Sign off after validation is complete.
