# NetShield Enterprise Upgrade Notes

## Project scope

Phase 3A V2 extends the completed NetShield Phase 3 Automation project.

These notes record only meaningful test observations, failures, fixes, decisions and lessons from the enterprise upgrade.

The project remains inside the Ubuntu VirtualBox sandbox and uses simulated enterprise data. No real Microsoft services, external accounts or production security actions are used.

---

## Stage 1 — Enterprise project foundation

### Observations and decisions

- The V2 project reused the existing SQLite database, RBAC roles, automation ACL, logging, evidence controls and sandbox boundaries.
- Reusing the existing controls kept the upgrade connected to NetShield instead of creating a separate security model.
- Retention periods were configured, but automatic deletion was not added because it requires its own controlled workflow.
- Sensitive values are masked in suitable output while original evidence remains unchanged.

### Problems and fixes

- Nested SQL injection lab data, logs and outputs appeared as untracked runtime files. Their paths were added to `.gitignore`.
- `CYOD-002` was registered in the enterprise context but missing from the authoritative CYOD inventory. The inventory was corrected and a consistency check was added.
- Repository separation restored `config/settings.json` with permission `664`. Git does not preserve detailed non-executable modes such as `640`, so the required permission was reapplied.
- Repeated V2 initialisation was checked to confirm that it did not create duplicate role assignments.

### Testing observation

V2 Stage 1 passed 12 out of 12 validation checks.

### Lesson

New enterprise context must agree with the project’s existing authoritative records. Configuration, inventory and database state cannot be treated as separate sources of truth.

---

## Stage 2 — Extended security data pipeline

### Observations and decisions

- Six V2 JSONL files contained 14 records.
- Twelve valid records were accepted.
- Two malformed records were quarantined.
- Accepted timestamps were stored in UTC.
- Original events were preserved with the normalised records.
- Repeated imports did not duplicate accepted events.

### Problems and fixes

- Updating `database/schema.sql` did not upgrade the existing SQLite database. A repeatable migration was added so new columns and indexes could be applied without deleting earlier data.
- The original filename logic read only the first word of a source name. This would have changed `identity_risk` into `identity`. Source detection was corrected to recognise the complete supported source name.
- The V2 validator originally counted rejection rows. Repeated imports could therefore make two malformed inputs appear to be several different malformed events. Validation was changed to check distinct malformed evidence.
- The original Stage 2 validator expected the supported-source list to equal the original five sources exactly. It was corrected to require those five while allowing approved V2 additions.
- Some older tests depended on ignored runtime output files. Sanitised fixtures were added so tests did not depend on machine-specific or untracked data.
- An unreadable source file was tested to confirm that a file-level failure creates a failed import batch instead of being silently ignored.

### Testing observation

V2 Stage 2 passed 13 out of 13 validation checks.

### Lesson

Pipeline validation must distinguish between source evidence and database row counts. It must also remain compatible when new approved sources are added.

---

## Stage 3 — Enterprise asset and device identity

### Observations and decisions

- Device ID and asset ID were kept as the main identity references.
- MAC addresses were treated as supporting evidence only.
- Known but unregistered devices were kept separate from completely unknown devices.
- Device removal preserved the inventory record and registration history.

### Problems and fixes

- Removing the existing `approval_status` field broke Phase 3 compatibility. The field was restored.
- Database and application assets were initially treated as devices. Device evaluation was limited to events containing a device ID or an asset ID known to the device inventory.
- `CYOD-003` was initially classified as unknown. Enterprise context confirmed that it was known but unregistered, so the finding was corrected.
- Different labels for the same Auckland location created an unnecessary mismatch. Compatible location values were normalised.

### Testing observation

Three relevant V2 device events were evaluated.

One meaningful High-severity Unregistered Device alert remained for `CYOD-003`. Approved `CYOD-002` activity produced no false alert.

Repeated detection did not create another stored alert.

V2 Stage 3 passed 19 out of 19 validation checks.

### Lesson

A device decision needs several pieces of evidence. A MAC address can support a result, but it should not be treated as proof of device identity.

---

## Stage 4 — Identity monitoring and risk detection

### Observations and decisions

- Stage 4 used 21 authentication events and three identity-risk events.
- The controlled run evaluated 24 relevant events and produced 16 identity alerts.
- Severity and confidence were stored separately.
- Each alert included traceable source events and a reason code.
- Known VPN and approved-testing exceptions were counted rather than silently ignored.
- The run recorded two VPN exceptions and one approved-testing exception.
- V2 alerts were stored separately from the original Phase 3 identity-alert table.

### Detection results

The controlled evidence produced:

- One Repeated Failed Logins alert
- One Possible Brute Force alert
- One Successful Login After Failures alert
- One Password Spraying Pattern alert
- One Multiple Accounts From One Source alert
- One Impossible Travel alert
- Two Unusual Sign-In Location alerts
- One New-Device Sign-In alert
- One MFA Failure or Fatigue Pattern alert
- One Suspicious Privilege Change alert
- One Dormant-Account Activity alert
- One Service-Account Interactive Login alert
- Two Risky Sign-In Behaviour alerts
- One Abnormal Access Time alert

### Problem found

The first controlled authentication dataset began at `00:00` UTC.

Normal access hours started later, so ordinary test activity would have been incorrectly treated as abnormal access. This was a test-data problem rather than a detector failure.

### Fix

Normal authentication events were moved inside the configured access period.

One deliberate event remained at `23:00` UTC so the abnormal-time rule still had controlled evidence.

The earlier Stage 4–5 source records and import batches were removed before the corrected files were regenerated and imported.

### Duplicate testing

The first identity-monitoring run stored 16 new alerts.

The repeated run reported:

- 16 detections
- 0 new alerts
- 16 existing alerts
- 16 stored alert keys
- 16 unique alert keys

No accepted identity alerts were duplicated.

### False-positive investigation

The Abnormal Access Time alert for `viewer01` was reviewed by `analyst01`.

It was classified as a False Positive and closed with the note that the event was controlled after-hours testing and no unauthorised access occurred.

The review was recorded in the audit trail.

### Testing result

The Stage 4 identity-monitoring tests passed 12 tests.

The alert-review tests passed seven tests.

V2 Stage 4 passed 12 out of 12 validation checks.

### Lesson

Controlled security data must match its configured baseline. A correct detector can produce misleading results when normal test activity is created outside the normal period.

Exceptions and false-positive review are also part of detection quality. They should be recorded without deleting the original alert.

---

## Stage 5 — Zero Trust and policy-based access decisions

### Observations and decisions

- Stage 5 evaluated nine controlled access requests.
- Existing RBAC and automation ACL controls were reused.
- Every decision stored its winning policy, reason codes and evaluated evidence.
- The engine supported Allow, Deny, Challenge and Restrict.
- Unknown or unverifiable access followed default deny.
- Policy priority and same-priority conflict handling were explicit.
- Proposed responses were checked against the automation ACL after the access decision was made.

### Decision results

The controlled run produced:

- 2 Allow decisions
- 4 Deny decisions
- 2 Challenge decisions
- 1 Restrict decision

The decisions covered:

- Verified access
- Missing role permission
- Unregistered and non-compliant device evidence
- Critical identity risk
- Restricted network
- Missing MFA
- Restricted location
- Approved VPN evidence
- Temporary access restriction

### Policy-priority observation

An active temporary restriction had the strongest priority.

When policies had the same priority, the more restrictive result won in this order:

1. Deny
2. Restrict
3. Challenge
4. Allow

This prevented a general Allow condition from overriding a stronger security rule.

### ACL observation

The Challenge decisions proposed `increase_monitoring`.

This action was allowed as an automatic simulated response.

The Restrict decision proposed `restrict_account`.

That action required approval and was not executed.

This confirmed that a policy decision does not bypass the automation ACL.

### Duplicate testing

The repeated policy run evaluated the same nine requests and reported:

- 9 decisions
- 0 new decisions
- 9 existing decisions
- 9 stored decision keys
- 9 unique decision keys

No policy decisions were duplicated.

### Testing result

The Stage 5 access-policy tests passed 13 tests.

V2 Stage 5 passed 14 out of 14 validation checks.

### Lesson

An access result must be explainable. The decision, winning policy, reason codes, evidence and response permission need to remain visible as separate parts of the result.

---

## Cross-stage validator finding

### Problem found

After Stage 4–5 events were imported, the Stage 3 validator counted later device-related events because its query used a broad V2 event boundary.

The validator expected three Stage 3 events but could see later-stage records as the project grew.

### Fix

The Stage 3 query was limited to the intended Stage 3 V2 source files.

The pipeline data was not removed because the later events were valid. Only the validator boundary was corrected.

### Lesson

A stage validator should identify its own evidence directly. It should not assume that later stages will never add records to the same database.

---

## SQLite connection finding

### Problem found

The complete test suite passed, but Python 3.14 reported many unclosed-database `ResourceWarning` messages.

A detailed diagnostic found:

- 100 Python files inspected
- 89 SQLite connection calls
- 38 affected files
- 101 unclosed-database warnings during the complete test suite
- No database integrity failure
- No remaining database handles after the Python process ended

The existing `with sqlite3.connect(...)` pattern handled commit and rollback but did not explicitly close the connection object.

### Decision

The connection lifecycle was corrected immediately instead of allowing the warning pattern to continue into later stages.

A shared managed connection helper was added and the affected call sites were updated.

The helper now:

1. Opens the connection.
2. Commits successful work.
3. Rolls back failed work.
4. Closes the connection in every case.

### Testing result

Three focused connection tests confirmed:

- Successful transactions are committed.
- Failed transactions are rolled back.
- Connections are closed after leaving the context.

After the correction:

- 151 unit tests passed.
- Zero unclosed-database warnings remained.
- SQLite integrity checking returned `ok`.
- Foreign-key checking returned no errors.
- V2 Stage 1 passed 12 out of 12 checks.
- V2 Stage 2 passed 13 out of 13 checks.
- V2 Stage 3 passed 19 out of 19 checks.
- V2 Stage 4 passed 12 out of 12 checks.
- V2 Stage 5 passed 14 out of 14 checks.
- The original Stage 11 full-project validation passed.

### Lesson

A passing functional test suite does not prove that resources are handled correctly. Runtime warnings can expose reliability problems that become harder to correct as the project grows.

---

## Configuration-permission finding

The two new Stage 4–5 security configuration files were initially created with permission `664`.

They were changed to `640` to match the project’s sensitive configuration standard.

Verified permissions were:

- `750` for the configuration directory
- `640` for both Stage 4–5 configuration files
- `700` for the database directory
- `600` for the SQLite database

### Lesson

Git does not preserve detailed non-executable permission modes. Sensitive configuration permissions must be checked again after restoration, cloning or file creation.

---

## Stage 6 — Network, Wi-Fi and access monitoring

### Observations and decisions

- Stage 6 used 27 network events and seven Wi-Fi events.
- All 34 events used schema version `2.0` and had unique event IDs.
- The source files used controlled documentation addresses and simulated network evidence.
- The detector used device ID and asset ID as primary device references.
- MAC addresses remained supporting evidence only.
- The existing IP allowlist, IP blocklist, VPN allowlist, CYOD inventory and automation ACL were reused.
- Network alerts, access decisions and connection-timeline records were stored separately from the original Phase 3 network tables.
- Every accepted Stage 6 event received one access decision.
- WPA, downgrade and rogue-access-point findings used controlled logs. No real wireless attack or network restriction was performed.

### Database migration observation

The first Stage 6 migration created:

- 3 tables
- 17 indexes

The repeated migration created:

- 0 tables
- 0 indexes

This confirmed that the migration was repeatable.

The Stage 6 schema was also added to `database/schema.sql` so a new database can create the same tables and indexes.

### Import result

The first import produced:

- 27 accepted network events
- 7 accepted Wi-Fi events
- 0 rejected events
- 0 failed files

The total was 34 accepted events.

### Detection results

The controlled evidence produced 18 alerts:

- Three Suspicious IP Address alerts
- One Port Scanning alert
- One Repeated Connection Attempts alert
- One Abnormal Connection Pattern alert
- Four Restricted Port or Service alerts
- One Unknown CYOD Device alert
- One MAC Address Reuse or Possible Spoofing alert
- One WPA3 Policy Violation alert
- One WPA2 Downgrade Attempt alert
- One Rogue Access Point alert
- One Wi-Fi Zone Violation alert
- One Unknown Wired Device alert
- One Restricted Wired Access alert

### Network-access decision results

The 34 events produced:

- 4 Allow decisions
- 18 Deny decisions
- 11 Challenge decisions
- 1 Restrict decision

One approved VPN event was allowed with `APPROVED_VPN_EXCEPTION`.

One controlled testing event was allowed with `APPROVED_TESTING_EXCEPTION`.

The connection timeline stored all 34 events.

### Decision-precedence problem

The first network policy did not explicitly define which outcome should win when an event matched several rules.

This became important because the controlled port-scan events also matched restricted-network and restricted-port conditions.

### Fix

A deterministic outcome order was added:

1. Deny
2. Restrict
3. Challenge
4. Allow

One port-scan event matched `port_scanning`, `suspicious_ip_address` and `restricted_port_or_service`.

The final decision was Deny, while all matching rules and reason codes remained in the stored evidence.

### Response-mapping problem

The first Restrict mapping proposed `restrict_account`.

That action belonged to identity response and did not match a network-access decision.

### Fix

The Restrict mapping was changed to `apply_ubuntu_firewall_rule`.

This action already existed in the automation ACL as approval-required.

The Rogue Access Point event therefore produced a Restrict decision, but the proposed firewall action remained `approval_required` and was not executed.

### MAC-rule correction

The first configuration contained a spelling error in the `mac_reuse_or_possible_spoofing` rule name.

The name was corrected before the detector was tested.

The final rule created an alert only when different primary device identities used the same MAC address inside the configured overlap window.

The result remained a possible spoofing indicator rather than confirmation that spoofing occurred.

### Duplicate testing

The first monitoring run stored:

- 18 new alerts
- 34 new access decisions
- 34 new timeline records

The repeated run reported:

- 0 new alerts and 18 existing alerts
- 0 new decisions and 34 existing decisions
- 0 new timeline records and 34 existing records

The stored totals remained:

- 18 alerts and 18 unique alert keys
- 34 decisions and 34 unique decision keys
- 34 timeline records and 34 unique source event IDs

### False-positive investigation

The Abnormal Connection Pattern alert for `CYOD-002` was reviewed by `analyst01`.

It was classified as a False Positive and closed after the activity was confirmed as controlled after-hours connection-volume testing.

The review retained the device, IP address, investigation notes, reviewer and UTC review time.

The audit trail recorded the successful review.

### Testing result

The Stage 6 monitoring tests passed 15 tests.

The Stage 6 network-alert review tests passed eight tests.

The focused Stage 6 total was 23 passing tests.

V2 Stage 6 passed 15 out of 15 validation checks.

The complete project passed 174 unit tests.

V2 Stages 1–6 passed their validators.

The original Stage 11 full-project validation passed.

SQLite integrity checking returned `ok`, and foreign-key checking returned no errors.

### Lesson

One network event can match several valid security rules. The project needs to retain every matching reason while producing one deterministic final decision.

A detection decision and permission to perform a response are separate. A Restrict result does not bypass approval controls.

MAC reuse can support an investigation, but it should not be treated as proof of device identity.

Approved exceptions should require matching evidence and remain visible in the stored decision.

Controlled wireless logs allow the security logic to be tested without interacting with a real wireless network.

---

## Next improvement

Stage 6 uses controlled network and Wi-Fi evidence, fixed thresholds and a small approved-access-point list.

Future improvement can add longer connection baselines, more network zones and broader approved access-point evidence.

Any later integration must preserve default deny, narrow exceptions, complete reason codes, duplicate protection, audit history and approval-controlled responses.
