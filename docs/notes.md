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

These are the results from the Stage 4–5 connection correction. Later regression totals are recorded under their respective stages.

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

## Stage 7 — Endpoint monitoring and investigation

### Observations and decisions

- Stage 7 used 26 controlled endpoint events.
- Device, process, owner, parent-child, command, CPU, file and inventory evidence were retained for investigation.
- The agreed crash or restart threshold was changed from ten minutes to three events within eight minutes.
- Administrative and testing exceptions required exact configured evidence.
- Critical alerts used the existing approval-required `quarantine_device` action.
- Isolation remained simulation-only. No Wi-Fi, firewall, network, process or operating-system changes were performed.
- Stage 7 and Stage 8 preparation initially shared a migration and event pipeline, but implementation continued one stage at a time.

### Shared preparation boundary

The first Stage 7–8 migration created six tables and 29 indexes. Running it again created zero tables and zero indexes.

The shared source set contained 42 events:

- 26 endpoint events for Stage 7
- 6 application-security events prepared for Stage 8
- 10 vulnerability events prepared for Stage 8

The first import accepted all 42 records with no rejected events or failed files.

The repeated import accepted zero records and rejected all 42 as duplicates. The accepted-event total remained 42.

At that point, the 16 Stage 8 records were preparation only. Stage 8 implementation and validation are recorded separately below.

The SQL injection lab asset `AST-WEB-001` was added to enterprise context as a sandbox web-application asset with Medium criticality, not as a CYOD device. Stage 1 tests and validation still passed.

### Metadata-query finding

An inspection query used `project_metadata`, which does not exist in the established database.

The project uses `system_metadata`. The query was corrected without creating another metadata table.

### Incomplete source-file finding

The event generator initially contained duplicated text in an `endpoint_event` call and failed syntax checking.

A later endpoint-engine replacement ended inside a return annotation at line 1204. The file tail confirmed that the pasted file was incomplete.

The source files were corrected and checked with Python compilation before execution.

The complete endpoint-engine replacement then passed checks for alert counts, Critical alerts, consolidated requests and simulation-only safety.

### Detection results

The controlled endpoint run produced:

- 26 alerts
- 13 detection types
- 10 Critical alerts
- 13 High alerts
- 3 Medium alerts
- 0 Low alerts
- 26 activity-timeline records
- 2 approved exceptions with no alerts

One event could support several findings. For example, a suspicious process could also be unapproved or have a suspicious parent-child relationship. The alert total therefore did not represent 26 separate affected devices or attacks.

### Crash or restart evidence

The related events were:

- `S78-END-017` at `09:40` UTC
- `S78-END-018` at `09:44` UTC
- `S78-END-019` at `09:47` UTC

The stored observations showed:

- Event count: 3
- Configured window: 8 minutes
- Observed window: 7 minutes

The rule correctly created one Repeated Process Crash or Restart alert for `netshield_worker`.

### Isolation-consolidation finding

The first run created ten approval-required isolation requests for `CYOD-002`, one for each Critical alert.

This repeated the device-level request unnecessarily.

The request builder was changed to consolidate Critical alerts by device while preserving every supporting alert key.

After the corrected engine passed its checks, the ten superseded pending simulation records were removed. A database backup was made before this correction.

The next run created one consolidated request. It retained:

- Device: `CYOD-002`
- Action: `quarantine_device`
- Control level: `approval_required`
- Critical alert count: 10
- Preserved Critical alert keys: 10
- Real actions: 0
- Network changes: 0

Repeating the run created zero new requests and identified the consolidated request as existing.

### Approval-status constraint finding

The approval script initially attempted to store `simulated_approved`.

SQLite rejected the update because the existing table constraint permits only:

- `approval_required`
- `simulated_isolated`
- `rejected`

The failed transaction left the request pending, with its original evidence intact.

The script was corrected to use the established `simulated_isolated` status rather than changing the database constraint.

This also matched the status already defined in the endpoint configuration.

### Simulated approval result

Analyst approval was rejected because the role lacked `execute_approved_containment`.

`responder01` successfully approved isolation record `11`.

The stored record showed:

- Status: `simulated_isolated`
- Approver role: `responder`
- Critical alert count: 10
- Preserved alert keys: 10
- Network state changed: 0
- Real action executed: 0

Approval notes, actor and UTC approval time were retained. The successful action was recorded in the audit trail.

A repeated approval attempt was rejected because the request was no longer awaiting approval.

Focused tests also confirmed that an Administrator could approve the simulated record.

### Runner-reporting finding

After approval, the runner printed `approval_required` from the newly calculated request even though the stored record correctly remained `simulated_isolated`.

The database had not reverted, but the console output was misleading.

The runner was corrected to load the stored isolation record after processing.

The verified output then showed:

```text
[ISOLATION RECORD] device=CYOD-002 | action=quarantine_device | status=simulated_isolated | approved_by=responder01 | real_action=False | network_change=False
```

The summary reported zero new isolation requests and one existing request.

### Endpoint-alert query finding

An inspection query requested `source_event_id` from the alert table.

Endpoint alerts store `source_event_ids` as a JSON list because a finding can involve several events.

The query was corrected to use the existing plural field. No schema change was required.

### False-positive investigation

Alert `18`, Repeated Process Crash or Restart, was reviewed by `analyst01`.

Its evidence recorded an approved `netshield_worker` process and a registered, compliant device with a low-risk inventory state.

The threshold match was valid. The security investigation classified the alert as a False Positive and closed it with these notes:

```text
Reviewed three crash and restart events within seven minutes. The detected process is approved, and the registered device is compliant with a low-risk state. No malicious activity is established by this alert evidence.
```

The notes did not claim that maintenance or service-recovery work had occurred, because that was not established by the supplied events.

Viewer review was rejected. Repeated review of the closed alert was also rejected.

The original source-event references, severity, confidence, investigation notes, reviewer and UTC review time remained available. The successful review was audited.

### Repeated-run result

After approval and false-positive review, the monitoring run reported:

- 26 detections
- 0 new alerts and 26 existing alerts
- 0 new timeline records and 26 existing records
- 0 new isolation requests and 1 existing request
- 2 approved exceptions
- 0 real actions
- 0 network changes

Alert `18` remained Closed with its False Positive classification.

Isolation record `11` remained `simulated_isolated` with `responder01` recorded as approver.

The controlled post-isolation event remained monitored. This represents supplied simulation evidence, not proof of real network isolation.

### Tracked-schema result

The working migration had already created the Stage 7 tables, but they were initially absent from `database/schema.sql`.

Only the Stage 7 objects were added:

- 3 endpoint tables
- 16 indexes

The combined tracked schema was executed successfully against a temporary in-memory database before being saved.

Stage 8 tables and indexes were not added to the tracked schema during this step.

### Final testing result

The saved Stage 7 test file compiled successfully.

All 17 focused tests passed.

Stage 7 validation passed 14 out of 14 checks.

The final project regression produced:

```text
Ran 191 tests in 2.060s

OK
```

The warning-enabled regression reported zero unclosed-database warnings.

V2 Stages 1–7 passed their validators.

The original Phase 3 Stage 11 full-project validation passed. Its references to Stages 8–10 concern the completed original Phase 3 project, not the pending V2 Stage 8 implementation.

SQLite integrity checking returned `ok`, and foreign-key checking reported no violations.

Python syntax compilation and `git diff --check` completed without errors.

### Lessons

Several Critical findings on one device can support one isolation request without losing their separate evidence.

The full table definition must be inspected before choosing a stored status. Column listings alone do not show SQLite `CHECK` constraints.

Printed output must reflect the stored approval or investigation state rather than only the current detector calculation.

A process crash pattern can be correctly detected without establishing malicious activity. Investigation notes must distinguish observed symptoms from conclusions and must not invent a maintenance explanation.

Repeated processing should preserve reviews and approvals, not reset them.

Compilation and file-tail checks are useful when a complete source file is transferred through copy-paste.

---

## Stage 8 — Vulnerability and application-security findings

### Observations and decisions

- Stage 8 used six application-security events and ten vulnerability events.
- All 16 events were already stored once through the shared V2 pipeline.
- Findings required authoritative asset context from `config/enterprise_context.json`.
- All managed findings used the registered sandbox asset `AST-WEB-001`.
- Severity, confidence, exploitability, exploitation status, exposed-service context and asset criticality remained separate fields.
- Priority used the configured weighted score instead of severity alone.
- Approved penetration-testing events remained testing evidence and did not become findings.
- Automatic incident creation remained disabled.
- A finding-to-incident link required exploitation or other supporting activity evidence.
- No external target or real penetration-testing action was used.

### Finding results

The controlled evidence produced seven duplicate-safe findings:

| Finding | Priority | Score | Remediation status |
|---|---:|---:|---|
| SQL injection authentication bypass | High | 71.05 | Verified |
| Restricted service exposed inside the sandbox | Medium | 64.65 | Open |
| Outdated local demonstration dependency | Medium | 64.20 | Verified |
| Outdated sandbox package | Medium | 53.60 | Planned |
| Missing local security header | Medium | 43.80 | Planned |
| Version-only finding requiring analyst review | Low | 39.50 | False Positive |
| Sensitive configuration permission check | Low | 27.50 | Verified |

The final totals were:

- 1 High-priority finding
- 4 Medium-priority findings
- 2 Low-priority findings
- 1 Open finding
- 2 Planned findings
- 3 Verified findings
- 1 False Positive

### Original-risk preservation problem

The first remediation handling allowed later Low-severity verification events to replace the original risk fields.

This reduced the SQL injection finding to a Low priority score of `31.15` and the dependency finding to `31.05`, even though their original evidence remained more serious.

The SQL injection result also appeared to have no exploitability or exploitation context after successful controlled exploitation had already been recorded.

### Fix

Remediation events were limited to updating the component information and remediation status.

They no longer replace the original:

- Severity
- Confidence
- Exploitability
- Exploitation status
- Exposed-service context
- Asset criticality

After the correction:

- The SQL injection finding retained High severity, demonstrated exploitability and successful exploitation evidence, producing a High priority score of `71.05`.
- The dependency finding retained High severity and high exploitability, producing a Medium priority score of `64.20`.
- Both findings could remain Verified without losing their original risk evidence.

### Remediation history observation

The engine built 12 duplicate-safe history records from the controlled source events.

The false-positive review added one later review record, bringing the stored total to 13 unique history records.

Remediation verification preserved the later supporting evidence without removing the original finding or its earlier status changes.

### Finding-link decisions

The SQL injection finding retained two evidence-based links:

- One alert link to `S78-END-020`
- One incident link to `INC-V2-001`

Both links retained successful exploitation context.

A separate test confirmed that an incident link without exploitation evidence was rejected.

No incident was created automatically.

### Approved-testing evidence

The controlled testing records were:

- `S78-APPSEC-TEST-001` for the local SQL injection lab
- `S78-VULN-TEST-001` for the local sandbox

Both records confirmed that the target was local and that no external target was used.

The events remained approved testing evidence and were not converted into vulnerability findings.

### False-positive investigation

The version-only finding `S78-FND-FP-001` was reviewed by `analyst01`.

The stored notes were:

```text
Reviewed the version-only match for demo-utility 3.0.0-simulated. The controlled evidence contains no exploitation activity and does not confirm that the component is vulnerable.
```

The finding was classified as a False Positive.

Its remediation status, classification, reviewer, UTC review time and review history were preserved.

Viewer review was rejected because the role lacked the required investigation permissions.

A finding without supporting review-candidate evidence was also rejected from the false-positive workflow.

### Runner-reporting finding

After the false-positive review, the engine rebuilt the controlled finding with an Open status and printed that calculated state.

The stored database record correctly remained False Positive, but the console output did not reflect it.

The runner was corrected to reload the stored findings after duplicate-safe storage.

The repeated output then showed:

```text
[Low] Version-only finding requiring analyst review | finding=S78-FND-FP-001 | asset=AST-WEB-001 | score=39.50 | status=False Positive
```

The summary also recorded one False Positive instead of counting the reviewed finding as Open.

### Duplicate testing

The repeated Stage 8 run reported:

- 7 findings
- 0 new findings and 7 existing findings
- 0 new source-driven history records and 12 existing records
- 0 new links and 2 existing links
- 1 preserved False Positive
- 0 automatic incidents
- 0 external targets

The Analyst review remained stored after repeated processing.

### Tracked-schema observation

The Stage 8 database objects already existed through the shared migration, but they had not yet been added to `database/schema.sql`.

The tracked schema was updated with:

- 3 vulnerability tables
- 13 named indexes

SQLite also reported three automatic indexes created for unique constraints. These were database-managed indexes rather than additional named Stage 8 indexes.

The complete tracked schema executed successfully against an in-memory database.

Repeated migration created no additional tables or indexes.

### Metadata validation finding

The Stage 8 validator initially found `v2_stage_8_status` set to `vulnerability_management_foundation_ready`.

This occurred because the shared initialisation script had been run again after the vulnerability engine had previously completed.

The initialisation, import, engine and review audit events were present, but the metadata correctly reflected the most recent initialisation step.

The Stage 8 engine was run again after migration testing. It restored the operational status to `vulnerability_management_complete` without duplicating findings, history or links.

The validator then passed the metadata and audit check.

### Python 3.14 warning check

The first Stage 8 focused-test run used direct SQLite connection contexts in the new test file and produced unclosed-database warnings under Python 3.14.

The test connections were changed to use the project’s managed connection helper.

The warning-enabled complete regression then reported zero unclosed-database warnings.

This did not require another project-wide connection rewrite. The issue was limited to the new Stage 8 test connections.

### Final testing result

All 14 focused Stage 8 tests passed.

Stage 8 validation passed 16 out of 16 checks.

Stage 7 validation still passed 14 out of 14 checks after the shared Stage 7–8 components were exercised.

The complete project regression produced:

```text
Ran 205 tests in 2.200s

OK
```

The warning-enabled regression reported zero unclosed-database warnings.

The original Phase 3 Stage 11 full-project validation passed.

SQLite integrity checking returned `ok`, and foreign-key checking reported no violations.

Python syntax compilation and `git diff --check` completed without errors.

### Lessons

Remediation verification must not erase the original risk that caused a finding to be prioritised.

A vulnerability alone is not an incident. Alert and incident links need supporting activity or exploitation evidence.

Stored investigation state must be loaded after processing so repeated output reflects completed reviews.

Approved penetration-testing activity is evidence of controlled testing, not automatically a vulnerability finding.

Authoritative asset context prevents findings from being stored against unknown or invented assets.

A validator should report the latest operational state accurately. If an initialisation step resets readiness metadata, the completed engine must run again before final validation.

---

## Next improvement

Stage 8 is complete and validated.

Any later project stage will be handled separately and only within its agreed scope. Completed findings, remediation history, reviews and evidence links must remain available when the project is extended.
