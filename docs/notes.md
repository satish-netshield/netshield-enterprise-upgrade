# NetShield Enterprise Upgrade Notes

## Project scope

Phase 3A V2 extends the completed NetShield Phase 3 Automation project.

These notes contain only meaningful observations, failures, fixes, decisions and lessons from the enterprise upgrade.

The project remains inside the Ubuntu VirtualBox sandbox and uses simulated security data. No real Microsoft services, external targets or production response actions are used.

---

## Stage 1 — Enterprise foundation

### Observations and decisions

- Existing SQLite, RBAC, automation ACL, logging and evidence controls were reused.
- Retention periods were configured without adding automatic deletion.
- Sensitive values are masked in suitable output while original evidence remains unchanged.

### Problems and fixes

- `CYOD-002` was present in enterprise context but missing from the authoritative inventory. The inventory and consistency checks were corrected.
- Runtime SQL injection lab files appeared as untracked files. Their paths were added to `.gitignore`.
- Sensitive configuration permissions were reapplied because Git does not preserve detailed non-executable permission modes.

### Result and lesson

Stage 1 passed 12 out of 12 validation checks.

Enterprise context, inventory and database state must agree. They cannot be treated as separate sources of truth.

---

## Stage 2 — Extended security data pipeline

### Observations

Six JSONL files contained 14 records:

- 12 valid records were accepted.
- 2 malformed records were quarantined.
- Accepted timestamps were stored in UTC.
- Original events were preserved.
- Repeated imports created no duplicate accepted events.

### Problems and fixes

- Updating `database/schema.sql` did not upgrade the existing database. A repeatable migration was added.
- Source detection shortened `identity_risk` to `identity`. Complete supported source names are now recognised.
- Repeated malformed inputs increased quarantine row counts. Validation was changed to check distinct malformed evidence.
- The original validator expected exactly five sources. It was changed to require the original sources while allowing approved V2 additions.

### Result and lesson

Stage 2 passed 13 out of 13 validation checks.

Validation must distinguish source evidence from database row counts and remain compatible with approved future sources.

---

## Stage 3 — Asset and device identity

### Observations and fixes

- Device ID and asset ID remain the primary device references.
- MAC addresses remain supporting evidence only.
- Database and web assets were initially treated as devices. Evaluation was limited to events with device evidence.
- `CYOD-003` was corrected from Unknown to Unregistered because it already existed in enterprise context.
- Device removal changes registration state instead of deleting history.

### Result and lesson

Three relevant events produced one High Unregistered Device alert for `CYOD-003`. Approved `CYOD-002` activity produced no false alert.

Stage 3 passed 19 out of 19 validation checks.

Reliable device identity requires inventory and event context. A MAC address alone is not enough.

---

## Stage 4 — Identity monitoring

### Observations

Twenty-four controlled events produced 16 traceable identity alerts.

Severity and confidence were stored separately. VPN and testing exceptions were counted instead of being silently ignored.

### Test-data problem

The first normal authentication events occurred shortly after midnight UTC, outside the configured normal access period.

This would have created unintended abnormal-time alerts even though the detector was working as configured.

### Fix

Normal events were moved inside the configured period. One deliberate event remained at `23:00` UTC to test the abnormal-time rule.

### Review and duplicate result

The deliberate Abnormal Access Time alert was reviewed by `analyst01`, classified as a False Positive and closed with investigation notes.

A repeated detector run created zero new alerts and identified all 16 as existing.

Stage 4 passed 12 out of 12 validation checks.

### Lesson

Controlled test data must agree with its configured baseline. Otherwise, a correct rule can produce misleading results.

---

## Stage 5 — Policy-based access decisions

### Observations

Nine controlled requests produced:

- 2 Allow decisions
- 4 Deny decisions
- 2 Challenge decisions
- 1 Restrict decision

Every decision retained its winning policy, matching reasons, evidence and ACL result.

### Policy decision

When policies had the same priority, the more restrictive result won:

1. Deny
2. Restrict
3. Challenge
4. Allow

This prevented a general Allow condition from overriding a stronger policy.

### ACL result

Challenge proposed the approved simulated `increase_monitoring` action.

Restrict proposed `restrict_account`, which remained approval-required and was not executed.

A repeated run created zero new decisions.

Stage 5 passed 14 out of 14 validation checks.

### Lesson

An access decision does not provide permission to perform a response. The automation ACL must still be enforced.

---

## Cross-stage validator boundary

### Problem

The Stage 3 validator used a broad V2 event query. After later events were imported, it could see records outside Stage 3.

### Fix

The query was limited to the intended Stage 3 source files. Valid later-stage data was not removed.

### Lesson

A validator should identify its own evidence directly instead of assuming that later stages will not add records to the same database.

---

## Python 3.14 SQLite connection finding

### Original finding

The complete test suite passed, but Python 3.14 reported unclosed-database `ResourceWarning` messages.

The first diagnostic found:

- 100 Python files inspected
- 89 SQLite connection calls
- 38 affected files
- 101 unclosed-database warnings
- No SQLite integrity failure
- No remaining handles after the Python process ended

The existing `with sqlite3.connect(...)` pattern handled commit and rollback but did not explicitly close the connection object.

### Original fix

A shared managed connection helper was added.

It now:

1. Opens the connection.
2. Commits successful work.
3. Rolls back failed work.
4. Closes the connection in every case.

Three focused tests confirmed commit, rollback and closure behaviour.

The corrected project then passed 151 tests with zero unclosed-database warnings. SQLite integrity returned `ok`.

### Stage 9 recurrence

Warning-enabled regression later found 20 unclosed connections in `tests/test_v2_stage9_continuous_monitoring.py`.

The warnings came from direct test connections, including setup and individual test queries. The application monitoring code was not the source.

### Stage 9 fix

The affected test connections were wrapped with `contextlib.closing` so leaving the block closed the connection explicitly.

The focused Stage 9 suite then passed all 15 tests with zero unclosed-database warnings.

Final regression after Stage 10 passed 237 tests with zero unclosed-database warnings.

### Lesson

A passing functional test suite does not prove that resources are handled correctly.

Python 3.14 warnings exposed connection-lifecycle problems that normal assertions did not detect. Test code needs the same resource discipline as application code.

---

## Stage 6 — Network and Wi-Fi monitoring

### Observations

Thirty-four controlled events produced:

- 18 alerts
- 34 access decisions
- 34 timeline records
- 4 Allow decisions
- 18 Deny decisions
- 11 Challenge decisions
- 1 Restrict decision

Approved VPN and testing exceptions remained visible in their decisions.

### Decision-precedence problem

Several port-scan events also matched restricted-network and restricted-port rules. The first policy did not define which outcome should win.

A fixed order was added:

1. Deny
2. Restrict
3. Challenge
4. Allow

All matching rules remained in the evidence.

### Response-mapping problem

The first network Restrict mapping proposed the identity action `restrict_account`.

It was replaced with `apply_ubuntu_firewall_rule`, which already existed as an approval-required action.

No real firewall change occurred.

### Other findings

- A spelling error in the MAC-reuse rule name was corrected.
- MAC reuse remained a possible spoofing indicator, not proof of spoofing.
- One Abnormal Connection Pattern alert was reviewed and closed as a supported False Positive.
- A repeated run created no new alerts, decisions or timeline records.

### Result and lesson

Twenty-three focused tests passed. Stage 6 passed 15 out of 15 validation checks.

One event can match several valid rules. Every reason should remain visible even when one final decision is selected.

---

## Stage 7 — Endpoint monitoring and investigation

### Observations

Twenty-six endpoint events produced:

- 26 alerts
- 13 detection types
- 10 Critical alerts
- 13 High alerts
- 3 Medium alerts
- 26 timeline records
- 2 approved exceptions with no alerts

The crash or restart threshold was three events within eight minutes.

### Incomplete-file finding

The event generator contained duplicated text and failed syntax checking.

A later endpoint-engine transfer ended inside a return annotation. File-tail inspection showed that the pasted file was incomplete.

Both files were corrected and compiled before execution.

### Isolation-consolidation problem

The first run created ten isolation requests for `CYOD-002`, one for each Critical alert.

The requests were consolidated by device while preserving all ten supporting alert keys.

The final record remained simulation-only:

- Status: `simulated_isolated`
- Approved by: `responder01`
- Real action executed: 0
- Network state changed: 0

### Status and output corrections

The approval script first attempted to store `simulated_approved`, which the table constraint did not permit.

It was corrected to use the existing `simulated_isolated` status.

The runner also printed a newly calculated pending state after approval. It was changed to read the stored isolation record before reporting status.

### False-positive investigation

The Repeated Process Crash or Restart alert was reviewed by `analyst01`.

Three events occurred within seven minutes, but the supplied evidence showed an approved process and a registered, compliant, low-risk device. The alert was classified as a False Positive without inventing a maintenance explanation.

Repeated monitoring preserved both the completed review and simulated approval.

### Result and lesson

All 17 focused tests passed. Stage 7 passed 14 out of 14 validation checks.

Several findings on one device can support one containment request without losing their separate evidence.

Printed output must reflect stored state, and investigation notes must separate observed facts from assumptions.

---

## Stage 8 — Vulnerability and application-security findings

### Observations and decisions

Sixteen controlled events produced seven asset-linked findings:

| Finding | Priority | Status |
|---|---:|---|
| SQL injection authentication bypass | High — 71.05 | Verified |
| Restricted service exposed inside the sandbox | Medium — 64.65 | Open |
| Outdated local demonstration dependency | Medium — 64.20 | Verified |
| Outdated sandbox package | Medium — 53.60 | Planned |
| Missing local security header | Medium — 43.80 | Planned |
| Version-only finding requiring analyst review | Low — 39.50 | False Positive |
| Sensitive configuration permission check | Low — 27.50 | Verified |

Priority used severity, confidence, exploitability, exposed-service context and asset criticality.

Original risk evidence remained unchanged when remediation or verification status changed.

### Incident boundary

The successful SQL injection finding retained:

- One finding-to-alert link to `S78-END-020`
- One finding-to-incident link to `INC-V2-001`
- Successful exploitation evidence

Other vulnerabilities did not create incidents because vulnerability presence alone was not treated as exploitation.

### False-positive review

A Viewer review was rejected.

`analyst01` reviewed the version-only finding and recorded that the controlled evidence did not confirm exploitation or a vulnerable component.

The finding became False Positive without deleting its evidence.

A repeated vulnerability run preserved the completed review.

### Metadata-status failure

The first Stage 8 validation passed its first 15 checks but failed the audit and completion check.

The database still contained:

```text
vulnerability_management_foundation_ready
```

The audit records showed that initialisation, import, management and review had all succeeded.

The management runner was executed again, which correctly updated the metadata to:

```text
vulnerability_management_complete
```

Stage 8 then passed all 16 validation checks.

### Result and lesson

All 14 focused tests passed. Stage 8 passed 16 out of 16 validation checks.

Remediation state must not replace original vulnerability evidence. A finding also needs activity or exploitation evidence before it can support an incident.

---

## Stage 9 — Continuous monitoring and dynamic risk scoring

### Observations and decisions

Stage 9 added:

- Five monitoring and risk tables
- Twenty-two indexes
- Deterministic 15-minute cycles
- User, device, asset and incident scores
- Threshold and health alerts
- Cooldown suppression
- Last-successful-run tracking

The risk engine loaded 171 evidence mappings and scored 20 entities.

Risk scores retained their original evidence references and did not replace alerts or findings.

### Evidence-loading check

An early inspection assertion failed because the expected evidence assumptions did not match the actual stored data.

The source counts and entity mappings were inspected instead of changing valid evidence.

The final source loader found:

- 171 evidence mappings
- 20 scored entities
- 9 validated exceptions
- 3 mappings with unknown asset criticality
- 0 empty evidence references

### Unknown-criticality decision

Some access-policy evidence used assets whose criticality was unknown.

Unknown criticality was assigned zero additional points. It was not silently treated as Low.

This kept missing context from increasing risk.

### Risk result

The current assessment produced four High threshold alerts:

- Asset `AST-001`: 71.00
- User `viewer01`: 71.00
- Device `CYOD-001`: 66.00
- User `responder01`: 66.00

Independent sources increased risk. Validated exceptions and older evidence reduced it.

### Cooldown behaviour

The first cycle created four threshold alerts.

A normal attempt to process the same interval was suppressed.

A controlled repeated cycle assessed the evidence again but created no new alerts. All four existing alerts were suppressed during their active cooldown and retained their supporting evidence.

### Health monitoring

Seven components reported Healthy:

- Access policy
- Endpoint detection
- Identity detection
- Ingestion
- Network detection
- Risk assessment
- Vulnerability management

No health or pipeline-failure alert was required.

### Inspection-query error

An inspection query requested a non-existent `suppressed_count` column.

The table uses `occurrence_count`, `suppression_reason` and `cooldown_until`.

The query was corrected. No schema change was required.

### Result and lesson

All 15 focused tests passed. Stage 9 passed 20 out of 20 validation checks.

The project regression passed 220 tests after the Stage 9 connection-warning correction.

Risk scoring becomes more useful when independent agreement, validated exceptions and time are considered together. The score must still point back to the original evidence.

---

## Stage 10 — XDR-style cross-source correlation

### Observations and decisions

Stage 10 loaded 76 unique evidence records across:

- Identity
- Access policy
- Network
- Endpoint
- Application
- Vulnerability

The correlation window was 2,160 minutes.

Device ID, asset ID, username, IP address, hostname, file hash and process evidence were available for correlation. MAC address remained supporting evidence only.

### Initial over-correlation problem

The first unrestricted transitive grouping joined 65 of the 76 records into one incident.

Shared context allowed evidence for `CYOD-001` and `CYOD-002` to become part of the same chain.

The result retained evidence, but it did not keep unrelated device activity separate.

### Fix

Correlation was changed to use deterministic primary anchors.

Strong device and asset identity was considered before weaker shared context. A common username, location, detection type or MAC address could no longer bridge otherwise separate device chains.

Explicit exploitation links remained able to join their named records.

A regression test confirmed that a shared username could not merge unrelated devices.

### Final incident result

Ten candidate groups produced three context-rich incidents:

| Device | Severity | Confidence | Sources | Evidence |
|---|---|---:|---:|---:|
| `CYOD-001` | Critical | 95 | 3 | 13 |
| `CYOD-002` | Critical | 88 | 6 | 49 |
| `CYOD-003` | Medium | 70 | 2 | 3 |

The incidents retained 65 duplicate-safe evidence links.

Independent sources increased confidence. Validated exceptions and verified activity reduced confidence without deleting evidence.

Repeated detections from one source event were retained but scored only once.

### Vulnerability handling

The successful SQL injection finding retained its explicit link to endpoint evidence.

Unexploited findings remained `context_only` and did not create incidents by themselves.

This preserved prevention context without presenting every vulnerability as an attack.

### Indicator handling

The final run stored:

- 10 IoCs
- 3 supporting observables
- 13 indicators in total

Supported IP addresses, hostnames, process names and a file hash were stored as IoCs.

MAC addresses remained supporting observables.

Suspicious behaviours and ATT&CK mappings remained separate from IoCs.

### Duplicate result

The repeated run reported:

- 3 existing incidents and 0 new incidents
- 65 existing evidence links and 0 new links
- 13 existing indicators and 0 new indicators
- 0 automatic response actions

### Other operational findings

- An inspection query used `metadata`, but the established table is `system_metadata`. The query was corrected without changing the schema.
- A bracketed-paste sequence created an accidental file named with terminal control characters. The file was identified and moved to `/tmp`.

### Result and lesson

All 17 focused tests passed. Stage 10 passed 20 out of 20 validation checks.

The final project regression passed 237 tests with zero unclosed-database warnings. SQLite integrity returned `ok`.

Correlation needs strong anchors and clear boundaries. Shared context can support an incident, but it should not be allowed to merge unrelated activity.

---

## Final engineering observations

- Risk scores and incidents support investigation; they do not replace evidence.
- Independent sources should strengthen confidence, but repeated evidence must not inflate it.
- Exceptions should reduce risk only after a supported review.
- Vulnerabilities provide context unless activity supports attempted or successful exploitation.
- MAC addresses can support an investigation but should not identify a device by themselves.
- Stored investigation state must survive repeated processing.
- Additional controlled datasets can improve future tuning of weights, decay, thresholds, cooldowns, correlation windows and anchor priority.
