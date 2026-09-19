# NetShield Engineering Notes

## Purpose

This file records meaningful observations, failures, corrections, decisions and lessons from Phase 3A V2. Detailed findings are kept here so the other documents can remain focused on their own purposes.

NetShield is my project and part of my engineering journey. The notes describe project outcomes without claiming personal hand-coding or independent source-code authorship.

---

## Foundation and ingestion

The V2 upgrade reused the Phase 3 RBAC, automation ACL, logging and SQLite controls.

The first enterprise consistency check found `CYOD-002` in the enterprise context but not in the CYOD inventory. The inventory was corrected before validation.

Compound source names such as `identity_risk` were initially shortened. Source handling was corrected to preserve the complete source name.

Repeated malformed inputs could create additional quarantine rows. Validation was changed to count distinct malformed evidence.

Stage 1 passed 12/12 checks. Stage 2 passed 13/13 checks. Twelve valid events were stored and two malformed events were quarantined.

Lesson: a repeatable migration and duplicate-safe storage are required when extending an existing project.

---

## Stage 3 observations

Database and web assets were initially treated as devices. Device evaluation was restricted to events containing a device identifier or a known asset identifier.

`CYOD-003` was corrected from Unknown Device to Unregistered Device because it already existed in the enterprise context.

Three relevant device events produced one High-severity alert for `CYOD-003`. Approved `CYOD-002` activity produced no false alert.

Stage 3 passed 19/19 validation checks.

Lesson: a MAC address can support an investigation, but device and asset identifiers remain the stronger identity evidence.

---

## Stage 4 observations

The first controlled identity dataset placed normal sign-ins outside the configured normal period. This would have created unintended abnormal-time alerts.

The event times were corrected before final detection validation. One deliberate after-hours event remained for testing.

Twenty-four events produced 16 identity alerts. VPN and approved-testing exceptions were recorded rather than silently suppressing evidence.

One abnormal-access-time alert was reviewed as a False Positive with investigation notes and audit evidence. A repeated detector run created no new alerts.

Stage 4 passed 12/12 validation checks and 19 focused tests.

Lesson: test data must agree with the configured baseline before detection results can be interpreted.

---

## Stage 5 observations

The access engine reused the existing RBAC roles and automation ACL rather than creating another permission system.

Nine controlled requests produced two allow, four deny, two challenge and one restrict decision.

The policy decision and response action remained separate. A restrict result could be recorded, but an approval-required account action was not executed automatically.

A repeated policy run created no duplicate decisions.

Stage 5 passed 14/14 validation checks and 13 focused tests.

Lesson: an access result is more useful when it stores the winning policy, matching reasons and supporting evidence together.

---

## Stage 6 observations

One configuration contained a spelling error in the MAC-reuse rule name. It was corrected before detector validation.

The first network policy did not clearly define how overlapping outcomes should be resolved. Deterministic precedence was added:

`deny → restrict → challenge → allow`

A restrict mapping initially used an identity response action. It was replaced with the existing approval-required network action.

Thirty-four events produced 18 alerts and 34 access decisions. Repeated monitoring created no duplicate alerts, decisions or timeline records.

Stage 6 passed 15/15 validation checks and 23 focused tests.

Lesson: one network event can match several rules, so every reason should be retained even when only one final decision is selected.

---

## Stage 7 observations

The first endpoint implementation created one isolation request for every Critical alert on a device. Requests were consolidated by device while preserving all supporting alert keys.

After approval, the runner displayed a newly calculated pending value instead of the stored approval state. It was corrected to read the saved record.

Twenty-six endpoint events produced 26 alerts across 13 detection types. One simulated isolation preserved all 10 supporting Critical alert keys.

Approved administrative and testing exceptions created no alerts. Stage 7 passed 14/14 validation checks and 17 focused tests.

Lesson: detection, approval and simulated isolation are separate records and must remain separate.

---

## Stage 8 observations

The first remediation handling replaced original SQL injection and dependency risk values with later verification data. The logic was corrected so verification changes remediation state while preserving original severity, confidence, exploitability and exploitation evidence.

After a false-positive review, a repeated run displayed rebuilt `Open` state instead of the stored False Positive state. The runner was corrected to display the saved finding.

Sixteen events produced seven duplicate-safe findings linked to the authoritative sandbox asset.

Final remediation states were:

- one Open
- two Planned
- three Verified
- one False Positive

The SQL injection finding retained High severity, demonstrated exploitability and successful exploitation evidence. One alert link and one incident link were supported by exploitation evidence.

Stage 8 passed 16/16 validation checks and 14 focused tests.

Lesson: remediation and verification add history; they must not erase the original risk evidence.

---

## Stage 9 observations

The first evidence check found three access-policy mappings with unknown asset criticality.

Unknown criticality was deliberately assigned zero points. It was not treated as Low because that would create risk evidence that did not exist.

The engine assessed 171 evidence mappings and produced 20 current scores across users, devices, assets and incidents.

Four High-risk threshold alerts were created. Seven monitored components reported healthy status.

A repeated cycle suppressed the same four alerts during cooldown. Occurrence count, suppression reason, cooldown expiry and evidence remained stored.

Stage 9 passed 20/20 validation checks and 15 focused tests.

Lesson: unknown context must remain unknown, and cooldown should reduce noise without hiding repeated activity.

---

## Stage 10 observations

The first correlation run used unrestricted transitive grouping. Shared fields incorrectly mixed separate device chains and placed 65 records into one incident.

Grouping was corrected to use one ordered primary anchor per record. Explicit exploitation links remained available for directly supported relationships.

The corrected result produced:

- 10 candidate groups
- 3 incidents
- 65 evidence links
- 10 IoCs
- 3 MAC supporting observables

The `CYOD-001`, `CYOD-002` and `CYOD-003` chains remained separate.

The `CYOD-002` incident retained the successful SQL injection link, endpoint evidence and vulnerability context. Unexploited findings did not create incidents by themselves.

A repeated correlation run created no duplicate incidents, links or indicators.

Stage 10 passed 20/20 validation checks and 17 focused tests.

Lesson: a shared username, IP address or MAC address must not become an unrestricted bridge between unrelated device activity.

---

## Stage 11 observations

The Stage 11 vulnerability-link migration initially referenced a non-unique field and caused a foreign-key mismatch.

The relationship was corrected to reference the unique vulnerability finding key while preserving the original source finding identifier.

The initial integrity validator compared SQLite result rows incorrectly. It was corrected to evaluate the integrity value before applying row-based checks.

The lifecycle validator initially required every lifecycle state to appear at the same time. It was corrected to validate allowed states and require an evidence-backed active investigation.

Three XDR incidents were imported with managed IDs:

- `INC-V2-11-0001`
- `INC-V2-11-0002`
- `INC-V2-11-0003`

One incident was assigned to `analyst01` and progressed from New to Triaged to Investigating.

An unauthorised viewer action was rejected and recorded in the audit trail. No false-positive closure or response action was created by that denied request.

Stage 11 context storage preserved:

- 65 evidence links
- SHA-256 evidence hashes
- 10 IoCs
- 31 behaviours
- 12 ATT&CK references
- 6 vulnerability links

One vulnerability link recorded successful exploitation. The remaining vulnerability links remained context-only.

Report generation initially included its own report-generated timeline event in the report input. That made repeated generation produce a mismatch. Report-generation events were excluded from report content so the output remained stable and hash-verifiable.

Each incident now has a JSON report and a readable text report. Repeated report generation created no duplicate report records.

Stage 11 validation passed. SQLite integrity, foreign keys, evidence hashes, lifecycle records, permissions, reports and audit records were valid.

Lesson: incident status must describe what genuinely happened. It must not imply containment, eradication or recovery without supporting action and verification evidence.

---

## Cross-stage decisions

The following decisions were retained throughout the project:

- Original evidence is preserved after scoring, remediation, correlation or review.
- Unknown values are not silently converted into safe or risky values.
- A finding does not automatically become an incident.
- A detection does not automatically perform a response action.
- Approval-required actions remain approval-required.
- Denied actions are recorded as denied, not successful.
- Repeated runs are duplicate-safe.
- Stored investigation state takes priority over rebuilt display output.
- MAC addresses remain supporting evidence.
- Vulnerability context is separate from exploitation evidence.
- Audit records identify the actor, action, target, result and evidence where applicable.

---

## What was learned

The project showed that security automation is not only about detecting conditions. It must also preserve evidence, explain decisions, enforce permissions, maintain history and prevent unsupported conclusions.

The most important corrections came from repeated runs, database integrity checks, validation failures and output comparisons.

A safe next step is approval-controlled containment and response, followed by verified eradication, recovery and post-incident review. Those stages must continue to use simulated actions, preserved evidence, least privilege and explicit validation.
