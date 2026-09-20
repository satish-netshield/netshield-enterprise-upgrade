# NetShield Enterprise Upgrade Engineering Notes

## Purpose

This file records meaningful observations, failures, corrections, decisions and lessons from Phase 3A V2. Detailed findings remain here so the other documents can stay focused on their own purposes.

NetShield is my project. These notes preserve the genuine engineering work, results and decisions made during its development.

---

## Foundation and ingestion

The V2 upgrade reused the existing Phase 3 RBAC, automation ACL, logging, evidence and SQLite controls.

The first consistency check found `CYOD-002` in the enterprise context but not in the CYOD inventory. The inventory was corrected before validation.

Compound source names such as `identity_risk` were initially shortened. Source handling was corrected to preserve the complete source name.

Repeated malformed inputs could create additional quarantine rows. Validation was changed to count distinct malformed evidence.

Stage 1 passed 12/12 checks. Stage 2 passed 13/13 checks. Twelve valid events were stored and two malformed events were quarantined.

Lesson: extending an existing project requires repeatable migration and duplicate-safe storage.

---

## Stage 3 observations

Database and web assets were initially treated as devices. Device evaluation was restricted to events containing a recognised device or asset identifier.

`CYOD-003` was corrected from Unknown Device to Unregistered Device because it already existed in the enterprise context.

Three relevant events produced one High-severity alert. Approved `CYOD-002` activity produced no false alert.

Stage 3 passed 19/19 checks.

Lesson: MAC addresses can support an investigation, but device and asset identifiers remain stronger evidence.

---

## Stage 4 observations

The first controlled identity dataset placed normal sign-ins outside the configured normal period. This would have created unintended abnormal-time alerts.

The event times were corrected before final detection validation. One deliberate after-hours event remained for testing.

Twenty-four events produced 16 identity alerts. VPN and approved-testing exceptions were recorded rather than silently removing evidence.

One abnormal-access-time alert was reviewed as a False Positive with investigation notes and audit evidence. A repeated detector run created no new alerts.

Stage 4 passed 12/12 validation checks and 19 focused tests.

Lesson: test data must agree with the configured baseline before results can be trusted.

---

## Stage 5 observations

The access engine reused the existing RBAC roles and automation ACL rather than creating another permission system.

Nine controlled requests produced two allow, four deny, two challenge and one restrict decision.

Policy decisions remained separate from response actions. A restrict result could be stored, but an approval-required action was not executed automatically.

A repeated policy run created no duplicate decisions.

Stage 5 passed 14/14 validation checks and 13 focused tests.

Lesson: an access decision is more useful when it stores its policy, reasons and evidence together.

---

## Stage 6 observations

One configuration contained a spelling error in the MAC-reuse rule name. It was corrected before detector validation.

The first network policy did not clearly define how overlapping outcomes should be resolved. Deterministic precedence was added:

`deny → restrict → challenge → allow`

A restrict mapping initially used an identity response action. It was replaced with the existing approval-required network action.

Thirty-four events produced 18 alerts and 34 access decisions. Repeated monitoring created no duplicates.

Stage 6 passed 15/15 validation checks and 23 focused tests.

Lesson: every matching reason should remain available even when one final decision is selected.

---

## Stage 7 observations

The first endpoint implementation created one isolation request for every Critical alert on a device. Requests were consolidated by device while retaining all supporting alert keys.

After approval, the runner displayed a newly calculated pending value rather than the stored approval state. It was corrected to read the saved record.

Twenty-six endpoint events produced 26 alerts across 13 detection types. One simulated isolation preserved all 10 supporting Critical alert keys.

Approved administrative and testing exceptions created no alerts. Stage 7 passed 14/14 checks and 17 focused tests.

Lesson: detection, approval and simulated isolation are separate records.

---

## Stage 8 observations

The first remediation handling replaced original SQL injection and dependency risk values with later verification data.

The logic was corrected so verification changed remediation state while preserving original severity, confidence, exploitability and exploitation evidence.

After a false-positive review, a repeated run displayed rebuilt Open state rather than the stored False Positive state. The runner was corrected to display the saved finding.

Sixteen events produced seven duplicate-safe findings. Final states were:

- one Open
- two Planned
- three Verified
- one False Positive

The SQL injection finding retained High severity, demonstrated exploitability and successful exploitation evidence.

Stage 8 passed 16/16 checks and 14 focused tests.

Lesson: remediation and verification add history; they must not erase original risk evidence.

---

## Stage 9 observations

The first evidence check found three access-policy mappings with unknown asset criticality.

Unknown criticality was assigned zero points. It was not treated as Low because that would create evidence that did not exist.

The engine assessed 171 evidence mappings and produced 20 current scores across users, devices, assets and incidents.

Four High-risk threshold alerts were created. Seven monitored components reported healthy status.

A repeated cycle suppressed the same four alerts during cooldown while retaining their occurrence count, suppression reason, expiry and evidence.

Stage 9 passed 20/20 checks and 15 focused tests.

Lesson: unknown context must remain unknown, and cooldown should reduce noise without hiding activity.

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

The `CYOD-002` incident retained its successful SQL injection link, endpoint evidence and vulnerability context. Unexploited findings did not create incidents by themselves.

A repeated run created no duplicate incidents, links or indicators.

Stage 10 passed 20/20 checks and 17 focused tests.

Lesson: shared context must not become an unrestricted bridge between unrelated activity.

---

## Python 3.14 database-resource finding

The full test suite initially completed successfully, but Python 3.14 reported unclosed SQLite connections through `ResourceWarning`.

This mattered because passing functional tests did not prove that database resources were released correctly. Repeated unclosed connections could hide poor connection handling and make later testing less reliable.

Database access was corrected to use managed connection handling or explicit closure. The suite was then rerun with resource warnings enabled.

The verified result was:

`151 tests passed with zero unclosed-database warnings.`

The complete finding remains here. The README keeps only the short validation result, and `docs/commands.md` keeps the operational warning-check command.

Lesson: warnings can reveal genuine engineering problems even when tests report success.

---

## Stage 11 observations

The vulnerability-link migration initially referenced a non-unique field and caused a foreign-key mismatch.

The relationship was corrected to reference the unique vulnerability finding key while preserving the original source finding identifier.

The first integrity validator compared SQLite result rows incorrectly. It was corrected to evaluate the integrity value before applying row-based checks.

The lifecycle validator initially required every lifecycle state to exist at the same time. It was corrected to validate allowed states and require an evidence-backed active investigation.

Three XDR incidents were imported:

- `INC-V2-11-0001`
- `INC-V2-11-0002`
- `INC-V2-11-0003`

One incident was assigned to `analyst01` and progressed from New to Triaged to Investigating.

An unauthorised viewer action was rejected and audited. It did not create a false-positive closure or response action.

Stage 11 preserved:

- 65 evidence links
- 10 IoCs
- 31 behaviours
- 12 ATT&CK references
- 6 vulnerability links

One vulnerability link recorded successful exploitation. The remaining links stayed context-only.

Report generation initially included its own report-generated timeline event in the input. Repeated generation then caused a report mismatch.

Report-generation events were excluded from report content so the output remained stable and hash-verifiable.

Each incident received JSON and readable reports. Repeated generation created no duplicate report records.

Lesson: incident status must describe what genuinely happened and must not imply unsupported response activity.

---

## Stage 12 observations

Stage 12 added 10 simulated containment actions to the existing ACL.

The first database initialisation stopped because its prerequisite-table check did not recognise the established database correctly. The check was aligned with the existing schema before migration continued.

The migration created four containment tables and 20 named indexes. A repeated migration created no additional objects.

Four evidence-backed actions demonstrated:

1. A simulated blocklist action succeeded.
2. An account restriction was approved, executed and safely rolled back.
3. A device-quarantine request was denied.
4. A simulated session revocation was approved but failed.

`responder01` requested the account restriction but could not approve or execute the same request. `admin01` approved and executed it.

Negative testing confirmed that:

- a viewer could not request containment
- undefined actions were denied
- denied actions could not execute
- failed actions remained failed
- irreversible actions could not invent rollback
- unrelated evidence was rejected
- target types had to match their configured actions

Twenty focused tests passed. Stage 12 passed 21/21 validation checks.

Lesson: requested, approved, executed, failed and rolled-back outcomes must remain separate.

---

## Stage 13 observations

Stage 13 added 19 simulated eradication and recovery actions with five tables and 25 named indexes.

One incident progressed through:

`Investigating → Contained → Eradicated → Recovered → Closed`

The other two incidents remained New.

Eight live actions were stored:

- four successful eradication actions
- one denied eradication action
- two successful restoration actions
- one successful monitoring action

### Self-approval persistence

A requester self-approval attempt was denied and audited. However, the first implementation updated the approval flag inside the same transaction that rolled back after the permission error.

The audit event survived, but the `self_approval_blocked` flag did not remain stored.

Denial handling was corrected so the flag persists after the failed transaction. Existing genuine audit evidence was used to reconcile the affected records. No denial evidence was invented.

### Lifecycle compatibility

The Stage 11 validator assumed the active incident would remain Investigating.

Stage 13 legitimately moved it through Contained, Eradicated, Recovered and Closed. The validator was corrected to accept later evidence-backed states while still requiring the original owner, evidence and Stage 11 decisions.

### Recovery and closure

Recovery was rejected until both required retests passed.

The final retests confirmed that:

- the original privilege-change threat was blocked
- the original Wi-Fi downgrade vulnerability was blocked

Closure then required verified eradication, verified recovery, active monitoring, lessons learned, improvement recommendations and an authorised actor.

The review was duplicate-safe.

Twenty-two focused tests passed. Stage 13 passed 27/27 validation checks.

Lesson: successful action records are not enough; recovery requires verification of the original problem.

---

## Stage 14 observations

Stage 14 introduced validation-only configuration and a full enterprise validator.

It preserves the live database while rebuilding the tracked schema in a temporary location, compiling Python, importing source modules, running regression tests, running all earlier V2 validators and checking integrated evidence.

### Temporary cleanup check

The first run rebuilt the schema successfully but failed its cleanup assertion.

The assertion ran while execution was still inside the temporary-directory context, so the database correctly still existed.

The check was moved after the context completed. This corrected the validation order without weakening the cleanup requirement.

### Results

Stage 14 passed 56/56 checks repeatedly.

Verified results included:

- 52 clean-state tables
- 211 named indexes
- 38 imported source modules
- 279 regression tests
- 13 V2 stage validators
- 176 checked audit records
- 73 incident and recovery evidence records
- no Microsoft platform SDK dependency
- no change to the live database

The live database SHA-256 remained:

`e332e619537c88df1fddb8348167e92a4a4b0a81d14b7fc1fa3396f9a783a7aa`

Lesson: validation must not change the evidence it is checking, and cleanup checks must run after cleanup occurs.

---

## Stage 15 observations

### Current-state report finding

The final report review found that the stored incident reports had valid hashes, but `INC-V2-11-0001` still showed Investigating.

Stage 13 had progressed that incident to Closed. The reports were authentic copies of an earlier state rather than accurate final reports.

The generator treated any changed report as a mismatch. This protected stored content from silent replacement but prevented an authorised lifecycle update from refreshing the reports.

The generator was corrected to:

- exclude report-generated events from report content
- refresh reports after genuine lifecycle changes
- update stored report hashes
- retain one report record and timeline event per incident
- write through a temporary file before replacement
- remain duplicate-safe on repeated runs

The Stage 11 validator was extended to compare both report formats with current incident records.

It now checks status, owner, closure details, lifecycle decisions and stored hashes.

The generator ran twice successfully. `INC-V2-11-0001` now reports Closed with its owner, closure details and final lifecycle decision.

### Final technical review

The correction passed:

- Stage 11 validation
- 279 regression tests twice
- Stage 13 validation at 27/27
- Stage 14 validation at 56/56
- SQLite integrity and foreign-key checks
- report hash and current-state checks
- duplicate-safety checks

Thresholds were reviewed against the implemented tests and evidence. No result supported changing them, so they remained unchanged.

The component inventory contained no obsolete marker or unsupported temporary workaround. Earlier Phase 3 components were retained because compatibility and regression checks still use them.

The secrets and privacy review found no private key, token, email address, personal home path or stored credential. Password matches were controlled SQL-lab parameters and queries, not embedded credentials.

Generated Python bytecode files were confirmed as ignored temporary files and removed. No untracked project file remained.

Lesson: integrity and accuracy are different checks. A matching hash does not prove that content still represents the current authoritative state.

---

## Cross-stage decisions

The following decisions remained consistent throughout Phase 3A V2:

- Preserve original evidence after scoring, remediation, correlation or response.
- Keep unknown values unknown.
- Do not convert every finding into an incident.
- Do not convert every detection into a response.
- Keep approval separate from execution.
- Keep execution separate from recovery.
- Prevent requesters from approving or executing their own disruptive requests.
- Deny undefined actions.
- Preserve denied and failed outcomes.
- Allow rollback only when it is safe and configured.
- Keep repeated runs duplicate-safe.
- Prefer stored investigation state over rebuilt display state.
- Validate report hashes and current report state.
- Keep MAC addresses as supporting evidence.
- Keep vulnerability context separate from exploitation evidence.
- Require verified recovery before closure.
- Record the responsible actor and result.
- Keep Microsoft security platforms as design concepts rather than dependencies.

---

## What was learned

The project showed that security automation must preserve evidence, explain decisions, enforce permissions, maintain history and prevent unsupported conclusions.

Repeated runs, negative tests, integrity checks and output comparisons found problems that successful first runs did not reveal.

The main lessons were:

- validate stored state, not only displayed output
- compare generated reports with current authoritative records
- preserve denied and failed outcomes
- keep approval separate from execution
- treat rollback as a controlled action
- retest the original problem before claiming recovery
- recheck earlier validators after extending shared lifecycle data
- confirm validation does not alter live evidence
- change thresholds only when evidence supports the change
- remove components only when they are genuinely obsolete
- record corrections without hiding the original failure

After Phase 3A V2 sign-off, further changes should be limited to genuine defects, security improvements or justified engineering requirements.
