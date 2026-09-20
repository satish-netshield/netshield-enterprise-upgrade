# NetShield Enterprise Upgrade Workflow

## Project boundary

Phase 3A V2 extends the completed NetShield Phase 3 Automation project inside a controlled Ubuntu VirtualBox sandbox.

The project uses Python, SQLite and simulated enterprise security data. Microsoft security platforms are design references only. No production service, external target or real response action is used.

NetShield is my project. Its design, configuration, testing, validation, corrections and documentation form part of my engineering journey.

---

## Stages 1 and 2 — Foundation and data pipeline

The V2 foundation reused the existing RBAC, automation ACL, logging, evidence and SQLite controls.

The data pipeline added simulated enterprise users, devices, applications and services. It validates JSONL input, preserves raw events, normalises UTC timestamps, rejects malformed data and prevents duplicate storage.

Testing found an incomplete CYOD inventory, shortened compound source names and repeated quarantine rows. The inventory and source handling were corrected, and malformed evidence was counted without duplication.

Stage 1 passed 12/12 checks. Stage 2 passed 13/13 checks.

Lesson: an upgrade must preserve existing controls while adding repeatable migrations and reliable data handling.

---

## Stage 3 — Asset and device identity

Stage 3 compared controlled events with the authoritative CYOD inventory. Device and asset identifiers remained primary; MAC addresses were supporting evidence only.

Database and web assets were initially treated as devices. Evaluation was restricted to recognised device or asset identifiers, and `CYOD-003` was correctly classified as unregistered.

Three relevant events produced one High-severity alert. Approved `CYOD-002` activity produced no false alert. Stage 3 passed 19/19 checks.

Lesson: device identity needs authoritative inventory context.

---

## Stages 4 and 5 — Identity and access decisions

Stage 4 evaluated authentication, location, MFA, device, privilege and account evidence. VPN and approved-testing exceptions remained narrow and auditable.

Twenty-four events produced 16 identity alerts. One alert was reviewed as a False Positive, and repeated detection created no duplicates.

Stage 5 evaluated identity, role, device, application, network and risk context. It returned `allow`, `deny`, `challenge` or `restrict` through deterministic policy precedence and default deny.

Nine requests produced two allow, four deny, two challenge and one restrict decision. Access decisions remained separate from response actions.

Lesson: every security decision should retain its policy, reasons and evidence.

---

## Stage 6 — Network and Wi-Fi monitoring

Stage 6 added network and wireless detections, access decisions and connection history.

When several rules match, the outcome order is:

`deny → restrict → challenge → allow`

A rule-name error, unclear overlap handling and an incorrect response mapping were corrected.

Thirty-four events produced 18 alerts and 34 decisions. Repeated monitoring created no duplicates. Stage 6 passed 15/15 checks.

Lesson: preserve every matching reason while selecting one clear final decision.

---

## Stage 7 — Endpoint monitoring

Stage 7 evaluated endpoint health, compliance, processes, command activity, persistence indicators, hashes and crash patterns.

Critical alerts were consolidated into one device-level simulated-isolation request. Approval used the existing RBAC and ACL controls and changed only project records.

Twenty-six events produced 26 alerts across 13 detection types. One approved simulated isolation retained all 10 supporting Critical alert keys.

Lesson: detection, approval and simulated isolation must remain separate.

---

## Stage 8 — Vulnerability management

Stage 8 added evidence-backed vulnerability and application-security findings linked to authoritative assets.

The first remediation flow replaced original risk values with later verification data. It was corrected so remediation and review add history without rewriting the original finding.

Sixteen events produced seven findings: one Open, two Planned, three Verified and one False Positive. A vulnerability alone did not create an incident.

Lesson: original severity, exploitability and evidence must remain available after remediation.

---

## Stage 9 — Continuous monitoring and risk

Stage 9 added scheduled health checks, explainable risk scoring and alert cooldown.

Risk combines severity, confidence, asset criticality, independent-source agreement, validated exceptions and time decay. Unknown criticality receives no invented value.

The engine assessed 171 evidence mappings and scored 20 entities. Four High-risk alerts were created, seven monitored components were healthy and a repeated cycle suppressed the same alerts during cooldown.

Lesson: risk should support decisions without replacing original evidence.

---

## Stage 10 — XDR-style correlation

Stage 10 correlated identity, access-policy, network, endpoint, application and vulnerability evidence.

Unrestricted grouping initially mixed unrelated device chains. Correlation was corrected to use ordered primary anchors while keeping MAC addresses, locations and detection names as supporting context.

The corrected result produced three incidents, 65 evidence links, 10 IoCs and three MAC supporting observables. Repeated correlation created no duplicates.

Lesson: correlation must explain both why evidence was joined and why other evidence remained separate.

---

## Stage 11 — Incident management

Stage 11 converted the three correlated incidents into managed records with ownership, lifecycle state, evidence, decisions, timelines, IoCs, behaviours, ATT&CK references, vulnerability links and reports.

The lifecycle is:

`New → Triaged → Investigating → Contained → Eradicated → Recovered → Closed`

Stage 11 preserved 65 evidence links, 10 IoCs, 31 behaviours, 12 ATT&CK references and six vulnerability links.

Testing found a foreign-key mismatch and overly strict integrity and lifecycle checks. Each issue was corrected without weakening evidence requirements.

Each incident received JSON and readable reports with stored SHA-256 hashes.

Lesson: incident state must reflect supported activity and must not imply that an unperformed response occurred.

---

## Stage 12 — Approval-controlled containment

Stage 12 added 10 simulated containment actions to the existing default-deny ACL.

Evidence is preserved before action. Disruptive actions require approval, requesters cannot approve or execute their own requests, and undefined actions are denied.

Four records demonstrated successful, denied, failed and rolled-back outcomes. Approval and execution remained separate, and safe rollback was duplicate-safe.

Stage 12 passed 20 focused tests and 21/21 validation checks.

Lesson: requested, approved, executed, failed and rolled-back states must remain separate and traceable.

---

## Stage 13 — Eradication, recovery and review

Stage 13 continued one evidence-backed incident through Contained, Eradicated, Recovered and Closed.

Nineteen simulated actions cover account, device, Wi-Fi, file, process, persistence, SQL, vulnerability and restoration work.

Recovery required successful retests of the original threat and vulnerability. Closure required verified recovery, post-recovery monitoring, lessons learned, improvement recommendations and an authorised decision.

Testing found that a self-approval denial flag was lost during transaction rollback. The denial handling was corrected so the audit event and database flag both remain stored.

Stage 13 passed 22 focused tests and 27/27 validation checks.

Lesson: an action reporting success does not prove recovery. The original problem must be retested.

---

## Stage 14 — Full enterprise validation

Stage 14 validates the complete upgrade without changing the live evidence database.

The validator:

1. Confirms simulation boundaries.
2. Rebuilds the tracked schema in a temporary database.
3. Checks Python syntax and source imports.
4. Runs the complete regression suite.
5. Runs all 13 earlier V2 validators.
6. Checks integrated evidence, response outcomes and audit records.
7. Compares the live database hash before and after validation.
8. Removes the temporary database.

The first cleanup check ran before the temporary-directory context finished. It was moved after cleanup and revalidated.

Stage 14 passed 56/56 checks repeatedly. It rebuilt 52 tables and 211 indexes, imported 38 source modules, ran 279 tests and confirmed that the live database remained unchanged.

Lesson: validation must not alter the evidence it is checking.

---

## Stage 15 — Final revision and sign-off

Stage 15 reviewed implementation, configuration, thresholds, reports, documentation, privacy, temporary files and Git changes.

The report review found that one incident report still showed Investigating after the incident had reached Closed. Its hash was valid, but its content represented an earlier lifecycle state.

The report generator was corrected to refresh reports after genuine lifecycle changes while keeping one report record and one timeline event per incident. The Stage 11 validator now compares report content with the current database state.

The correction passed:

- Stage 11 validation
- 279 regression tests twice
- Stage 13 validation at 27/27
- Stage 14 validation at 56/56
- SQLite integrity and foreign-key checks
- duplicate-safety and report-hash checks

No evidence supported changing the established thresholds. No obsolete project component was identified. Secret, personal-information and temporary-file reviews found no tracked credential or personal-data exposure. Generated Python cache files were removed.

Lesson: a valid file hash proves integrity, but current-state comparison is also required to prove accuracy.

---

## Completion workflow

Final sign-off follows this order:

1. Confirm implementation and documentation agree.
2. Run the complete regression and validation workflow.
3. Check database integrity, foreign keys and evidence hashes.
4. Confirm reports match current incident state.
5. Review privacy, temporary files and Git changes.
6. Confirm no real response action or external target was used.
7. Commit and push only after every check passes.
8. Confirm the local branch matches the remote branch.

After sign-off, changes should be limited to genuine defects, security improvements or justified engineering requirements.
