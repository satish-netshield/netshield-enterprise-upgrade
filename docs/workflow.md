# NetShield Enterprise Upgrade Workflow

## Project boundary

Phase 3A V2 extends the completed NetShield Phase 3 Automation project inside the controlled Ubuntu VirtualBox sandbox.

The project uses Python, SQLite and simulated enterprise security data. Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design references only. No production services, external targets or real response actions are used.

NetShield is my project: its scope, security logic, configuration, testing, validation, corrections and documentation form part of my engineering journey.

---

## Stages 1 and 2 — Foundation and data pipeline

The foundation reused the existing RBAC, automation ACL, logging and SQLite controls. The pipeline added simulated enterprise users, devices, applications and services, retention rules, sensitive-field masking, JSONL validation, UTC timestamps, raw-event preservation, duplicate protection and malformed-event quarantine.

The database was upgraded through repeatable migrations rather than by changing `schema.sql` alone.

The main problems were an incomplete CYOD inventory, shortened compound source names and repeated quarantine rows. The inventory was corrected, complete source names were preserved and validation counted distinct malformed evidence.

Stage 1 passed 12/12 checks. Stage 2 passed 13/13 checks, with 12 valid events stored and two malformed events quarantined.

Lesson: extending an existing security system requires preserving its original controls and evidence model.

---

## Stage 3 — Asset and device identity

Stage 3 matched controlled events with the authoritative CYOD inventory using device and asset identifiers. MAC addresses remained supporting evidence only. Registration, compliance, ownership, stale-device and removal states were preserved.

Database and web assets were initially treated as devices. Evaluation was limited to known device or asset identifiers. `CYOD-003` was corrected to Unregistered Device because it already existed in the enterprise context.

Three relevant events produced one High-severity alert for `CYOD-003`. Approved `CYOD-002` activity created no false alert. Stage 3 passed 19/19 validation checks.

Lesson: device identity needs inventory context; a MAC address alone is not enough.

---

## Stages 4 and 5 — Identity and access decisions

Stage 4 grouped authentication and identity-risk events by user, source address and time window. It evaluated sign-in, device, location, MFA, privilege and account evidence, while keeping VPN and testing exceptions narrow and auditable.

Twenty-four events produced 16 alerts. A repeated run created no duplicates. One abnormal-access-time alert was reviewed as a False Positive with notes and audit evidence. Stage 4 passed 12/12 validation checks.

The first normal-activity timestamps fell outside the configured period. They were corrected before final validation.

Stage 5 evaluated access requests using identity, role, device, application, network, location, risk and MFA evidence. It returned `allow`, `deny`, `challenge` or `restrict`, with default deny and deterministic policy precedence. Decisions remained separate from response actions, so approval-required actions were not executed automatically.

Nine requests produced two allow, four deny, two challenge and one restrict decision. Stage 5 passed 14/14 validation checks.

Lesson: a security decision must explain its policy, reasons and evidence.

---

## Stage 6 — Network and Wi-Fi monitoring

Stage 6 added network and wireless detections, access decisions and a connection timeline. It checked addresses, ports, services, connection volume, device identity, Wi-Fi security, access zones and approved exceptions.

Overlapping outcomes use deterministic precedence: `deny`, `restrict`, `challenge`, then `allow`. MAC reuse remains an investigation indicator, not a device identity.

A rule-name error, unclear overlap handling and an incorrect response mapping were corrected before validation. Thirty-four events produced 18 alerts and 34 decisions. Repeated monitoring created no duplicate records. Stage 6 passed 15/15 validation checks.

Lesson: preserve every matching rule while selecting one explainable final decision.

---

## Stage 7 — Endpoint monitoring

Stage 7 evaluated endpoint health, compliance, processes, parent-child relationships, command activity, persistence indicators, hashes and crash patterns. Three crashes or restarts within eight minutes formed the agreed pattern.

Critical alerts were consolidated into one device-level simulated-isolation request. Approval required the existing RBAC and ACL controls and changed only the project record.

Twenty-six events produced 26 alerts across 13 detection types. One approved simulated isolation preserved all 10 supporting Critical alert keys. Approved administrative and testing activity created no false alerts. Stage 7 passed 14/14 validation checks.

Separate isolation requests were consolidated by device, and stored approval status was corrected so output reflected the database record.

Lesson: detection, approval and isolation must remain separate.

---

## Stage 8 — Vulnerability and application-security findings

Stage 8 added controlled vulnerability findings linked to authoritative asset `AST-WEB-001`. It preserved severity, confidence, exploitability, exposure, asset criticality, remediation history and verification evidence.

The priority model uses severity, exploitability, asset criticality, exposed-service context and confidence. A vulnerability alone does not create an incident. Approved testing remains evidence, not a finding.

The original risk evidence was initially replaced by later verification data. The remediation logic was corrected to preserve the original evidence. A repeated run also displayed rebuilt `Open` state instead of the stored False Positive state; the runner was corrected to display saved state.

Sixteen events produced seven findings. Final states were one Open, two Planned, three Verified and one False Positive. Stage 8 passed 16/16 validation checks.

Lesson: remediation and review add history; they must not rewrite the original finding.

---

## Stage 9 — Continuous monitoring and risk scoring

Stage 9 introduced scheduled assessment across existing security sources using a deterministic 15-minute interval.

The risk engine maps evidence to users, devices, assets and incidents. It combines severity, confidence, asset criticality, independent-source agreement, validated exceptions and time decay. Risk supports decisions but never replaces original evidence.

Unknown asset criticality was found in three mappings. It was deliberately assigned zero points rather than being treated as Low. Repeated threshold alerts retain occurrence count, evidence, cooldown reason and expiry.

The engine assessed 171 evidence mappings and scored 20 entities. Four High-risk alerts were created. Seven monitored components reported healthy status. A repeated cycle suppressed the same four alerts during cooldown. Stage 9 passed 20/20 validation checks.

Lesson: risk must remain explainable, evidence-backed and honest about unknown context.

---

## Stage 10 — XDR-style correlation

Stage 10 correlated identity, access-policy, network, endpoint, application and vulnerability evidence.

Records use ordered primary anchors such as device, asset, user, IP address, hostname, file hash and process. MAC address, location and detection type remain supporting context. Explicit exploitation links can join directly related evidence. Repeated source events are scored once.

The first implementation used unrestricted transitive grouping and incorrectly mixed device chains. It was corrected to use one ordered primary anchor per record while preserving explicit exploitation links.

The corrected result produced 10 candidate groups, three incidents, 65 evidence links, 10 IoCs and three MAC supporting observables. Unexploited vulnerabilities remained context. Repeated correlation created no duplicate incidents, links or indicators. Stage 10 passed 20/20 validation checks.

Lesson: correlation must explain both joined evidence and evidence kept separate.

---

## Stage 11 — Incident management and evidence

Stage 11 converted the three Stage 10 XDR incidents into managed incidents with unique IDs, ownership, lifecycle state, evidence, decisions, approvals, timelines, IoCs, behaviours, ATT&CK references, vulnerability links and reports.

The managed lifecycle is:

`New → Triaged → Investigating → Contained → Eradicated → Recovered → Closed`

Containment, eradication and recovery are recorded only when those actions genuinely occur. False-positive closure is allowed only from New, Triaged or Investigating with authorised investigation permission.

The implementation preserved 65 evidence links with SHA-256 hashes, 10 IoCs, 31 behaviours, 12 ATT&CK references and six vulnerability links. One vulnerability link records successful exploitation; the remaining links are context-only.

One incident was assigned to `analyst01` and progressed from New to Triaged to Investigating. An unauthorised viewer action was rejected and audited. No unperformed response action was recorded.

A foreign-key mismatch in the vulnerability link table was corrected by referencing the unique finding key. The integrity validator and lifecycle validator were also corrected after testing exposed overly strict checks.

Each incident has a duplicate-safe JSON report and readable text report with verified hashes. Stage 11 validation passed, including SQLite integrity, evidence integrity, RBAC, lifecycle and audit checks.

Lesson: an incident status is not proof that response actions occurred. Evidence, permission and verification must support every lifecycle change.

---

## Next improvement

Stages 9, 10 and 11 are complete and validated.

The next controlled expansion is approval-controlled containment and response. It will extend the existing ACL while preserving evidence before disruptive actions, requiring approval, preventing self-approval, denying undefined actions, recording every outcome and supporting safe rollback where applicable.

The working process remains:

1. Confirm scope.
2. Reuse existing controls.
3. Build only the required capability.
4. Test real output and stored evidence.
5. Record meaningful problems and decisions.
6. Correct genuine failures.
7. Run focused tests and full regression.
8. Update only the relevant documentation.
9. Sign off after final validation.
