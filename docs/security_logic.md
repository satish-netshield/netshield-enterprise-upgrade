# NetShield Enterprise Upgrade Security Logic

## Purpose

This document explains the main security decisions in Phase 3A V2 and why they exist. It focuses on security logic and boundaries rather than repeating commands, workflow steps or detailed test findings.

NetShield is my project. Its design, configuration, testing, validation and improvement form part of my engineering journey.

## Project boundary

The system runs inside a controlled Ubuntu sandbox using Python, SQLite and simulated enterprise data.

Microsoft security platforms and XDR are design references only. The project does not require Microsoft services, production accounts, external targets or real response actions.

---

## Foundation and data ingestion

### Authoritative context

Users, devices, applications, services and assets must come from registered project context. Unknown context is not silently trusted.

This prevents an event from gaining trust only because it contains a familiar username, address or device value.

### RBAC and ACL

RBAC decides which roles may investigate, review, request, approve or manage records. The automation ACL controls response actions separately.

Undefined actions are denied by default. Permission to investigate does not automatically grant permission to approve or execute a response.

### Event validation

Events require valid fields, data types, source names and UTC timestamps.

Raw events are preserved, valid events are normalised, malformed records are quarantined and duplicate records are ignored.

This keeps evidence traceable while preventing invalid or repeated data from changing the result.

---

## Stage 3 — Device identity

Device evaluation uses device ID, asset ID, registration, ownership, compliance and last-seen evidence.

MAC addresses are supporting evidence because they can be reused or changed. Unknown, unregistered, stale and mismatched devices remain separate investigation states.

Database and web assets are not treated as devices.

---

## Stage 4 — Identity monitoring

Identity detections group related authentication and identity-risk activity by user, source address and time window.

The logic checks failures, password spraying, successful access after failures, location, new devices, access time, MFA, privilege changes, dormant accounts, service accounts and shared source activity.

Approved VPN and controlled-testing exceptions remain narrow and auditable. They suppress only the expected condition and do not delete the original event.

Deterministic alert keys prevent repeated detections from creating duplicate alerts.

---

## Stage 5 — Access policy

Access decisions evaluate identity, active role, permission, device state, application sensitivity, asset criticality, location, network, risk and MFA evidence.

The available outcomes are:

- `allow`
- `deny`
- `challenge`
- `restrict`

The default is `deny`.

When policies conflict, configured priority is applied first. Equal-priority outcomes use the more restrictive order:

`deny → restrict → challenge → allow`

A policy decision does not execute a response. Any later action must still pass the automation ACL and approval controls.

---

## Stage 6 — Network and Wi-Fi

Network logic checks IP reputation, approved networks, ports, services, connection volume, device identity, Wi-Fi security, access points and network zones.

Every matching rule and reason is preserved before one final decision is selected.

MAC reuse can support an investigation but cannot override device identity evidence.

Network restrictions are simulated. The project does not change the real Ubuntu firewall, Wi-Fi configuration or network connection.

---

## Stage 7 — Endpoint monitoring

Endpoint logic evaluates health, compliance, risk, approved processes, process ownership, parent-child relationships, command activity, persistence indicators, file hashes and crash patterns.

Three crashes or restarts within eight minutes form the configured repeated-crash pattern.

Critical alerts can create one consolidated simulated-isolation request per device. Approval changes only the project record.

A suspicious process, crash or hash is evidence for investigation rather than automatic proof of malicious activity.

---

## Stage 8 — Vulnerability management

A vulnerability finding requires authoritative asset context and preserved evidence.

Priority uses:

- severity
- exploitability
- asset criticality
- exposed-service context
- confidence

Remediation adds status and verification history without replacing the original risk evidence.

Approved testing remains evidence and does not become a vulnerability by itself. A vulnerability becomes incident context only when related activity or exploitation evidence exists.

False-positive classification requires authorised review, notes and an audit record.

---

## Stage 9 — Continuous monitoring and risk

Risk scoring combines existing evidence for users, devices, assets and incidents.

The score uses severity, confidence, asset criticality, independent-source agreement, validated exceptions and time decay.

Repeated evidence from one source does not gain independent-source points. Unknown asset criticality contributes zero points instead of being treated as Low.

Threshold alerts use cooldown and suppression records to reduce repeated noise without deleting evidence.

Risk supports investigation decisions but never replaces the original events, alerts, findings or decisions.

---

## Stage 10 — XDR-style correlation

Correlation uses ordered primary anchors such as device ID, asset ID, username, IP address, hostname, process name and file hash.

MAC address, location and detection type remain supporting context.

A shared username or address cannot create an unrestricted bridge between unrelated device chains. Explicit exploitation links may connect only the specifically related evidence.

Repeated detections are preserved but scored once. Independent sources can increase confidence, while validated exceptions and verified activity can reduce it.

IoCs remain separate from behaviours. Detection names describe behaviour; they are not automatically IoCs.

---

## Stage 11 — Incident management

Managed incidents preserve identity, device, asset, network, evidence, ownership, decisions, approvals, timelines, IoCs, behaviours, ATT&CK references, vulnerability links and reports.

The controlled lifecycle is:

`New → Triaged → Investigating → Contained → Eradicated → Recovered → Closed`

False-positive closure is allowed only from `New`, `Triaged` or `Investigating` with investigation permission.

Containment, eradication and recovery states are recorded only when supporting actions genuinely occurred.

Evidence references use SHA-256 hashes. Reports are hash-recorded and duplicate-safe.

A valid report hash proves that report content has not changed unexpectedly. It does not prove that the report still matches the current incident state. Validation therefore compares both report formats with the authoritative incident record.

An incident status does not prove that a response action was performed.

---

## Stage 12 — Containment and response

Stage 12 uses the existing RBAC and automation ACL to control simulated containment.

Every action requires:

- a managed incident
- related evidence
- a configured action
- the correct target type
- an authorised requester
- a responsible actor
- an audit record

Evidence is preserved before the action is considered.

Approval-required actions cannot be approved or executed by their requester. Approval records permission to continue; it does not claim that execution occurred.

The system records requested, approved, denied, successful, failed and rolled-back outcomes separately.

Undefined actions and unauthorised roles fail closed. Failed and denied actions remain visible and cannot be represented as successful.

Rollback is allowed only when the configured action has a safe rollback path. An irreversible action cannot invent one.

All containment remains simulated and does not change real accounts, devices, processes, files, sessions or networks.

---

## Stage 13 — Eradication and recovery

Stage 13 continues only after successful evidence-backed containment.

Eradication actions can address simulated credentials, privileges, compromised accounts, devices, Wi-Fi, rogue access points, malicious files, persistence, processes, vulnerable SQL and vulnerability remediation.

Disruptive eradication and recovery actions are never automatic. Approval-required and manual actions preserve separation between requester, approver and executor.

The incident can move to Eradicated only after at least one successful eradication action.

Recovery can restore accounts, devices, services and access restrictions. Post-recovery monitoring must remain active.

The incident cannot move to Recovered until both conditions are verified:

- the original threat no longer succeeds
- the original vulnerability no longer succeeds

Closure requires a completed post-incident review, recorded lessons, improvement recommendations and an authorised closure decision.

A successful action alone is not proof of recovery. Verification is required.

---

## Stage 14 — Full validation

Stage 14 is validation-only. It cannot perform response actions or change external systems.

The tracked schema is rebuilt in a temporary database. The live evidence database is preserved and is not copied into the temporary environment.

Validation checks:

- Python syntax and source imports
- the complete regression suite
- all earlier V2 validators
- SQLite and foreign-key integrity
- malformed and duplicate handling
- RBAC and ACL enforcement
- evidence hashes
- lifecycle transitions
- denied and failed actions
- containment and rollback
- eradication and recovery
- IoC and behaviour extraction
- audit completeness
- earlier-stage compatibility

The live database SHA-256 hash is compared before and after validation. A changed hash causes validation to fail.

Source imports also confirm that the project does not depend on Microsoft platform SDKs.

---

## Stage 15 — Final assurance

Final revision checks both integrity and accuracy.

Generated reports must:

- match their stored SHA-256 hashes
- match the current authoritative incident state
- retain closure details when an incident is Closed
- remain duplicate-safe after repeated generation

Thresholds are changed only when test evidence supports a change. Passing results alone do not justify making a threshold stricter or weaker.

A component is removed only when it is shown to be obsolete or unused. Earlier Phase 3 components remain because compatibility and regression checks still depend on them.

Privacy review checks for credentials, private keys, tokens, personal paths, email addresses and temporary files. Simulated security values are retained when they form part of controlled project evidence.

Final documentation must describe actual project behaviour and keep Microsoft products labelled as design concepts rather than dependencies.

---

## Evidence and audit rules

Original evidence remains available after scoring, correlation, review, containment, eradication, recovery or closure.

Every meaningful action records its actor, target, reason, evidence and result.

Denied actions remain denied. Failed actions remain failed. Approval does not prove execution, and execution does not prove recovery.

SQLite integrity, foreign keys, duplicate protection, evidence hashes and report state are checked during validation.

---

## Main security lessons

- Unknown values must remain unknown.
- Evidence must remain separate from interpretation.
- Detection, approval and execution are different events.
- Requesters must not approve or execute their own disruptive requests.
- A vulnerability is not automatically an incident.
- Correlation must explain why evidence was joined or kept separate.
- Risk scores support decisions but do not replace evidence.
- Failed and denied actions must remain visible.
- Recovery requires retesting the original threat and vulnerability.
- Closure requires verified recovery and an authorised review.
- Report integrity and report accuracy must both be validated.
- Final changes require evidence rather than assumption.

After Phase 3A V2 sign-off, changes should be limited to genuine defects, security improvements or justified engineering requirements.
