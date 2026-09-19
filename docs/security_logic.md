# NetShield Security Logic

## Purpose

This document explains the main security decisions in Phase 3A V2 and why they exist. It focuses on logic and boundaries rather than repeating workflow steps, commands or detailed findings.

NetShield is my project and part of my engineering journey. Its security logic, configuration, testing, validation and improvements are documented here without claiming personal source-code authorship.

## Project boundary

The system runs in the controlled Ubuntu sandbox with Python, SQLite and simulated enterprise data.

Microsoft security products and XDR concepts are design references only. Real production accounts, external targets, network changes and automatic response actions remain disabled.

---

## Foundation and data ingestion

### Authoritative context

Users, devices, applications, services and assets must come from registered project context. Unknown context is not silently accepted as trusted.

### RBAC and ACL

RBAC controls which roles may investigate, review, approve or manage records. The automation ACL controls response actions separately. Undefined actions are denied.

### Event validation

Events must contain the required fields, valid data types, recognised sources and UTC timestamps. Raw events are preserved, accepted events are normalised, malformed records are quarantined and duplicates are ignored.

### Why this exists

Security decisions need traceable identity, valid evidence and repeatable storage. The original Phase 3 controls remain available while V2 adds enterprise context.

---

## Stage 3 — Device identity

Device evaluation uses device ID, asset ID, registration, ownership, compliance and last-seen evidence.

MAC addresses are supporting evidence only. They cannot identify a device by themselves.

Unknown, unregistered, stale and mismatched states remain separate so that an investigation can distinguish missing inventory from suspicious activity.

---

## Stage 4 — Identity monitoring

Identity detections group related authentication events by user, source address and time window.

The logic considers:

- repeated failures and password spraying
- successful sign-in after failures
- impossible travel and unusual location
- new-device sign-in
- abnormal access time
- MFA failure or fatigue
- privilege changes
- dormant-account activity
- service-account interactive login
- multiple accounts from one source
- risky sign-in and user-risk activity

Approved VPN and controlled-testing exceptions are narrow. They suppress only the expected condition and remain recorded as evidence.

Deterministic alert keys prevent repeated detections from creating duplicate alerts.

---

## Stage 5 — Access policy

Access decisions verify identity, active role, required permission, device state, application sensitivity, asset criticality, location, network, sign-in risk, user risk and MFA evidence.

The engine returns:

- `allow` when required evidence is satisfied
- `deny` when access is not permitted
- `challenge` when stronger verification is required
- `restrict` when controlled restriction should be considered

The default is `deny`.

When rules conflict, lower priority numbers win. Equal-priority outcomes use the more restrictive order:

`deny → restrict → challenge → allow`

A policy decision does not execute a response action. Any response still passes through the automation ACL and approval boundary.

---

## Stage 6 — Network and Wi-Fi

Network logic checks IP reputation, approved networks, ports, services, connection volume, access time, device identity, Wi-Fi security, access points and network zones.

Overlapping outcomes use:

`deny → restrict → challenge → allow`

The engine stores every matching rule and reason code before selecting one final decision.

MAC reuse can raise an investigation indicator, but it cannot override device identity evidence.

Network restriction remains simulated and approval-controlled. The project does not change the real Ubuntu firewall or wireless state.

---

## Stage 7 — Endpoint monitoring

Endpoint logic evaluates health, compliance, risk, process approval, ownership, parent-child relationships, command activity, persistence indicators, file hashes and crash patterns.

Three crashes or restarts within eight minutes form the configured pattern.

Critical alerts are consolidated into one simulated isolation request per device. Approval changes the project record only; it does not disable Wi-Fi, stop traffic, terminate processes or change the operating system.

A crash or suspicious process is evidence for investigation, not automatic proof of malicious activity.

---

## Stage 8 — Vulnerability management

A finding requires an authoritative asset and preserved supporting evidence.

Priority uses:

- severity
- exploitability
- asset criticality
- exposed-service context
- confidence

Remediation changes status and adds verification history. It does not erase the original severity, exploitability or exploitation evidence.

Approved testing remains evidence and does not become a vulnerability by itself.

A finding links to an alert or incident only when supporting activity or exploitation evidence exists. A vulnerability alone does not create an incident.

False-positive classification requires an authorised investigator, review notes and an audit record.

---

## Stage 9 — Continuous risk scoring

Risk scoring combines existing evidence for users, devices, assets and incidents.

The score uses severity, confidence, asset criticality, independent-source independent-source agreement, validated exceptions and time decay.

Risk scores support investigation decisions but never replace the source alerts, findings, decisions or events.

Independent sources add configured agreement points. Repeated records from the same source do not receive the same benefit again.

Completed false-positive reviews and verified activity can reduce risk. Unknown asset criticality contributes zero points rather than being treated as Low.

Threshold alerts use cooldown and suppression records to reduce repeated noise without deleting evidence.

Detection health records processed data, failures and last-successful-run values. A risk score is not considered reliable if required pipeline components are failing.

---

## Stage 10 — Cross-source correlation

Correlation uses ordered primary anchors such as:

- device ID
- asset ID
- username
- IP address
- hostname
- process name
- file hash

MAC address, location and detection type provide supporting context only.

Records are grouped within the configured time window. A shared username or address cannot create an unrestricted transitive bridge between separate device chains.

Explicit exploitation links may join the specifically named evidence across normal grouping boundaries.

Repeated detections from one source event are preserved but scored once. Independent source agreement increases confidence. Validated exceptions and verified activity reduce confidence without deleting evidence.

Vulnerability findings remain context unless activity or explicit exploitation evidence supports an incident.

IoCs are stored separately from behaviours. IP addresses, file hashes, hostnames and suspicious process values may be IoCs when supported by evidence. A detection label remains a behaviour.

---

## Stage 11 — Incident management

Managed incidents preserve:

- unique incident ID
- source incident key
- title and detection sources
- severity and confidence
- risk provenance
- identity, device, asset and network context
- owner and status
- investigation notes
- analyst decisions
- closure reason
- IoCs and behaviours
- ATT&CK references
- evidence links and SHA-256 hashes
- timeline and approval records
- vulnerability relationships
- JSON and readable reports

The controlled lifecycle is:

`New → Triaged → Investigating → Contained → Eradicated → Recovered → Closed`

False-positive closure is allowed only from `New`, `Triaged` or `Investigating` and requires investigation permission.

Containment, eradication and recovery states are used only when those actions genuinely occurred. An incident does not automatically prove that a response action was performed.

Reports are hash-recorded and duplicate-safe. Repeated generation must produce the same evidence-backed result.

---

## Evidence and audit logic

Original evidence remains available after scoring, correlation, remediation, review or incident management.

Every meaningful decision records its actor, reason, evidence reference and result. Denied actions are audited as denied; they are not represented as successful actions.

SQLite integrity, foreign-key integrity, duplicate protection and evidence hashes are checked during validation.

---

## Testing and validation

Each implemented stage has focused tests, validation checks and repeat-run checks. The project also uses regression validation to confirm that earlier components remain operational.

The main validation themes are:

- safe sandbox boundaries
- authoritative asset and device context
- RBAC and ACL enforcement
- evidence preservation
- duplicate-safe storage
- deterministic decisions
- lifecycle integrity
- audit completeness
- no unauthorised or automatic real-world response

---

## Engineering lessons

The project repeatedly showed that:

- evidence must remain separate from interpretation
- unknown values must remain unknown
- detection and response must remain separate
- approval must be enforced by the ACL
- repeated runs must preserve stored investigation state
- independent evidence should increase confidence only once
- a vulnerability is not automatically an attack
- correlation must explain both joined and separated activity
- lifecycle status must reflect actions that genuinely occurred

Future stages should extend these controls without replacing the original evidence model.
