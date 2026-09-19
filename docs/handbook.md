# NetShield Enterprise Upgrade Handbook

## 1. Welcome

This handbook is a simple learning guide to Phase 3A V2 of my NetShield project.

It is for someone who wants to understand the engineering journey without reading every script, database field or validation rule. The README gives the project summary. The workflow explains how the stages were developed. The security logic explains the main decisions. The notes keep detailed observations and corrections.

---

## 2. Engineering Goals

The goal was to extend the original NetShield Phase 3 Automation project into a controlled enterprise-security simulation.

The project needed to:

- preserve existing security controls
- use known users, devices, assets and services
- process realistic simulated security events
- keep original evidence available
- produce explainable alerts and decisions
- apply RBAC and approval controls
- remain local and simulated
- support repeatable testing and validation
- record meaningful engineering lessons

Microsoft security products and XDR concepts were used as design references only. No production service or real response action was used.

NetShield is my project and part of my engineering journey. It was designed, built, configured, tested, validated, improved and documented as one connected body of work.

---

## 3. Engineering Principles

The project followed these principles:

1. Reuse existing controls before adding new ones.
2. Build one controlled capability at a time.
3. Preserve original evidence after later decisions.
4. Keep detection separate from response.
5. Enforce least privilege through RBAC and the automation ACL.
6. Treat unknown context as unknown.
7. Make repeated runs duplicate-safe.
8. Record failures and correct the underlying problem.
9. Validate stored data and displayed output.
10. Keep all actions inside the sandbox boundary.
11. Update documentation from real project evidence.
12. Keep meaningful changes in Git history.

The working cycle was:

`Build → Test → Review → Correct → Revalidate → Document`

---

## 4. What Was Built

### Enterprise foundation and data pipeline

The project added simulated enterprise users, devices, applications and services. It also added retention rules, sensitive-field masking, JSONL validation, UTC normalisation, raw-event preservation, duplicate protection and malformed-event quarantine.

### Device and asset identity

The device component checks registration, ownership, compliance, stale status and asset relationships. Device and asset identifiers are stronger evidence than MAC addresses.

### Identity and access monitoring

Identity monitoring evaluates authentication and identity-risk patterns. The access-policy engine combines identity, device, application, network, location, MFA and risk evidence.

### Network and Wi-Fi monitoring

Network monitoring evaluates addresses, ports, services, connection patterns, Wi-Fi security, access zones and device context. Each event receives one explainable access decision.

### Endpoint monitoring

Endpoint monitoring evaluates device health, processes, command activity, persistence indicators, file hashes and crash patterns. Critical alerts can create one simulated isolation request per device.

### Vulnerability management

Vulnerability management stores asset-linked findings, priority scores, remediation history, verification evidence and authorised false-positive reviews. Approved testing remains evidence and does not automatically become a finding.

### Continuous monitoring

The risk engine assesses users, devices, assets and incidents on a scheduled interval. It uses severity, confidence, criticality, agreement, exceptions and time decay without replacing source evidence.

### Cross-source correlation

The correlation engine combines related identity, access, network, endpoint, application and vulnerability evidence. It keeps unrelated device chains separate, extracts IoCs and preserves behaviours and ATT&CK context.

### Incident management

Incident management stores unique IDs, ownership, lifecycle state, evidence links, hashes, decisions, approvals, timelines, IoCs, behaviours, ATT&CK references, vulnerability links and JSON or readable reports.

---

## 5. Testing and Validation

Testing followed the project’s normal engineering cycle:

- stage-specific validation was run for completed components
- focused tests checked each new capability
- full regression was run after major changes
- SQLite integrity and audit checks were performed
- repeated runs checked duplicate-safe behaviour
- permission and approval boundaries were tested
- original evidence was checked after later processing

The validation process confirmed that earlier components remained available while later stages were added.

---

## 6. Major Engineering Decisions

### Reuse instead of redesign

Existing RBAC, ACL, logging and SQLite controls were extended rather than replaced. This preserved compatibility with the earlier Phase 3 project.

### Evidence before interpretation

Alerts, findings, risk scores and incidents refer back to original records. Later scoring or remediation does not erase earlier evidence.

### Separate detection and response

A detected risk can recommend an action, but the ACL and approval rules still decide whether that action may occur.

### Deterministic decisions

Policy precedence, risk thresholds, alert cooldown and correlation anchors are configured so repeated runs produce explainable results.

### Strong identity anchors

Device ID, asset ID, username, IP address and other approved anchors are used in a controlled order. MAC addresses remain supporting evidence.

### Vulnerability context is not automatically an attack

A finding contributes context. An incident relationship requires activity or exploitation evidence.

### Local simulation

Network restrictions, endpoint isolation and response actions remain simulated. The project does not change real connectivity, accounts, processes or files.

### Lifecycle must reflect reality

Containment, eradication and recovery are recorded only when those actions genuinely occur. A status value alone is not proof of a completed action.

---

## 7. Improvements Made

The project was improved through real validation findings:

- the missing CYOD inventory record was corrected
- complete compound source names were preserved
- malformed-event counting became duplicate-safe
- device classification was restricted to authoritative context
- identity event times were aligned with the configured baseline
- network decision precedence was made deterministic
- an incorrect network response mapping was corrected
- endpoint isolation requests were consolidated by device
- stored approval status replaced recalculated display output
- remediation verification stopped replacing original risk evidence
- stored False Positive state was preserved across repeated runs
- unknown asset criticality was assigned zero points
- alert cooldown state was recorded explicitly
- unrestricted correlation grouping was replaced with ordered anchors
- vulnerability foreign-key references were corrected
- integrity and lifecycle validators were corrected
- report generation was made repeatable and hash-stable

These changes came from test failures, output comparisons, database checks and repeated execution.

---

## 8. Lessons Learned

The project taught me that:

- security evidence must remain available after interpretation
- unknown values should not be silently assigned convenient meanings
- a finding is not automatically an incident
- a detection is not automatically a response
- approval must be checked separately from detection
- repeated execution is essential for finding state and duplicate problems
- output must reflect stored investigation state
- a shared field should not create an uncontrolled correlation bridge
- one device may have many alerts but still need one device-level action
- lifecycle states must be supported by real actions and evidence
- simple, deterministic rules are easier to investigate and explain
- documentation is strongest when it records genuine problems and corrections

The most useful engineering work often came from correcting an assumption rather than adding another feature.

---

## 9. Future Expansion

The next planned expansion is approval-controlled containment and response.

It will extend the existing ACL for simulated actions such as IP blocking, account restriction, session revocation, device quarantine, endpoint isolation, process suspension, file quarantine and increased monitoring.

Later work will cover verified eradication, recovery, retesting, post-incident review and measurable improvement.

Future stages must continue to preserve:

- original evidence
- least-privilege permissions
- approval boundaries
- safe rollback
- complete audit history
- simulated-only operation
- repeatable validation

The completed Phase 3A V2 project provides a controlled foundation for later cloud-security and security-automation work.
