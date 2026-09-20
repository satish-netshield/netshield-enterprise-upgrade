# NetShield Enterprise Upgrade Handbook

## 1. Welcome

This handbook is a simple learning guide to Phase 3A V2 of my NetShield project.

It is for someone who wants to understand the engineering journey without reading every script, database field or validation rule.

The README gives the main project evidence. The workflow explains how the work progressed. The security logic explains why the controls exist. The notes preserve detailed findings and corrections.

---

## 2. Engineering Goals

The goal was to extend the original NetShield Phase 3 Automation project into a controlled enterprise-security simulation.

The project needed to:

- preserve the existing security foundation
- use known users, devices, assets and services
- process realistic simulated security events
- keep original evidence available
- produce explainable alerts and decisions
- enforce RBAC, ACL and approval controls
- support investigation and controlled response
- verify containment, eradication and recovery
- remain local, safe and repeatable
- support later cloud-security expansion

Microsoft security platforms and XDR were used as design concepts only. No Microsoft service, production account, external target or real response action was required.

NetShield is my project. It was designed, built, configured, tested, validated, improved and documented as part of my engineering journey.

---

## 3. Engineering Principles

The project followed these principles:

1. Understand the existing design before changing it.
2. Reuse established controls instead of creating unnecessary replacements.
3. Build one controlled capability at a time.
4. Preserve original evidence after later decisions.
5. Keep detection, approval and execution separate.
6. Enforce least privilege through RBAC and the automation ACL.
7. Treat unknown context as unknown.
8. Make repeated runs duplicate-safe.
9. Record genuine failures and correct their cause.
10. Validate stored data, displayed output and complete workflows.
11. Keep every response inside the sandbox.
12. Keep documentation aligned with actual behaviour.
13. Maintain meaningful Git history.

The working cycle was:

`Build → Test → Review → Correct → Revalidate → Document`

---

## 4. What Was Built

### Enterprise foundation and data pipeline

The project added simulated enterprise users, devices, applications and services. It also added retention rules, sensitive-field masking, event validation, UTC normalisation, raw-event preservation, duplicate protection and malformed-event quarantine.

### Device, identity and access controls

Device checks use authoritative inventory and asset context. Identity monitoring evaluates authentication and risk patterns. Access decisions combine identity, role, device, application, network, MFA and risk evidence.

### Network and endpoint monitoring

Network monitoring evaluates addresses, services, traffic patterns, Wi-Fi security and access zones. Endpoint monitoring evaluates health, processes, commands, persistence indicators, hashes and crash patterns.

### Vulnerability management

Vulnerability findings retain asset context, priority, remediation history, verification evidence and authorised false-positive reviews.

### Continuous monitoring and risk

Scheduled monitoring combines existing evidence for users, devices, assets and incidents. Risk scores remain explainable and do not replace source evidence.

### XDR-style correlation

Cross-source correlation joins related identity, access, network, endpoint, application and vulnerability activity while keeping unrelated device chains separate.

### Incident management

Managed incidents include unique IDs, ownership, lifecycle state, preserved evidence, decisions, timelines, IoCs, behaviours, ATT&CK references, vulnerability links and reports.

### Controlled containment

Containment uses existing RBAC and ACL controls. Evidence is preserved before action, requesters cannot self-approve or self-execute disruptive requests, and safe rollback is supported where applicable.

### Eradication and recovery

Eradication and recovery cover simulated account, device, Wi-Fi, file, process, persistence, SQL and vulnerability work. Recovery requires successful retesting and post-recovery monitoring.

### Full enterprise validation

The complete upgrade can rebuild its schema in a temporary database, check its components, run the regression suite and validators, inspect integrated evidence and confirm that validation does not change the live database.

---

## 5. Testing and Validation

Testing was completed incrementally and across the complete project.

The project used:

- focused tests for individual capabilities
- stage-specific validators
- full regression testing
- clean-state schema reconstruction
- SQLite integrity and foreign-key checks
- evidence-hash verification
- permission and approval rejection tests
- duplicate and repeated-run checks
- failed-action and rollback checks
- complete incident-lifecycle validation
- final report-state comparison

Stage 14 passed 56/56 checks repeatedly.

Final validation evidence included:

- 279 regression tests passed
- all 13 earlier V2 validators passed
- 52 tables and 211 named indexes rebuilt
- 38 source modules imported
- 176 audit records checked
- 73 incident and recovery evidence records retained
- the live database hash remained unchanged
- Stage 11 reports matched their current incident records

The final report correction was followed by another full regression and affected-stage validation.

---

## 6. Major Engineering Decisions

### Reuse instead of redesign

Existing RBAC, ACL, logging and SQLite controls were extended rather than replaced. This preserved continuity with the original Phase 3 project.

### Evidence before interpretation

Alerts, findings, scores, incidents and actions refer back to preserved evidence. Later processing does not erase the original record.

### Default deny

Unknown permissions and undefined actions are denied. Access is granted only when the required evidence and role are present.

### Detection is not response

A detection can recommend an action, but it cannot bypass the ACL, approval or separation-of-duty controls.

### Approval is not execution

Approval records permission to continue. Execution records whether the simulated action succeeded or failed.

### Strong identity anchors

Device ID, asset ID, username and other controlled identifiers remain stronger evidence than MAC addresses or general context.

### Vulnerability context is not automatically an attack

A finding contributes context. An incident relationship requires supporting activity or exploitation evidence.

### Recovery requires verification

An incident cannot be closed only because response actions were recorded. The original threat and vulnerability must be retested successfully.

### Integrity and accuracy are separate

A valid hash proves that content has not changed unexpectedly. Current-state comparison is also required to prove that a report remains accurate.

### Local simulation

The project does not change real accounts, devices, files, processes, networks or external services.

### Platform independence

Microsoft security products informed the design, but the implementation remains independent of Microsoft platforms and SDKs.

---

## 7. Improvements Made

Testing and repeated execution produced genuine improvements:

- missing inventory context was corrected
- complete source names were preserved
- malformed-event handling became duplicate-safe
- device classification was limited to authoritative context
- identity test data was aligned with its baseline
- network decisions gained deterministic precedence
- endpoint isolation requests were consolidated by device
- stored approval and review state replaced rebuilt display state
- remediation stopped replacing original evidence
- unknown asset criticality remained unknown
- alert cooldown retained repeated evidence
- correlation stopped joining unrelated device chains
- vulnerability foreign keys were corrected
- incident reports became repeatable and hash-verifiable
- self-approval denial flags were preserved
- earlier lifecycle validation accepted later valid states
- recovery became dependent on successful retesting
- temporary database cleanup was checked after cleanup completed
- final reports were refreshed after genuine lifecycle changes
- report validation gained current-state comparison
- privacy and temporary-file checks were completed

Thresholds remained unchanged because the final evidence did not justify tuning them. Earlier project components were retained because compatibility and regression checks still depended on them.

---

## 8. Lessons Learned

The project taught me that:

- evidence must remain available after interpretation
- unknown values should not be given convenient meanings
- a finding is not automatically an incident
- a detection is not automatically a response
- approval and execution are different events
- requesters must not approve or execute their own disruptive requests
- denied and failed actions must remain visible
- rollback must be safe and explicitly supported
- repeated execution reveals duplicate and stored-state problems
- later stages can expose assumptions in earlier validators
- correlation must explain why evidence was joined
- recovery requires retesting the original problem
- closure requires evidence, verification and authorised review
- validation must not change the evidence being checked
- a matching hash does not prove that content is current
- changes should be supported by evidence rather than assumption

The most useful engineering work often came from correcting an assumption rather than adding another feature.

---

## 9. Future Expansion

Phase 3A V2 provides a tested foundation for later NetShield work.

Future expansion can include:

- cloud-hosted storage and monitoring
- cloud identity and access controls
- serverless event processing
- managed logging and alerting
- cloud-security posture checks
- larger controlled datasets
- broader recovery scenarios
- improved reporting and visualisation
- security-automation integration
- later AI-assisted analysis with clear evidence boundaries

Microsoft platforms may continue to provide useful design comparisons, but future implementation choices should remain explicit and should not create an unnecessary platform dependency.

After Phase 3A V2 sign-off, changes should be limited to genuine defects, security improvements or justified engineering requirements.
