# NetShield Enterprise Upgrade Handbook

## Welcome

This handbook explains the engineering journey behind Phase 3A V2 — NetShield Enterprise Upgrade.

It is for someone who wants to understand the project without reading every script, configuration file or database table.

The README presents the completed components, outputs and test results. This handbook focuses on the goals, important decisions, improvements and lessons from the project.

NetShield Enterprise Upgrade extends the completed Phase 3 Automation project. It remains a local Python and SQLite project inside an Ubuntu VirtualBox sandbox.

Enterprise users, devices, applications and security events are simulated. Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design references only. No Microsoft services or real enterprise response actions are used.

The completed upgrade currently covers Stages 1–8.

---

## Engineering Goals

The goal is to understand how identity, device, network, endpoint and vulnerability evidence can support security investigation, access decisions and remediation.

I build each component gradually, check its behaviour and confirm that earlier components still work.

The work aims to:

- Reuse the completed Phase 3 foundation.
- Add simulated enterprise context.
- Process several types of security data reliably.
- Improve device identity and inventory consistency.
- Detect identity, network and endpoint risks.
- Make access decisions that retain their reasons.
- Prioritise vulnerability and application-security findings.
- Preserve remediation and investigation history.
- Apply default deny and least privilege.
- Keep disruptive responses behind approval controls.
- Preserve original evidence.
- Handle repeated runs without duplicating accepted records.

The project does not copy a commercial security platform. It applies security concepts locally so I can understand how the evidence and decisions fit together.

---

## Engineering Principles

### Build incrementally

I verify the existing project, add the next component, test it independently and then run the wider regression.

This helps identify which change caused a failure.

### Preserve compatibility

The upgrade extends NetShield rather than replacing its roles, database or response controls.

Existing components remain operational while new capabilities are added.

### Use genuine evidence

Controlled events exercise normal, suspicious, malformed, duplicate, remediation and exception cases.

Recorded results come from actual project runs. Simulated evidence is identified as simulated rather than presented as live activity.

### Fix the responsible problem

When testing finds a failure, I check whether it belongs to the implementation, configuration, test data or validator.

A security rule should not be weakened simply to make a test pass.

### Keep decisions explainable

Alerts, access decisions and vulnerability findings retain their supporting events, reasons and relevant context.

The result should explain why it was produced.

### Separate detection from response

A serious alert or vulnerability does not give the project permission to perform a disruptive action.

RBAC controls who may act, and the automation ACL controls the permitted response.

### Preserve original risk

Remediation changes the current state of a finding.

It should not erase the original severity, exploitability or evidence that caused the finding to be prioritised.

### Test repeated behaviour

Initialisation, imports, detections and storage are repeated.

These checks confirm that accepted events, alerts, findings, timelines, reviews and response records are not duplicated or reset unexpectedly.

### Keep documentation and Git history aligned

Implementation, tests and documentation are reviewed before committing completed work.

Runtime databases and logs remain outside Git. Controlled test inputs and fixtures are tracked where needed.

---

## What Was Built

### Enterprise foundation

Stage 1 added simulated enterprise users, devices, applications and services.

It reused the existing RBAC, automation ACL, SQLite database, logging, evidence controls and sandbox boundaries. Retention settings and sensitive-field masking were also added.

### Extended security data pipeline

Stage 2 added enterprise-style event sources.

The pipeline validates records, normalises timestamps to UTC, preserves original events and prevents duplicate accepted events. Malformed records retain their evidence and rejection reason.

### Enterprise asset and device identity

Stage 3 strengthened the device inventory and distinguished unknown, unregistered, stale and mismatched device findings.

Device ID and asset ID are the main references. MAC addresses remain supporting evidence.

### Identity monitoring and investigation

Stage 4 added wider sign-in and identity-risk detection, including failure patterns, unusual activity, MFA problems and privilege changes.

It also supports authorised alert review, investigation notes and false-positive classification.

### Zero Trust access policy

Stage 5 evaluates identity, role, device, application, location, network, MFA and risk evidence.

It produces Allow, Deny, Challenge or Restrict decisions with supporting reasons and the winning policy.

### Network, Wi-Fi and access monitoring

Stage 6 detects controlled network and wireless problems, including suspicious addresses, connection patterns, restricted services, unknown devices and wireless-policy violations.

It stores network-access decisions, a connection timeline and false-positive reviews.

### Endpoint monitoring and investigation

Stage 7 added endpoint health, compliance and risk checks alongside process, command, CPU, persistence and file-hash monitoring.

It stores an endpoint activity timeline, considers approved administrative and testing exceptions, and supports false-positive investigation.

Critical alerts for the same device are consolidated into a simulated isolation request. Authorised approval changes only the project record; it does not disconnect the device or change its network state.

### Vulnerability and application-security findings

Stage 8 added controlled vulnerability and application-security findings linked to the registered sandbox web application.

It covers configuration, dependency, package, exposed-service and SQL injection evidence.

Findings retain severity, confidence, exploitability, asset criticality, priority and remediation status.

The stage also supports duplicate protection, remediation verification, false-positive review and evidence-based alert and incident links.

A vulnerability does not automatically become an incident.

### Validation

The Stage 8 tests, V2 Stage 1–8 validators and complete unit-test suite passed.

The original Phase 3 full-project validator also passed. Database integrity checks found no integrity or foreign-key violations.

Detailed outputs and totals belong in the README and engineering notes.

---

## Major Engineering Decisions

### Extend one foundation

I reused the original database, roles and response controls.

Creating separate versions could leave different parts of the project making conflicting decisions.

### Keep default deny

Missing permissions or insufficient access evidence should not silently produce an Allow decision.

Access must satisfy the configured requirements.

### Separate severity from confidence

Severity describes possible impact. Confidence describes how strongly the evidence supports a finding.

A high-impact possibility and a well-supported finding are not the same thing.

### Combine device evidence

A MAC address can be changed or reused.

Device and asset identifiers provide the main references, supported by user, hostname, registration, compliance and network context.

### Preserve rejected evidence

Malformed events remain outside accepted-event storage, but their original content is retained.

This allows the reason for rejection to be investigated.

### Support existing databases

Changing the tracked schema prepares a new database but does not upgrade a working database.

Repeatable migrations add the required structures while preserving earlier records.

### Make policy conflicts predictable

Identity access policies use explicit priority and restrictive tie-breaking. Network decisions use a configured decision order.

The same evidence should not produce a different outcome because rules were listed in a different order.

### Keep simulations separate from real actions

Wireless scenarios use controlled logs. Endpoint isolation records and vulnerability-testing evidence are also simulated.

Approval does not stop traffic, disable Wi-Fi, terminate processes or change the operating system.

### Consolidate isolation requests

Several Critical alerts can concern the same device.

One consolidated request avoids repeated requests while retaining the supporting Critical alert keys.

### Use authoritative asset context

A vulnerability finding must belong to a registered asset.

This prevents findings from being stored against unknown or invented systems.

### Keep vulnerabilities separate from incidents

A vulnerability shows that a weakness may exist.

An incident link requires supporting activity or exploitation evidence. Automatic incident creation remains disabled.

### Preserve original risk during remediation

A Verified finding still needs its original risk evidence.

Remediation status and verification history are stored without replacing the severity or exploitability that caused the finding to be investigated.

### Preserve review history

Closing an alert or classifying a finding changes its investigation state, not its original evidence.

Classifications, notes, reviewer details and audit records remain available.

---

## Improvements Made

### Aligned enterprise context and inventory

A registered device appeared in enterprise context but was missing from the authoritative CYOD inventory.

The inventory was corrected and a consistency check was added.

### Recognised complete source names

The first filename logic shortened compound source names.

It was corrected to preserve supported names such as `identity_risk`.

### Improved migration and validation boundaries

Repeatable migrations were added for existing databases.

Validators were also corrected to allow approved new sources and check their intended evidence rather than unrelated later-stage records.

### Counted distinct malformed evidence

Repeated imports could record the same malformed input more than once.

Validation was changed to distinguish repeated rejection records from distinct malformed inputs.

### Corrected device classification

Non-device assets initially entered device evaluation. The detector was restricted to relevant device context.

A known but unregistered device was also separated from a completely unknown device.

### Aligned controlled timestamps

Some normal identity events fell outside the configured normal access hours.

Their timestamps were corrected, while deliberate abnormal-time evidence was retained.

### Clarified network decisions and responses

Stage 6 gained a fixed decision order for conflicting conditions.

Its Restrict outcome was mapped to the existing network-related firewall action, which remained approval-required.

### Completed damaged source files

The Stage 7 generator contained a duplicated function name, and an endpoint-engine paste ended inside a function signature.

The files were corrected and syntax-checked before execution continued.

### Reduced repeated isolation requests

The first endpoint run created a request for each Critical alert.

The requests were consolidated by device while preserving their supporting alert keys. Repeated runs then retained one stored request.

### Used the established isolation status

An approval attempt used a status that the database did not permit.

The implementation was corrected to use the existing `simulated_isolated` status rather than changing the schema unnecessarily.

### Reported stored response state

The endpoint runner initially printed a newly calculated pending status even after approval was stored.

It was changed to display the actual stored isolation record. Repeated runs preserved both approval and closed alert reviews.

### Preserved vulnerability risk after verification

Stage 8 initially allowed later verification events to replace the original finding risk.

The logic was corrected so remediation updates the current status while the original severity, exploitability and exploitation evidence remain available.

### Reported the stored finding state

After a false-positive review, the vulnerability runner initially displayed a newly calculated Open status.

It was corrected to reload the stored finding so repeated output preserved the completed False Positive review.

---

## Lessons Learned

### Context must agree

User, device, inventory, application, network and vulnerability records are connected.

Inconsistent context can produce a valid-looking but incorrect result.

### Test data needs careful design

Timestamps, locations, process names and risk values must match the scenario being tested.

Otherwise, the detector may correctly identify a problem that the test did not intend to create.

### One event can support several findings

A process event can match suspicious-process, approval and parent-child rules at the same time.

These findings are not automatically duplicates. Their separate reasons should remain available.

### Several alerts do not always need several actions

Related Critical alerts can support one device-level isolation request.

Consolidation should retain evidence rather than hide it.

### Check the full schema

A list of column names does not show every database restriction.

The isolation-status failure showed why the complete table definition must be checked before introducing a new value.

### Printed output must match stored state

A calculated result is not necessarily the current database record.

Operational output should reflect stored approval, investigation and remediation states.

### Exceptions need specific evidence

Approved administrative or testing activity should match its intended exception.

An approved process, compliant device or authorised test alone does not prove that every activity is harmless.

### False-positive review needs reasoning

A detection or version match can be technically correct without proving malicious activity or a genuine vulnerability.

Review should use the available evidence, record the conclusion and preserve the original finding.

### Remediation does not rewrite history

Verification describes the current remediation result.

It should not remove the earlier evidence that explains why the finding mattered.

### Vulnerabilities and incidents are different

A weakness can support prevention and remediation work without becoming an incident.

Activity or exploitation evidence is needed before creating an incident relationship.

### Repeated runs test more than duplicates

They also check whether approval, classifications, remediation states and investigation notes survive later processing.

### Simulation limits must stay clear

Controlled isolation, penetration testing and exploitation evidence are project records, not real external actions.

The project must describe what it recorded and avoid claiming actions it did not perform.

---

## Future Expansion

Stages 1–8 are complete and validated.

The completed identity, access, network, endpoint and vulnerability components provide evidence that later project work can reuse.

Any future expansion should continue to preserve:

- Original evidence
- Authoritative asset and device context
- Least privilege
- Default deny
- Approval boundaries
- Investigation and remediation history
- Duplicate protection
- Compatibility with completed components

Later stages will be handled separately and only within their agreed scope.
