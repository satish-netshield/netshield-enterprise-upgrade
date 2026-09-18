# NetShield Enterprise Upgrade Handbook

## 1. Welcome

This handbook explains the engineering journey behind Phase 3A V2 — NetShield Enterprise Upgrade.

It is written for someone who wants to understand the project without reading every script, configuration file or database table.

The README presents the completed components and main results. The workflow explains how the components were built. The security logic explains the important security decisions. The notes preserve detailed findings and fixes.

This handbook focuses on what I was trying to achieve, the important choices I made and what I learned while building the upgrade.

NetShield Enterprise Upgrade extends the completed Phase 3 Automation project. It runs locally with Python and SQLite inside an Ubuntu VirtualBox sandbox.

Users, devices, applications and security events are simulated. Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design references only. No Microsoft services or real enterprise response actions are used.

The completed upgrade currently covers Stages 1–10.

---

## 2. Engineering Goals

My main goal was to understand how several types of security evidence can work together instead of being checked separately.

The project was designed to:

- Extend the existing NetShield foundation without replacing it.
- Process identity, access, network, endpoint, application and vulnerability evidence.
- Preserve original evidence and investigation history.
- Apply default deny, least privilege and approval controls.
- Produce explainable alerts, decisions, findings, scores and incidents.
- Handle malformed and duplicate data safely.
- Support repeated monitoring instead of one-time checks.
- Keep unrelated activity separate during correlation.
- Use risk scores to support decisions without replacing evidence.
- Keep all testing controlled and local.

I built each stage separately, tested it and then checked that the earlier stages still worked.

---

## 3. Engineering Principles

### Build incrementally

I added one component at a time and tested it before continuing.

This made failures easier to understand and reduced the chance of damaging completed work.

### Preserve compatibility

The upgrade reused the existing database, RBAC roles, automation ACL, logging and evidence controls.

New capabilities were added without creating a second security model.

### Use genuine project evidence

The documentation uses results produced by the actual scripts, tests and database.

Simulated evidence is described as simulated and is not presented as live security activity.

### Fix the responsible problem

A failure can come from code, configuration, test data, a database constraint or a validator.

I checked which part was responsible before changing the security rule.

### Keep decisions explainable

Alerts, findings, scores and incidents retain their source evidence and reasons.

A reviewer should be able to understand why a result was created.

### Separate detection from response

A serious alert, risk score or incident does not provide permission to perform a disruptive action.

RBAC controls who may act, and the automation ACL controls what kind of response is permitted.

### Test repeated behaviour

Migrations, imports, detections, monitoring and correlation were run more than once.

Repeated runs confirmed that records were not duplicated and completed reviews were not reset.

### Keep documentation and Git aligned

Implementation, testing and documentation are checked before completed work is committed.

Runtime databases, logs and generated outputs remain outside Git.

---

## 4. What Was Built

### Stage 1 — Enterprise foundation

The project gained simulated enterprise users, devices, applications and services.

Retention settings and sensitive-field masking were added while the original Phase 3 controls remained available.

### Stage 2 — Security data pipeline

The pipeline accepts several event formats, validates them, converts timestamps to UTC and preserves the original records.

Malformed records are quarantined, and repeated events are not stored again.

### Stage 3 — Asset and device identity

The device inventory distinguishes unknown, unregistered, stale and mismatched devices.

Device ID and asset ID are the main references. MAC addresses remain supporting evidence.

### Stage 4 — Identity monitoring

The project detects controlled sign-in failures, unusual access, MFA problems, privilege changes and account-risk activity.

Authorised investigators can add notes and classify supported false positives.

### Stage 5 — Access-policy decisions

Access requests are evaluated using identity, role, device, application, network, location, MFA and risk evidence.

The result can be Allow, Deny, Challenge or Restrict, with the winning policy and reasons retained.

### Stage 6 — Network and Wi-Fi monitoring

The project evaluates addresses, ports, services, connection patterns, device context, wireless security and network zones.

It stores alerts, access decisions and a connection timeline without changing a real firewall or wireless network.

### Stage 7 — Endpoint monitoring

Endpoint health, compliance, process activity, ownership, commands, CPU use, crashes, persistence and file hashes are assessed.

Critical alerts can support one simulated device-isolation request. Approval changes only the project record.

### Stage 8 — Vulnerability findings

Controlled configuration, dependency, package, exposed-service and SQL injection findings are linked to registered assets.

Priority considers severity, confidence, exploitability, exposure and asset criticality.

Remediation, verification and false-positive reviews retain the original finding evidence.

### Stage 9 — Continuous monitoring

Security evidence is reassessed through scheduled 15-minute cycles.

The project calculates user, device, asset and incident risk while considering independent sources, validated exceptions and time-based decay.

Threshold alerts, cooldown periods, component health and last-successful-run information are also recorded.

### Stage 10 — XDR-style correlation

Identity, access, network, endpoint, application and vulnerability evidence is correlated into explainable incidents.

Strong identifiers keep unrelated device chains separate. Vulnerabilities add context but do not become attacks without supporting activity.

IoCs, supporting observables, suspicious behaviours and ATT&CK mappings remain separate parts of the investigation.

### Validation

Each V2 stage passed its focused tests and validator.

The complete regression, original Phase 3 full-project validator and SQLite integrity checks also passed.

Detailed totals and outputs are kept in the README and engineering notes.

---

## 5. Major Engineering Decisions

### Extend one project foundation

I reused the original roles, database and response controls.

This kept later decisions consistent with the completed Phase 3 project.

### Keep default deny

Missing permissions or unverifiable conditions must not silently produce an Allow decision.

### Preserve original evidence

Normalisation, review, remediation, risk scoring and correlation add context without replacing the original event or finding.

### Separate severity from confidence

Severity describes possible impact. Confidence describes how strongly the evidence supports the result.

### Use strong identity anchors

Device and asset identifiers are stronger than shared usernames, locations or MAC addresses.

Supporting context can strengthen an investigation but should not merge unrelated activity.

### Keep vulnerabilities separate from attacks

A vulnerability is a prevention and remediation concern.

It supports an incident only when activity or explicit exploitation evidence connects it to the investigation.

### Increase risk through independent agreement

Evidence from independent sources can strengthen a risk score or incident.

Repeated detections from one source event must not inflate the result.

### Reduce risk only with validated evidence

Approved activity and completed false-positive reviews can reduce risk or confidence.

Unreviewed evidence does not receive an exception reduction.

### Keep responses controlled

Isolation, account restriction and firewall actions remain simulated or approval-required.

No risk score or correlated incident performs an automatic disruptive response.

### Preserve investigation state

Repeated processing keeps classifications, notes, approvals and remediation history instead of resetting them.

---

## 6. Improvements Made

### Improved source and migration handling

Compound source names are recognised correctly, and repeatable migrations update existing databases without deleting records.

### Corrected validation boundaries

Validators now check the evidence belonging to their stage instead of depending on the database containing no later-stage records.

### Improved test-data quality

Normal activity was aligned with configured time and location baselines while deliberate suspicious evidence remained available.

### Made policy outcomes deterministic

Identity and network decisions gained explicit priority and tie-breaking rules.

The same evidence now produces the same result regardless of rule order.

### Consolidated endpoint isolation

Several Critical alerts for one device originally created several isolation requests.

They were consolidated into one device request while retaining all supporting alerts.

### Preserved remediation and review state

Later processing no longer replaces completed finding reviews, remediation verification or endpoint approval state.

### Handled unknown criticality safely

Unknown asset criticality contributes zero additional risk instead of being silently treated as Low.

### Added monitoring cooldowns

Repeated threshold detections update the existing alert during cooldown instead of creating alert noise.

### Corrected XDR over-correlation

The first broad correlation grouped activity from separate devices into one incident.

Deterministic primary anchors and explicit exploitation links were added. The final result preserved three separate device chains.

### Separated IoCs from supporting context

Suspicious values can become IoCs when supported by evidence.

MAC addresses remain supporting observables, and behaviours remain investigation descriptions.

---

## 7. Lessons Learned

- An upgrade should extend existing controls instead of creating competing security models.
- Test data must match the baseline it is intended to represent.
- One event can support several valid findings without being several separate attacks.
- Several alerts can support one response request when they concern the same device.
- A vulnerability is not proof of exploitation.
- A risk score is useful only when its original evidence remains available.
- Independent sources strengthen a conclusion, but repeated evidence should not inflate it.
- Shared context can connect unrelated activity if correlation anchors are too broad.
- Exceptions should reduce risk only when they are reviewed and supported.
- Printed output should reflect stored investigation state.
- Database constraints must be checked before introducing new status values.
- Repeated runs test preservation of reviews and approvals as well as duplicate protection.
- Simulated actions must never be described as real containment.
- Documentation is more useful when it records genuine problems and corrections instead of only successful results.

---

## 8. Future Expansion

The completed Stages 1–10 provide a local enterprise-security workflow from event ingestion to cross-source investigation.

The next improvement is to test the risk and correlation settings with additional controlled datasets containing:

- Longer activity timelines
- More overlapping users and devices
- Additional asset relationships
- Repeated but unrelated activity
- Changes in risk over time
- More remediation and verification states

This will help assess whether the scoring weights, decay periods, thresholds, cooldowns, time windows and correlation anchors remain reliable as the dataset grows.

Future cloud and security work can build on the same principles:

- Preserve original evidence.
- Apply least privilege and default deny.
- Keep decisions explainable.
- Require approval for disruptive actions.
- Test changes without damaging completed components.
