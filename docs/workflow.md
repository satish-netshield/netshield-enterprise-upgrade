# NetShield Enterprise Upgrade Workflow

## Project boundary

Phase 3A V2 extends the completed NetShield Phase 3 Automation project.

The project remains inside the controlled Ubuntu VirtualBox sandbox and uses Python, SQLite and simulated enterprise security data.

Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are used only as design references. No Microsoft services, production accounts or real response actions are used.

---

## Combined Stages 1 and 2

Stages 1 and 2 were completed together because the enterprise foundation supports the extended security data pipeline.

### Workflow

1. Verify the completed Phase 3 project.
2. Reuse the existing configuration, RBAC, automation ACL, logging and SQLite database.
3. Add simulated enterprise users, devices, applications and services.
4. Confirm that registered devices agree with the authoritative CYOD inventory.
5. Configure retention periods and sensitive-field masking.
6. Upgrade the existing database through a repeatable migration.
7. Generate enterprise-style JSONL events.
8. Validate schemas, sources, required fields and data types.
9. Convert accepted timestamps to UTC.
10. Preserve raw events and store normalised events.
11. Quarantine malformed records and reject duplicates.
12. Record ingestion totals, failures and audit events.
13. Revalidate the original Phase 3 project.

### Engineering reasoning

The upgrade reuses the original controls instead of creating a separate security model.

A migration updates the existing database safely. Updating `schema.sql` alone would only prepare a new database.

### Problems and solutions

- `CYOD-002` was registered in the enterprise context but missing from the CYOD inventory. The inventory and consistency tests were corrected.
- Compound source names such as `identity_risk` were shortened incorrectly. Source identification was changed to recognise the complete source name.
- Existing validation expected exactly five source types. It was corrected to retain the original sources while allowing approved V2 additions.
- Repeated malformed inputs created additional quarantine rows. Validation was changed to count distinct malformed evidence.

### Testing and lesson

Stage 1 passed 12 out of 12 validation checks. Stage 2 passed 13 out of 13 checks.

Six Stage 2 source files contained 14 events. Twelve were accepted and two malformed events were quarantined.

The main lesson was that an upgrade must preserve the original controls while extending the data and database structure.

---

## Stage 3 — Enterprise asset and device identity

Stage 3 added a controlled device inventory, device identity checks and device-alert review.

### Workflow

1. Synchronise the approved CYOD inventory with SQLite.
2. Match events using device and asset identifiers.
3. Check registration, compliance, ownership and last-seen evidence.
4. Treat MAC addresses as supporting evidence only.
5. Separate unknown, unregistered, stale and mismatched devices.
6. Preserve registration and removal history.
7. Store duplicate-safe alerts and review actions.

### Engineering reasoning

A device ID and asset ID provide stronger evidence than a MAC address alone. Device removal changes its state instead of deleting its history.

### Problems and solutions

Database and web assets were initially treated as devices. Device evaluation was limited to events containing a device ID or an asset ID already known to the device inventory.

`CYOD-003` was also corrected from Unknown Device to Unregistered Device because it already existed in the enterprise context.

### Testing and lesson

Three relevant device events produced one High-severity Unregistered Device alert for `CYOD-003`. Approved `CYOD-002` activity produced no false alert.

Stage 3 passed 19 out of 19 validation checks.

The main lesson was that reliable device identity requires several matching pieces of inventory and event evidence.

---

## Combined Stages 4 and 5

Stages 4 and 5 were built together because access decisions depend on identity, device and risk evidence.

They remain separate components with separate tests, validation results, observations and lessons.

- Stage 4 detects identity and authentication risks.
- Stage 5 evaluates access requests using identity, device, role and risk context.

---

## Stage 4 — Identity monitoring and risk detection

Stage 4 extended the existing authentication logic with enterprise identity-risk monitoring.

### Workflow

1. Generate controlled authentication and identity-risk events.
2. Import the events through the existing V2 pipeline.
3. Load the accepted Stage 4 events from SQLite.
4. Group related failures by user, source address and time window.
5. Compare successful sign-ins with device and location baselines.
6. Evaluate access time, MFA activity, privilege changes and account type.
7. Apply known VPN and approved-testing exceptions.
8. Calculate severity, confidence and optional MITRE ATT&CK mappings.
9. Create deterministic alert keys from the detection and source events.
10. Store alerts with user, device, location, time, risk and evidence.
11. Review a controlled alert through the existing RBAC permissions.
12. Record the detection and review actions in the audit trail.

### Detection workflow

The Stage 4 rules cover:

- Repeated failed logins
- Possible brute-force activity
- Password spraying
- Successful login after repeated failures
- Impossible travel
- New-device sign-in
- Unusual location
- Abnormal access time
- MFA failure or fatigue
- Suspicious privilege changes
- Dormant-account activity
- Service-account interactive login
- Multiple accounts accessed from one source
- Risky sign-in and user-risk activity

Known VPN activity can suppress device, location and impossible-travel findings when the source address is approved. Approved test activity is excluded only when both the user and event are marked for controlled testing.

### Engineering reasoning

The existing Phase 3 identity detector was preserved. Stage 4 uses separate V2 alert storage because the original alert table does not contain confidence, device ID, reason-code or MITRE fields.

Deterministic alert keys prevent repeated detection runs from storing the same alert again.

### Problems and solutions

The first controlled dataset placed normal sign-ins shortly after midnight UTC while the configured normal period began at 06:00 UTC. This would have created several unintended abnormal-time alerts.

The event times were corrected before the detector was completed. Normal sign-ins now occur during the configured period, with one deliberate after-hours event at 23:00 UTC.

### Testing

Twenty-four Stage 4 events produced 16 alerts covering all configured detection types.

The results recorded two VPN exceptions and one approved-testing exception.

One Abnormal Access Time alert was investigated by `analyst01`, classified as a False Positive and closed with investigation notes. The review was written to the audit trail.

A repeated detector run created zero new alerts and identified all 16 as existing.

Nineteen Stage 4 tests passed. Stage 4 validation passed 12 out of 12 checks.

### What I learned

Time-based detection data must agree with the configured time window. Otherwise, valid activity can create false alerts before the detection logic is properly assessed.

I also learned that exceptions should be narrow and recorded. They should suppress only the expected condition rather than bypassing unrelated security checks.

---

## Stage 5 — Zero Trust and policy-based access decisions

Stage 5 added a local policy engine inspired by Zero Trust, RBAC and Conditional Access concepts.

It does not reproduce Microsoft Conditional Access.

### Workflow

1. Load accepted access requests from SQLite.
2. Verify that the identity is active and has an active role.
3. Check the required RBAC permission and minimum role.
4. Load device registration, compliance, risk and asset evidence.
5. Check application sensitivity and asset criticality.
6. Evaluate restricted locations and networks.
7. Evaluate sign-in risk, user risk and MFA evidence.
8. Check temporary access restrictions.
9. Apply an approved VPN exception where configured.
10. Collect every matching policy and reason code.
11. Select the winning policy by priority.
12. Use the more restrictive outcome when priorities are equal.
13. Validate any simulated response action against the automation ACL.
14. Store the complete decision and supporting evidence.
15. Record the evaluation in the audit trail.

### Decision workflow

The engine can return four outcomes:

- `allow` when all required evidence is satisfied
- `deny` when access is not permitted
- `challenge` when stronger verification or monitoring is required
- `restrict` when critical risk requires a controlled restriction

Every decision records the matching policies, winning policy, reason codes, identity evidence, device evidence, risk evidence and ACL result.

The default decision is `deny`.

### Policy priority

Policies use lower numbers for higher priority.

A temporary restriction has higher priority than risk, device or MFA conditions. When policies have the same priority, the engine selects the more restrictive decision in this order:

1. `deny`
2. `restrict`
3. `challenge`
4. `allow`

### Engineering reasoning

Stage 5 reuses the existing RBAC roles and automation ACL rather than defining another permission system.

The policy decision and response action remain separate. A `restrict` decision can be produced immediately, but `restrict_account` remains approval-required and is not automatically executed.

### Testing

Nine controlled access requests produced:

- 2 allow decisions
- 4 deny decisions
- 2 challenge decisions
- 1 restrict decision

The tests covered role permissions, application requirements, registered and compliant devices, restricted networks, restricted locations, MFA, critical risk, VPN exceptions, temporary restrictions, default deny and policy conflicts.

Automatic monitoring remained simulated. Account restriction stopped at `approval_required`.

A repeated policy run created zero new decisions and identified all nine as existing.

Thirteen Stage 5 tests passed. Stage 5 validation passed 14 out of 14 checks.

### What I learned

An access decision should explain why access was allowed or blocked. The final outcome is easier to investigate when the winning policy, all matching reasons and supporting evidence are stored together.

I also learned that access decisions should not bypass the response ACL. A high-risk result can request a restriction, but approval must still be enforced.

---

## Stage 6 — Network, Wi-Fi and access monitoring

Stage 6 extended the project with network and wireless detections, explainable network-access decisions and a connection timeline.

### Workflow

1. Define the network, Wi-Fi, device, zone and exception policies.
2. Create the Stage 6 alert, decision and timeline tables through a repeatable migration.
3. Generate controlled network and Wi-Fi JSONL events.
4. Import the events through the existing V2 pipeline.
5. Load the accepted events and current device inventory from SQLite.
6. Compare source addresses with the IP allowlist, blocklist and approved networks.
7. Group related connections by source address and time window.
8. Check restricted ports, services, connection volume and access time.
9. Match device and asset identifiers with the CYOD inventory.
10. Use MAC addresses as supporting evidence for possible reuse or spoofing.
11. Check Wi-Fi security, access points and network zones.
12. Apply approved VPN and controlled-testing exceptions.
13. Create alerts with severity, confidence, reason codes and connection evidence.
14. Evaluate one network-access decision for every event.
15. Resolve overlapping rules using the configured decision precedence.
16. Validate simulated response actions against the existing automation ACL.
17. Store the connection timeline, alerts and decisions with duplicate protection.
18. Review one controlled alert and record the investigation in the audit trail.

### Detection workflow

Stage 6 covers:

- Suspicious IP addresses
- IP allowlist and blocklist matching
- Port scanning
- Repeated and abnormal connections
- Restricted ports and services
- Unknown CYOD devices
- MAC reuse or possible spoofing
- WPA3 policy violations
- Simulated WPA2 downgrade attempts
- Rogue access points
- Wi-Fi zone violations
- Unknown wired devices
- Restricted wired access

WPA, downgrade and rogue-access-point findings use controlled simulated logs. No wireless attack or real network restriction was performed.

### Network-access decisions

Every Stage 6 event receives one of four outcomes:

- `allow` for approved connections and verified exceptions
- `deny` for prohibited network activity
- `challenge` when more monitoring or verification is required
- `restrict` when a controlled network restriction should be considered

When an event matches more than one rule, the configured precedence is:

1. `deny`
2. `restrict`
3. `challenge`
4. `allow`

This makes the decision deterministic. For example, a port-scan event from a restricted network matched both `port_scanning` and `suspicious_ip_address`. The final decision was `deny` because it has higher precedence than `restrict`.

### Engineering reasoning

Stage 6 uses separate V2 alert, decision and timeline tables so the original Phase 3 network detector and storage remain unchanged.

Device ID and asset ID remain the primary device references. A shared MAC address raises an investigation indicator only when different primary device identities overlap within the configured time window.

Network decisions remain separate from response actions. A `challenge` can create simulated increased monitoring automatically. A `restrict` decision uses the approval-required `apply_ubuntu_firewall_rule` action and does not change the real Ubuntu firewall.

### Problems and solutions

- The first configuration contained a spelling error in the MAC-reuse rule name. It was corrected before the detector was tested.
- The first network policy did not explicitly define how overlapping outcomes should be resolved. A deterministic decision order was added.
- The first `restrict` mapping used `restrict_account`, which was an identity response rather than a network response. It was replaced with the existing approval-required `apply_ubuntu_firewall_rule` action.
- Several port-scan events also matched restricted-network and restricted-port rules. The detector preserved every matching rule and reason while producing one final decision through precedence.

### Testing

Two Stage 6 source files contained 34 unique events:

- 27 network events
- 7 Wi-Fi events

The detector produced 18 alerts across all 13 configured detection types.

The policy evaluation produced 34 decisions:

- 4 allow
- 18 deny
- 11 challenge
- 1 restrict

The connection timeline stored all 34 events.

One approved VPN event and one approved-testing event were allowed with their exception reason codes preserved.

The rogue-access-point event produced a `restrict` decision, but the firewall action remained `approval_required`.

One Abnormal Connection Pattern alert was reviewed by `analyst01`, classified as a False Positive and closed after confirming controlled after-hours connection-volume testing.

A repeated monitoring run created:

- 0 new alerts and 18 existing alerts
- 0 new decisions and 34 existing decisions
- 0 new timeline records and 34 existing records

Twenty-three focused Stage 6 tests passed. Stage 6 validation passed 15 out of 15 checks.

The complete project passed 174 unit tests. The original Stage 11 validation passed, and SQLite integrity returned `ok`.

### What I learned

One network event can match several valid security rules. Keeping every matching rule and reason code while producing one final decision makes the result easier to explain.

I also learned that a security decision and a response action are not the same thing. The detector can recommend restriction, but the automation ACL must still decide whether that action is automatic, approval-required or manual.

MAC reuse is useful evidence, but it should not identify a device by itself.

---

## Stage 7 — Endpoint monitoring and investigation

Stage 7 added vendor-neutral endpoint investigation using device, process, user and activity evidence.

### Workflow

1. Define endpoint health, compliance, risk, process and exception policies.
2. Create the endpoint alert, timeline and simulated-isolation tables through a repeatable migration.
3. Import controlled endpoint events through the existing V2 pipeline.
4. Load accepted events and the CYOD inventory from SQLite.
5. Evaluate endpoint health, device compliance and device-risk states.
6. Check process approval, ownership, parent-child relationships and command activity.
7. Group CPU activity and repeated crashes or restarts within their configured time windows.
8. Check possible persistence indicators and unexpected file-hash changes.
9. Apply approved administrative and testing exceptions using exact evidence.
10. Store traceable alerts and the activity timeline with duplicate protection.
11. Consolidate Critical alerts into one simulated-isolation request per device.
12. Require an authorised Responder or Administrator to approve the request through the existing RBAC and `quarantine_device` ACL controls.
13. Record approval as `simulated_isolated` without changing real network connectivity.
14. Continue monitoring endpoint events, including controlled post-isolation activity.
15. Review an endpoint alert and preserve its evidence, classification and audit history.
16. Add the Stage 7 tables and indexes to the tracked schema and run stage and project validation.

### Engineering reasoning

Endpoint findings use observed activity alongside inventory context. A registered device or approved process can still produce an alert when its behaviour matches a rule.

Repeated crashes or restarts use the agreed threshold of three events within eight minutes.

Detection and isolation approval remain separate. Approval changes only the project record; it does not disable Wi-Fi, stop network traffic, terminate processes or change the operating system.

### Problems and solutions

- The first implementation created a separate isolation request for every Critical alert on the same device. Requests were consolidated by device while preserving all supporting Critical alert keys.
- After approval, the runner printed the newly calculated pending status rather than the stored status. It was corrected to read and display the existing isolation record.

### Testing

Twenty-six controlled endpoint events produced 26 alerts across 13 detection types. Approved administrative and testing exceptions produced no alerts.

One consolidated request preserved all 10 Critical alert keys. Analyst approval was rejected, and `responder01` recorded simulated approval. Repeated approval and monitoring runs preserved the approved record without creating another request.

The crash or restart alert was reviewed by `analyst01`, classified as a False Positive and closed with evidence-based notes. Re-running detection preserved the review.

All 17 Stage 7 tests and 14 validation checks passed. Earlier V2 validators, the complete regression and original Phase 3 validation also passed.

### What I learned

Several alerts on one device do not require several isolation requests. One device-level request can retain every supporting finding.

Printed output must reflect the stored investigation state, especially after approval or review.

A crash or restart pattern is evidence for investigation, not proof of malicious activity. Classification needs process, device and event context.

---

## Stage 8 — Vulnerability and application-security findings

Stage 8 added controlled vulnerability and application-security findings linked to the authoritative sandbox asset.

### Workflow

1. Register the SQL injection lab as the authoritative `AST-WEB-001` sandbox web-application asset.
2. Define vulnerability scoring, remediation, review, linking and testing boundaries.
3. Create the finding, remediation-history and evidence-link tables through a repeatable migration.
4. Import the controlled application-security and vulnerability events through the existing V2 pipeline.
5. Verify that every finding refers to an authoritative asset.
6. Build findings from configuration checks, dependency checks, package checks, exposed-service evidence and the local SQL injection lab.
7. Preserve severity, confidence, exploitability, exploitation status, exposed-service context and asset criticality.
8. Calculate a weighted priority score from the five configured factors.
9. Store findings and remediation history with duplicate protection.
10. Preserve the original risk evidence when remediation status changes.
11. Record remediation verification as later evidence without replacing the original finding.
12. Keep approved penetration-testing events as testing evidence rather than treating them as vulnerabilities.
13. Create alert and incident links only when supporting activity or exploitation evidence exists.
14. Prevent a vulnerability from automatically creating an incident.
15. Allow an authorised Analyst to review a supported false-positive candidate.
16. Preserve the classification, investigation notes, remediation history and audit record.
17. Re-run the engine to confirm that stored reviews and verification states remain unchanged.
18. Run focused tests, Stage 8 validation, the complete regression and database-integrity checks.

### Priority workflow

The priority score uses the configured weighted model:

- Severity: 30%
- Exploitability: 25%
- Asset criticality: 20%
- Exposed-service context: 15%
- Confidence: 10%

The combined score produces a priority level from Low to Critical.

Remediation does not reduce or erase the original severity, confidence or exploitability evidence. It changes the finding’s remediation status and adds verification history.

### Engineering reasoning

A vulnerability finding is not proof that exploitation occurred. The project keeps vulnerability evidence separate from alert and incident evidence.

Finding-to-alert and finding-to-incident links require supporting activity or exploitation context. Automatic incident creation remains disabled.

Controlled penetration-testing records confirm that approved local testing occurred. They remain evidence and do not become findings by themselves.

The engine uses the registered sandbox asset rather than accepting unknown assets. This keeps findings connected to known project context.

### Problems and solutions

- The first remediation handling replaced the original SQL injection and dependency risk values with later Low-severity verification data. The logic was corrected so verification updates the remediation state while preserving the original risk evidence.
- After the false-positive review, a repeated engine run printed the rebuilt `Open` status instead of the stored `False Positive` status. The runner was corrected to reload and display the saved finding state.

### Testing

Two Stage 8 source files contained 16 unique events:

- 6 application-security events
- 10 vulnerability events

The engine stored seven duplicate-safe findings linked to `AST-WEB-001`:

- 1 High-priority finding
- 4 Medium-priority findings
- 2 Low-priority findings

The final remediation states were:

- 1 Open
- 2 Planned
- 3 Verified
- 1 False Positive

The SQL injection finding retained its original High severity, demonstrated exploitability and successful exploitation evidence after remediation verification.

One alert link and one incident link were stored for the SQL injection finding because successful exploitation evidence was available. No incident was created automatically.

Two approved controlled-testing events remained evidence and used no external targets.

`analyst01` reviewed the version-only finding, classified it as a False Positive and preserved the investigation notes and review history. A repeated engine run retained that decision.

All 14 Stage 8 tests passed. Stage 8 validation passed 16 out of 16 checks.

The complete project passed 205 unit tests. The original Stage 11 validation passed, and SQLite integrity returned `ok`.

### What I learned

Remediation evidence should not rewrite the original risk. A verified finding still needs its earlier severity, exploitability and exploitation context for investigation and audit history.

A vulnerability should be linked to an incident only when activity or exploitation evidence supports the relationship.

Stored investigation state must take priority over newly rebuilt output. Otherwise, a repeated run can display an outdated status even when the database record is correct.

Approved security testing is evidence of a controlled test, not evidence that every test target contains a vulnerability.

---

## Next improvement

Stage 8 is complete and validated.

Later work should continue one stage at a time and only within its agreed scope:

1. Confirm the stage boundary.
2. Build only the required capability.
3. Test the implemented component.
4. Run it with the existing project.
5. Review the actual output and stored evidence.
6. Record meaningful failures and decisions.
7. Correct genuine problems.
8. Run the affected tests and complete regression.
9. Update only the relevant documentation.
10. Sign off after final validation.
