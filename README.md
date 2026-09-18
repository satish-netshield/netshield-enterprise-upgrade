# NetShield Enterprise Upgrade

NetShield Enterprise Upgrade extends the completed NetShield Phase 3 Automation project.

It is a Python and SQLite security-automation project running inside a controlled Ubuntu VirtualBox sandbox. Enterprise users, devices, applications and security events are simulated.

Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design references only. No Microsoft tenants, cloud resources, production accounts, external targets or real response actions are used.

## Current Project Status

Completed Phase 3A V2 stages:

- Stage 1 — Enterprise foundation
- Stage 2 — Extended security data pipeline
- Stage 3 — Enterprise asset and device identity
- Stage 4 — Identity monitoring and risk detection
- Stage 5 — Policy-based access decisions
- Stage 6 — Network, Wi-Fi and access monitoring
- Stage 7 — Endpoint monitoring and investigation
- Stage 8 — Vulnerability and application-security findings
- Stage 9 — Continuous monitoring and dynamic risk scoring
- Stage 10 — XDR-style cross-source correlation

The original Phase 3 components remain operational. This README concentrates on the enterprise upgrade.

## Technologies

- Ubuntu VirtualBox sandbox
- Python 3 and `unittest`
- SQLite
- JSON and JSONL
- Git and GitHub
- Application and audit logging
- SHA-256 evidence hashing

---

## Stage 1 — Enterprise Foundation

### What the component does

Stage 1 adds simulated enterprise users, devices, applications and services, along with retention settings, sensitive-field masking and V2 metadata.

### Why it exists or how it behaves

The upgrade reuses the established RBAC roles, automation ACL, database, logging, evidence controls and sandbox boundaries instead of creating a second security model.

### Information, rules and capabilities

- Viewer, Analyst, Responder and Administrator roles
- CYOD inventory consistency
- Default-deny automation controls
- Retention settings and sensitive-field masking
- Evidence preservation and Phase 3 compatibility

Automatic retention enforcement is not implemented. Masking suitable output does not change original evidence.

### Workflow

1. Load settings and enterprise context.
2. Reuse the database and security controls.
3. Register simulated users with existing roles.
4. Verify registered devices against the CYOD inventory.
5. Store metadata and audit records.
6. Revalidate the foundation.

### Observed example output

```text
PASS: Phase 3A V2 Stage 1 foundation initialised
Simulated users registered: 4
Simulated devices available: 3
Applications and services available: 5

V2 STAGE 1 VALIDATION: PASS (12/12)
```

### Testing Notes

Repeated initialisation did not duplicate role assignments. Inventory consistency, masking, permissions and Phase 3 compatibility were checked.

### Engineering observations

`CYOD-002` was registered in enterprise context but missing from the authoritative inventory. The inventory and consistency test were corrected.

### What I Learned

Enterprise context must agree with existing authoritative records.

---

## Stage 2 — Extended Security Data Pipeline

### What the component does

Stage 2 adds enterprise-style security sources while preserving the original event pipeline.

### Why it exists or how it behaves

Later decisions need consistent and traceable data. Records are validated before acceptance and stored with UTC timestamps and original evidence.

### Information, rules and capabilities

- Common schema and source identification
- Required-field and data-type validation
- Malformed-event quarantine
- Duplicate protection
- Raw-event preservation
- Import statistics and failed-batch records

### Workflow

1. Apply the repeatable migration.
2. Read the controlled JSONL files.
3. Validate and normalise records.
4. Store accepted events.
5. Quarantine malformed records.
6. Record import and audit results.

### Observed example output

```text
V2 STAGE 2 IMPORT: files=6 total=14 accepted=12 rejected=2 failed=0
```

A repeated import produced:

```text
V2 STAGE 2 IMPORT: files=6 total=14 accepted=0 rejected=14 failed=0
```

### Testing Notes

Twelve valid events were accepted and two malformed inputs were quarantined. Repeated import stored no duplicate accepted events.

### Engineering observations

Compound source names were initially shortened incorrectly. Complete-name recognition was added.

A repeatable migration was also required because updating `schema.sql` alone did not upgrade the working database.

### What I Learned

Malformed records, duplicates and file failures need separate outcomes. Database changes must support both new and existing databases.

---

## Stage 3 — Enterprise Asset and Device Identity

### What the component does

Stage 3 strengthens device inventory and identity context for later decisions.

### Why it exists or how it behaves

Device ID and asset ID are the main references. User, hostname, location and MAC address provide supporting context.

### Information, rules and capabilities

- Registered CYOD inventory
- Unknown, unregistered, stale and mismatched devices
- Duplicate-safe alerts
- Registration and review history

A MAC address is not treated as proof of device identity.

### Observed example output

```text
PASS: One meaningful Stage 3 device alert is stored
PASS: CYOD-003 is correctly classified as an unregistered device
PASS: Approved CYOD-002 activity creates no false alert
```

### Testing Notes

Three relevant events produced one High Unregistered Device alert. Repeated detection created no duplicate alert.

### Engineering observations

Non-device assets were excluded from device evaluation. `CYOD-003` was classified as known but unregistered rather than unknown.

### What I Learned

Reliable device identity requires combined inventory and event context.

---

## Stage 4 — Identity Monitoring and Risk Detection

### What the component does

Stage 4 detects identity and authentication risks and supports authorised investigation.

### Why it exists or how it behaves

Related events and identity baselines provide more context than a single sign-in.

### Information, rules and capabilities

- Failed-login and password-spraying patterns
- Success after repeated failures
- New devices, unusual locations and impossible travel
- Abnormal access time and MFA failures
- Privilege changes, dormant accounts and service accounts
- Severity, confidence, reasons and supporting evidence
- VPN and controlled-testing exceptions

### Workflow

1. Load identity events.
2. Group related activity.
3. Compare it with configured baselines.
4. Apply evidence-matched exceptions.
5. Store duplicate-safe alerts.
6. Record authorised reviews.

### Observed example output

```text
V2 STAGE 4 IDENTITY MONITORING: events=24 detections=16 new=16 existing=0 vpn_exceptions=2 testing_exceptions=1
```

A repeated run produced:

```text
V2 STAGE 4 IDENTITY MONITORING: events=24 detections=16 new=0 existing=16 vpn_exceptions=2 testing_exceptions=1
```

### Testing Notes

The monitoring and review groups passed 19 tests. An Analyst classified the controlled abnormal-time alert as a False Positive without deleting its evidence.

### Engineering observations

Normal test events initially occurred outside the configured access period. Their timestamps were corrected while deliberate abnormal-time evidence remained.

### What I Learned

Test data must agree with its configured baseline.

---

## Stage 5 — Policy-Based Access Decisions

### What the component does

Stage 5 evaluates identity, role, device, application, location, network, MFA and risk evidence.

### Why it exists or how it behaves

A recognised account or role is not enough to confirm that a complete access request is safe. Unknown applications and unverifiable conditions follow default deny.

### Access outcomes

| Outcome | Meaning |
|---|---|
| Allow | Required conditions were satisfied. |
| Deny | Access was not permitted. |
| Challenge | Stronger verification was required. |
| Restrict | Serious risk supported a controlled restriction request. |

Equal-priority policies use the order Deny, Restrict, Challenge and Allow.

### Workflow

1. Load the request and context.
2. Check restrictions and role permissions.
3. Evaluate device, network, MFA and risk.
4. Select the winning policy.
5. Check the proposed response against the ACL.
6. Store the decision and reasons.

### Observed example output

```text
V2 STAGE 5 ACCESS POLICY: requests=9 decisions=9 new=9 existing=0 allow=2 deny=4 challenge=2 restrict=1
```

A repeated run produced:

```text
V2 STAGE 5 ACCESS POLICY: requests=9 decisions=9 new=0 existing=9 allow=2 deny=4 challenge=2 restrict=1
```

### Testing Notes

Thirteen focused tests passed. Every request retained one unique decision.

### Engineering observations

Policy priority and restrictive tie-breaking were made explicit. Proposed account restriction remained approval-required.

### What I Learned

An access decision must explain its evidence without gaining permission to perform a response.

---

## Stage 6 — Network, Wi-Fi and Access Monitoring

### What the component does

Stage 6 detects suspicious network and wireless activity, produces access decisions and stores a connection timeline.

### Why it exists or how it behaves

One event can match several conditions. Every matching reason is retained while one deterministic decision is produced.

Wireless scenarios use controlled logs. No real wireless attack or firewall change is performed.

### Information, rules and capabilities

- Suspicious addresses and list matching
- Port scans and repeated connections
- Restricted ports and services
- Unknown devices and possible MAC reuse
- WPA3 violations and simulated WPA2 downgrade
- Rogue access points and zone violations
- Allow, Deny, Challenge and Restrict decisions
- Connection timeline and alert review

Decision precedence is Deny, Restrict, Challenge and Allow. MAC addresses remain supporting evidence.

### Observed example output

```text
V2 STAGE 6 NETWORK MONITORING: events=34 alerts=18 new_alerts=18 existing_alerts=0 decisions=34 new_decisions=34 existing_decisions=0 timeline_new=34 timeline_existing=0 allow=4 deny=18 challenge=11 restrict=1 vpn_exceptions=1 testing_exceptions=1
```

### Testing Notes

Thirty-four events produced 18 alerts, 34 decisions and 34 timeline records. Repeated monitoring created no duplicates.

Twenty-three focused tests passed. An Analyst closed the controlled Abnormal Connection Pattern alert as a False Positive.

### Engineering observations

A fixed decision order resolved conflicting conditions. The Restrict outcome was mapped to the existing approval-required firewall action.

### What I Learned

Several valid findings can support one decision. A network decision does not automatically authorise a network change.

---

## Stage 7 — Endpoint Monitoring and Investigation

### What the component does

Stage 7 evaluates device state, process activity, commands, CPU use, crashes, persistence and file hashes.

### Why it exists or how it behaves

Endpoint health or a process name alone cannot explain suspicious activity. The engine retains the evidence behind each finding.

Critical alerts for the same device support one consolidated simulated-isolation request.

### Information, rules and capabilities

- Endpoint health, compliance and risk
- Suspicious or unapproved processes
- Unexpected process owners and parent-child relationships
- High CPU and repeated crash activity
- Suspicious commands and persistence indicators
- Unexpected file-hash changes
- Approved exceptions
- Endpoint timeline
- Simulated isolation and false-positive review

No real isolation, network change or process termination occurs.

### Observed example output

```text
[ISOLATION RECORD] device=CYOD-002 | action=quarantine_device | status=simulated_isolated | approved_by=responder01 | real_action=False | network_change=False
```

Repeated monitoring produced:

```text
V2 STAGE 7 ENDPOINT MONITORING: events=26 alerts=26 new_alerts=0 existing_alerts=26 detection_types=13 critical=10 high=13 medium=3 low=0 timeline_new=0 timeline_existing=26 isolation_requests=1 isolation_new=0 isolation_existing=1 approved_exceptions=2 real_actions=0 network_changes=0
```

### Testing Notes

Seventeen focused tests passed. Stage 7 validation passed 14 out of 14 checks.

One isolation record preserved all 10 Critical alert keys. Repeated monitoring preserved the approval and completed false-positive review.

### Engineering observations

The first run created 10 requests for one device. They were consolidated without losing the supporting alert keys.

The runner was also corrected to report the stored approval state.

### What I Learned

Several alerts can support one response request without losing their separate evidence.

---

## Stage 8 — Vulnerability and Application-Security Findings

### What the component does

Stage 8 manages controlled vulnerability, configuration, dependency, package, service-exposure and SQL injection findings.

### Why it exists or how it behaves

Findings support prevention and remediation. They do not become incidents unless activity or other evidence supports attempted or successful exploitation.

### Information, rules and capabilities

- Authoritative asset links
- Severity and confidence
- Exploitability and exposed-service context
- Asset criticality
- Weighted priority scores
- Remediation status and verification
- Duplicate-safe findings and history
- False-positive review
- Finding-to-alert and finding-to-incident links
- Approved local testing boundaries

### Priority model

Priority combines:

1. Finding severity
2. Confidence
3. Exploitability
4. Exposed-service context
5. Asset criticality

The score supports prioritisation without replacing original evidence.

### Observed example output

```text
[High] SQL injection authentication bypass | finding=S78-FND-SQL-001 | asset=AST-WEB-001 | score=71.05 | status=Verified
[Medium] Restricted service exposed inside the sandbox | finding=S78-FND-SVC-001 | asset=AST-WEB-001 | score=64.65 | status=Open
[Low] Version-only finding requiring analyst review | finding=S78-FND-FP-001 | asset=AST-WEB-001 | score=39.50 | status=False Positive
```

The final summary reported:

```text
V2 STAGE 8 VULNERABILITY MANAGEMENT: events=16 findings=7 critical=0 high=1 medium=4 low=2 open=1 planned=2 verified=3 false_positive=1 alert_links=1 incident_links=1 approved_tests=2 automatic_incidents=0 external_targets=0
```

### Testing Notes

Fourteen focused tests passed. Stage 8 validation passed 16 out of 16 checks.

Seven findings, 13 history records and two evidence-backed links remained duplicate-safe. Repeated processing preserved the false-positive review.

### Engineering observations

The first validator run found that Stage 8 metadata still contained the foundation status. A completed management run updated it to `vulnerability_management_complete`.

### What I Learned

Remediation should add history without rewriting original risk. A vulnerability also needs activity evidence before it can support an incident.

---

## Stage 9 — Continuous Monitoring and Dynamic Risk Scoring

### What the component does

Stage 9 reassesses existing security evidence through scheduled monitoring cycles.

### Why it exists or how it behaves

Security risk changes as evidence ages, exceptions are validated and independent sources agree.

Risk scores support decisions but do not replace the original alerts, findings or events.

### Information, rules and capabilities

- Deterministic 15-minute cycles
- User, device, asset and incident risk
- Severity, confidence and criticality weighting
- Independent-source agreement
- Validated exception reduction
- Time-based decay
- Threshold and escalation alerts
- Alert cooldown and suppression
- Detection and pipeline health
- Last-successful-run tracking
- Monitoring summaries and metrics

Unknown asset criticality adds zero points rather than being treated as Low.

### Risk workflow

1. Load evidence from completed components.
2. Map evidence to the relevant entity.
3. Apply configured weights.
4. Add independent-source agreement.
5. Apply validated exception and time reductions.
6. Store current and historical scores.
7. Create threshold alerts.
8. Record component health and cycle results.

### Observed example output

```text
PASS: Stage 9 risk scoring completed
Evidence mappings: 171
Entities scored: 20
Threshold alerts proposed: 4
```

The four High scores were:

```text
asset AST-001: score=71.00
user viewer01: score=71.00
device CYOD-001: score=66.00
user responder01: score=66.00
```

A controlled repeated cycle reported:

```text
status=completed evidence=171 entities=20 risk_alerts=4 health_alerts=0 alerts_new=0 alerts_suppressed=4
```

### Testing Notes

Fifteen focused tests passed. Stage 9 validation passed 20 out of 20 checks.

Twenty entities covered all four entity types. Seven monitored components were Healthy. A repeated cycle suppressed four alerts during cooldown without losing evidence.

### Engineering observations

Some evidence used unknown asset criticality. It was assigned zero additional points instead of an assumed Low value.

An inspection query also requested a non-existent suppression column. The query was corrected to use the actual stored fields without changing the schema.

### What I Learned

A useful score must remain connected to its evidence. Independent agreement can raise risk, while validated exceptions and time can reduce it.

---

## Stage 10 — XDR-Style Cross-Source Correlation

### What the component does

Stage 10 correlates identity, access-policy, network, endpoint, application and vulnerability evidence into explainable incidents.

### Why it exists or how it behaves

Related activity should be combined, but shared context must not merge unrelated device chains.

Vulnerability context supports an incident only when related activity also exists.

### Information, rules and capabilities

- Device, asset, user, address, hostname, process and file-hash context
- Primary correlation anchors
- Configured time window
- Independent-source confidence
- Validated exception and verified-activity reduction
- Explicit exploitation links
- Duplicate-event score protection
- Original evidence links
- IoC extraction
- Supporting observables
- Suspicious behaviours
- Relevant ATT&CK mappings
- Duplicate-safe incidents, evidence links and indicators

MAC addresses remain supporting observables and cannot become primary correlation anchors.

### Correlation workflow

1. Load unique evidence from six source types.
2. Select the strongest available primary anchor.
3. Apply the configured time window.
4. Preserve explicit exploitation links.
5. Keep unrelated activity separate.
6. Calculate severity and confidence.
7. Attach context-only vulnerabilities.
8. Extract supported IoCs and observables.
9. Store incidents and evidence links.
10. Repeat correlation and verify duplicate protection.

### Observed example output

```text
[Critical] XDR Incident | title=Cross-source activity involving device CYOD-001 | confidence=95 | sources=3 | evidence=13
[Critical] XDR Incident | title=Cross-source activity involving device CYOD-002 | confidence=88 | sources=6 | evidence=49
[Medium] XDR Incident | title=Cross-source activity involving device CYOD-003 | confidence=70 | sources=2 | evidence=3
```

The final summary reported:

```text
V2 STAGE 10 XDR CORRELATION: evidence=76 source_types=6 candidate_groups=10 incidents=3 evidence_links=65 indicators=13 critical=2 high=0 medium=1 low=0 iocs=10 supporting_observables=3 vulnerability_context=6 exceptions=3 verified_activity=4 automatic_actions=0
```

### Testing Notes

Seventeen focused tests passed. Stage 10 validation passed 20 out of 20 checks.

Repeated correlation created:

- 0 new incidents and 3 existing incidents
- 0 new links and 65 existing links
- 0 new indicators and 13 existing indicators
- 0 automatic response actions

### Engineering observations

The first broad grouping joined 65 of 76 records into one incident and mixed separate device chains.

Correlation was corrected to use deterministic primary anchors and supported explicit links. A regression test confirmed that a shared username could not merge unrelated devices.

### What I Learned

Correlation needs strong boundaries. Shared context can support an investigation, but it should not connect unrelated activity by itself.

---

## System Validation

### Clean-state validation workflow

The final validation sequence:

1. Compiled project Python files.
2. Ran V2 Stage 1–10 validators.
3. Ran the original Phase 3 full-project validator.
4. Ran the complete unit-test suite.
5. Checked the warning-enabled test run.
6. Checked SQLite integrity and foreign keys.
7. Checked repository whitespace and status.

### Genuine end-to-end results

```text
V2 STAGE 1 VALIDATION: PASS (12/12)
V2 STAGE 2 VALIDATION: PASS (13/13)
Stage 3 validation: 19/19 checks passed
V2 STAGE 4 VALIDATION: PASS (12/12)
V2 STAGE 5 VALIDATION: PASS (14/14)
V2 STAGE 6 VALIDATION: PASS (15/15)
V2 STAGE 7 VALIDATION: PASS (14/14)
V2 STAGE 8 VALIDATION: PASS (16/16)
V2 STAGE 9 VALIDATION: PASS (20/20)
V2 STAGE 10 VALIDATION: PASS (20/20)

Ran 237 tests in 2.235s

OK

STAGE 11 VALIDATION: PASS
```

SQLite integrity returned `ok`. Foreign-key checking returned no violations. Python compilation and repository whitespace checks completed successfully.

Earlier Stage 4–5 validation result: 151 tests passed with zero unclosed-database warnings.

The Stage 11 result belongs to the original Phase 3 project and confirms that the upgrade did not break the inherited project.

### Problems discovered

The main problems involved:

- Inconsistent enterprise and inventory context
- Source-name recognition
- Existing-database migration
- Validator evidence boundaries
- Policy conflicts
- Repeated isolation requests
- Incomplete or damaged source transfers
- Stage completion metadata
- Unknown asset criticality
- XDR over-correlation

### How the problems were fixed

Authoritative records were aligned, complete source names were recognised and repeatable migrations were added.

Validators were limited to their intended evidence. Policy precedence was made explicit. Isolation requests were consolidated. Stored state was used for reporting.

Unknown criticality was prevented from adding risk. XDR correlation was restricted to deterministic primary anchors and supported explicit links.

### Engineering observations

Repeated execution checked more than duplicate protection. It also confirmed that reviews, approvals, remediation history, cooldown state and evidence links survived later processing.

Later-stage data was not removed to satisfy earlier validators. Validator boundaries were corrected instead.

### What I Learned

Security automation is easier to trust when every result retains its evidence, reason and investigation history.

Risk scoring and correlation improve prioritisation, but they must not replace original evidence or authorise disruptive responses.

### Next expansion scope

The next improvement is to test the completed risk and correlation settings with additional controlled datasets containing longer timelines and more overlapping users, devices and assets.

This will help assess scoring weights, decay periods, thresholds, cooldowns, correlation windows and anchor order while preserving the existing safety boundaries.
