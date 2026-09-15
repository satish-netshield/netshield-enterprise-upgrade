# NetShield Enterprise Upgrade

NetShield Enterprise Upgrade extends the completed NetShield Phase 3 Automation project.

It is a Python and SQLite security-automation project running inside a controlled Ubuntu VirtualBox sandbox. Enterprise users, devices, applications and security events are simulated.

Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design references only. No Microsoft tenants, cloud resources, production accounts, external targets or real response actions are used.

## Current Project Status

Completed Phase 3A V2 stages:

- Stage 1 — Enterprise project foundation
- Stage 2 — Extended security data pipeline
- Stage 3 — Enterprise asset and device identity
- Stage 4 — Identity monitoring and risk detection
- Stage 5 — Zero Trust and policy-based access decisions
- Stage 6 — Network, Wi-Fi and access monitoring
- Stage 7 — Endpoint monitoring and investigation

Stage 8 has saved configuration, database preparation and controlled inputs. Its vulnerability-management engine is not implemented or validated.

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

## Stage 1 — Enterprise Project Foundation

### What the component does

Stage 1 adds simulated enterprise users, devices, applications and services, along with retention settings, sensitive-field masking and V2 metadata.

### Why it exists or how it behaves

The upgrade reuses the established RBAC roles, automation ACL, database, logging, evidence controls and sandbox boundaries rather than creating a second security model.

### Information, rules and capabilities

- Viewer, Analyst, Responder and Administrator roles
- CYOD inventory consistency
- Default-deny automation controls
- Retention settings and sensitive-field masking
- Evidence preservation and compatibility checks

Automatic retention enforcement is not implemented. Masking suitable output does not change original evidence.

### Workflow

1. Load settings and enterprise context.
2. Reuse the database and security controls.
3. Register simulated users with existing roles.
4. Verify registered devices against the CYOD inventory.
5. Apply retention and masking settings.
6. Store metadata and audit records.
7. Revalidate the foundation.

### Observed example output

```text
PASS: Phase 3A V2 Stage 1 foundation initialised
Simulated users registered: 4
Simulated devices available: 3
Applications and services available: 5

V2 STAGE 1 VALIDATION: PASS (12/12)
```

### Testing Notes

Validation passed. Repeated initialisation did not duplicate user-role assignments. Inventory consistency, masking and sensitive permissions were checked.

### Engineering observations

`CYOD-002` appeared as registered in enterprise context but was missing from the authoritative inventory. The inventory was corrected and a consistency test was added.

### What I Learned

Enterprise context must agree with existing authoritative records.

---

## Stage 2 — Extended Security Data Pipeline

### What the component does

Stage 2 adds identity-risk, access-policy, database, vulnerability, incident and response sources while preserving the original event sources.

### Why it exists or how it behaves

Later decisions need consistent, traceable data. Events are validated before acceptance and stored with UTC timestamps and original evidence.

### Information, rules and capabilities

- Common schema, schema version and source identification
- Required-field and data-type validation
- Malformed-event quarantine
- Duplicate-event protection
- Raw-event preservation
- Investigation indexes, import totals and failed-batch records

### Workflow

1. Apply the repeatable migration.
2. Generate and read JSONL source files.
3. Validate records and normalise timestamps.
4. Store accepted events and original evidence.
5. Quarantine malformed records and reject duplicates.
6. Record batch totals, failures and audit events.

### Observed example output

```text
V2 STAGE 2 IMPORT: files=6 total=14 accepted=12 rejected=2 failed=0
```

A repeated import produced:

```text
V2 STAGE 2 IMPORT: files=6 total=14 accepted=0 rejected=14 failed=0
```

### Testing Notes

Twelve valid events were stored and two malformed inputs were quarantined. Repeated import accepted no duplicates. A temporary unreadable file confirmed failed-batch recording.

### Engineering observations

Compound source names were initially shortened incorrectly. Complete-name recognition was added.

Updating `schema.sql` did not upgrade the working database, so a repeatable migration was added. Validation was also corrected to count distinct malformed evidence.

### What I Learned

Malformed records, duplicate events and file failures need separate outcomes. Database upgrades must support both new and existing databases.

---

## Stage 3 — Enterprise Asset and Device Identity

### What the component does

Stage 3 strengthens device inventory and identity context for later decisions.

### Why it exists or how it behaves

Device ID and asset ID are the main references. User, hostname, address, location and MAC address provide supporting evidence.

### Information, rules and capabilities

- Registered CYOD inventory
- Unknown, unregistered, stale and mismatched device findings
- Duplicate-safe alerts
- Registration and review history

A MAC address is not treated as proof of identity.

### Workflow

1. Synchronise the approved inventory with SQLite.
2. Match relevant device events.
3. Compare observed and expected context.
4. Store findings and preserve review history.

### Observed example output

```text
PASS: One meaningful Stage 3 device alert is stored
PASS: CYOD-003 is correctly classified as an unregistered device
PASS: Approved CYOD-002 activity creates no false alert
```

### Testing Notes

Three relevant events produced one High-severity Unregistered Device alert. Repeated detection created no duplicate alert.

### Engineering observations

Non-device assets were excluded from device evaluation. `CYOD-003` was classified as known but unregistered rather than unknown.

### What I Learned

Reliable device identity requires combined context, not a MAC address alone.

---

## Stage 4 — Identity Monitoring and Risk Detection

### What the component does

Stage 4 detects identity and authentication risks and supports authorised alert investigation.

### Why it exists or how it behaves

Related events and user baselines provide more context than a single sign-in. V2 alerts use separate storage to preserve the original Phase 3 implementation.

### Information, rules and capabilities

- Failed-login patterns, password spraying and success after failures
- Multiple-account activity from one source
- Impossible travel, new devices and unusual locations or access times
- MFA failures, privilege changes and risky sign-ins
- Dormant-account and service-account activity
- Severity, confidence, reason codes and supporting evidence
- Evidence-matched VPN and testing exceptions

### Workflow

1. Load authentication and identity-risk events.
2. Group related activity by identity, source and time.
3. Compare activity with configured baselines.
4. Apply approved exceptions.
5. Store duplicate-safe alerts.
6. Record authorised investigation and classification.

### Observed example output

```text
V2 STAGE 4 IDENTITY MONITORING: events=24 detections=16 new=16 existing=0 vpn_exceptions=2 testing_exceptions=1
```

A repeated run produced:

```text
V2 STAGE 4 IDENTITY MONITORING: events=24 detections=16 new=0 existing=16 vpn_exceptions=2 testing_exceptions=1
```

### Testing Notes

The monitoring and review groups passed 19 tests. Stored alert keys remained unique. An Analyst classified the controlled abnormal-time alert as a False Positive and closed it without deleting evidence.

### Engineering observations

Normal test events initially fell outside configured access hours. Their timestamps were corrected while deliberate abnormal-time evidence was retained.

### What I Learned

Test data must match its baseline. Exceptions and investigation outcomes should remain visible.

---

## Stage 5 — Zero Trust and Policy-Based Access Decisions

### What the component does

Stage 5 evaluates identity, role, device, application, location, network, MFA and risk evidence to make local access decisions.

### Why it exists or how it behaves

A recognised username or role does not establish that a complete request is safe. Unknown applications and unverifiable conditions follow default deny.

### Information, rules and capabilities

| Outcome | Meaning |
|---|---|
| Allow | Required conditions were satisfied. |
| Deny | Access was not permitted. |
| Challenge | Stronger verification or evidence was required. |
| Restrict | Access should be limited because of serious risk. |

Decisions retain the winning policy, reasons, evidence and ACL result. Equal-priority policies use the order Deny, Restrict, Challenge, Allow.

### Workflow

1. Load the request and supporting context.
2. Check restrictions and role permissions.
3. Evaluate device, network, location, MFA and risk.
4. Resolve matching policy priorities.
5. Check proposed responses against the automation ACL.
6. Store the decision and audit record.

### Observed example output

```text
V2 STAGE 5 ACCESS POLICY: requests=9 decisions=9 new=9 existing=0 allow=2 deny=4 challenge=2 restrict=1
```

A repeated run produced:

```text
V2 STAGE 5 ACCESS POLICY: requests=9 decisions=9 new=0 existing=9 allow=2 deny=4 challenge=2 restrict=1
```

### Testing Notes

Thirteen Stage 5 tests passed. Every request retained one unique decision. Approved VPN evidence did not bypass unrelated role, device, MFA or risk rules.

### Engineering observations

Policy priority and restrictive tie-breaking were made explicit. Proposed account restriction remained approval-required and was not executed.

### What I Learned

An access decision must explain its evidence and policy without gaining permission to perform a response.

---

## Stage 6 — Network, Wi-Fi and Access Monitoring

### What the component does

Stage 6 detects suspicious network and wireless activity, produces access decisions and stores a connection timeline.

### Why it exists or how it behaves

One event can match several conditions. The detector preserves matching reasons while producing one deterministic decision.

Wireless scenarios use simulated logs. No wireless attack, firewall change or external network action is performed.

### Information, rules and capabilities

- Suspicious IP, allowlist and blocklist matching
- Port scans, repeated connections and abnormal activity
- Restricted ports, services and wired access
- Unknown devices and possible MAC reuse or spoofing indicators
- WPA3 violations and simulated WPA2 downgrades
- Rogue-access-point and Wi-Fi zone indicators
- Approved VPN and testing exceptions
- Allow, Deny, Challenge and Restrict decisions
- Connection timeline and false-positive review

Decision precedence is Deny, Restrict, Challenge, Allow. MAC addresses remain supporting evidence.

### Workflow

1. Load network and Wi-Fi events.
2. Evaluate addresses, connection patterns, ports and services.
3. Match device context and check wireless policies.
4. Apply approved exceptions.
5. Create alerts and one decision per event.
6. Check proposed responses against the ACL.
7. Store duplicate-safe results and authorised reviews.

### Observed example output

```text
V2 STAGE 6 NETWORK MONITORING: events=34 alerts=18 new_alerts=18 existing_alerts=0 decisions=34 new_decisions=34 existing_decisions=0 timeline_new=34 timeline_existing=0 allow=4 deny=18 challenge=11 restrict=1 vpn_exceptions=1 testing_exceptions=1
```

### Testing Notes

Twenty-seven network and seven Wi-Fi events produced 18 alerts, 34 decisions and 34 timeline records. Repeated monitoring created no duplicates.

The focused group passed 23 tests. An Analyst closed the controlled Abnormal Connection Pattern alert as a False Positive, preserving its evidence and audit history.

### Engineering observations

A fixed decision order resolved conflicting conditions. The Restrict response was mapped to the existing approval-required `apply_ubuntu_firewall_rule` action rather than an identity action.

### What I Learned

Several valid findings can support one final decision. A network decision does not automatically authorise a network change.

---

## Stage 7 — Endpoint Monitoring and Investigation

### What the component does

Stage 7 evaluates endpoint, device, process, user and activity evidence. It stores alerts, an activity timeline, simulated isolation records and investigation outcomes.

### Why it exists or how it behaves

Endpoint health or a process name alone cannot explain all suspicious activity. The engine evaluates several rules and retains the evidence behind each finding.

Critical alerts for the same device support one consolidated isolation request. Approval changes only the project record; it performs no real isolation.

### Information, rules and capabilities

- Endpoint health, compliance and device-risk states
- Suspicious or unapproved processes and unexpected owners
- Suspicious parent-child process relationships
- High CPU activity
- Three process crashes or restarts within eight minutes
- Suspicious command and possible persistence indicators
- Unexpected file-hash changes
- Exact administrative and testing exceptions
- Endpoint timeline and simulated post-isolation activity
- Authorised isolation approval and false-positive review

Isolation uses the existing `quarantine_device` ACL action. Requests begin as `approval_required`. An authorised Responder or Administrator can record `simulated_isolated`.

Network changes, process termination and real device isolation remain disabled.

### Workflow

1. Load accepted endpoint events and device inventory.
2. Evaluate health, compliance, risk and process rules.
3. Apply exact approved exceptions.
4. Store alerts and timeline evidence.
5. Consolidate Critical alerts into a device-level request.
6. Record authorised simulated approval.
7. Continue evaluating controlled endpoint activity.
8. Record alert investigation without deleting evidence.
9. Repeat monitoring and verify stored states remain unchanged.

### Observed example output

After approval, the runner reported the stored state:

```text
[ISOLATION RECORD] device=CYOD-002 | action=quarantine_device | status=simulated_isolated | approved_by=responder01 | real_action=False | network_change=False
```

Repeated monitoring produced:

```text
V2 STAGE 7 ENDPOINT MONITORING: events=26 alerts=26 new_alerts=0 existing_alerts=26 detection_types=13 critical=10 high=13 medium=3 low=0 timeline_new=0 timeline_existing=26 isolation_requests=1 isolation_new=0 isolation_existing=1 approved_exceptions=2 real_actions=0 network_changes=0
```

### Testing Notes

Seventeen Stage 7 tests passed.

The controlled dataset produced 26 alerts across 13 detection types and 26 unique timeline records. One isolation record preserved all 10 Critical alert keys. Two approved exceptions created no alerts.

Analyst isolation approval and Viewer alert review were rejected. Responder approval succeeded; repeated approval was rejected.

An Analyst reviewed the crash-and-restart alert as a False Positive and closed it. Repeated monitoring preserved the classification, notes and isolation approval.

Post-isolation detection uses controlled simulated activity context; it does not prove a real device disconnection.

### Engineering observations

The first run created 10 isolation requests for one device. They were consolidated into one request while preserving supporting alert keys.

An unsupported approval status failed the database constraint. The implementation was corrected to use the established `simulated_isolated` value.

The runner initially displayed a calculated pending status after approval. It was corrected to read the stored record.

### What I Learned

Several Critical alerts can support one response request without losing evidence.

The complete database definition and stored state must agree with approval logic and printed output. A reached detection threshold still requires investigation rather than an assumed malicious cause.

---

## System Validation

### Clean-state validation workflow

The project’s validation sequence covers:

1. Compile Python source.
2. Initialise the foundation and apply repeatable migrations.
3. Generate and import controlled events.
4. Run device, identity, access-policy, network and endpoint monitoring.
5. Record controlled reviews and simulated isolation approval.
6. Repeat imports, monitoring and storage checks.
7. Run focused tests and the complete unit-test suite.
8. Run V2 Stage 1–7 validators.
9. Run the original Phase 3 full-project validator.
10. Check database integrity, foreign keys, permissions and repository whitespace.

The final Stage 7 regression checked the populated project database. Earlier clean-state checks remain part of the original Phase 3 validation.

### Genuine end-to-end results

```text
V2 STAGE 1 VALIDATION: PASS (12/12)
V2 STAGE 2 VALIDATION: PASS (13//13)
Stage 3 validation: 19/19 checks passed
V2 STAGE 4 VALIDATION: PASS (12/12)
V2 STAGE 5 VALIDATION: PASS (14/14)
V2 STAGE 6 VALIDATION: PASS (15/15)
V2 STAGE 7 VALIDATION: PASS (14/14)

Ran 191 tests in 2.060s

OK

STAGE 11 VALIDATION: PASS
```

SQLite integrity returned `ok`; the foreign-key check returned no violations. Python compilation and `git diff --check` completed without errors.

Earlier Stage 4–5 regression result:

151 tests passed with zero unclosed-database warnings.

The Stage 11 result belongs to the original Phase 3 project. It does not indicate completion of V2 Stage 8.

### Problems discovered

The main integration problems involved inconsistent inventory context, incomplete source-name recognition, existing-database upgrades and validators checking unrelated or repeated evidence.

Decision work also exposed conflicting policy outcomes, an unsuitable network-response mapping, repeated isolation requests and disagreement between calculated and stored response state.

### How the problems were fixed

Authoritative records were aligned, source recognition was corrected and repeatable migrations were added.

Validators were limited to distinct, stage-specific evidence. Policy precedence and ACL mappings were clarified. Endpoint requests were consolidated, the established approval status was reused and the runner was changed to report stored state.

### Engineering observations

Repeated execution confirmed more than duplicate protection: it also preserved closed reviews, approval details and original evidence.

Later-stage data was not removed simply to satisfy earlier validators. Their evidence boundaries were corrected instead.

### What I Learned

A working upgrade requires configuration, database constraints, security rules, validation and operational output to agree.

Findings are easier to investigate when their reasons, exceptions, review history and response permissions remain visible.

### Next expansion scope

Stage 8 will add asset-linked vulnerability and application-security findings, prioritisation, remediation tracking, review and evidence linking.

Its saved preparation is not a completed implementation. A vulnerability alone will not automatically become an incident; exploitation activity or other supporting evidence is required.

The project remains local, controlled and simulated.
