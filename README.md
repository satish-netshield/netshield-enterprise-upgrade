# NetShield Enterprise Upgrade

NetShield Enterprise Upgrade extends the completed NetShield Phase 3 Automation project.

It is a Python and SQLite security-automation project running inside a controlled Ubuntu VirtualBox sandbox.

The project applies enterprise security concepts to simulated users, devices, applications, services, identity risks, access requests and network events.

Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design references only. No Microsoft tenants, cloud resources, production accounts, external targets or real response actions are used.

## Current Project Status

Completed Phase 3A V2 stages:

- Stage 1 — Enterprise project foundation
- Stage 2 — Extended security data pipeline
- Stage 3 — Enterprise asset and device identity
- Stage 4 — Identity monitoring and risk detection
- Stage 5 — Zero Trust and policy-based access decisions
- Stage 6 — Network, Wi-Fi and access monitoring

The original Phase 3 components remain available and operational. Their detailed implementation remains in the original Phase 3 project.

## Technologies

- Ubuntu VirtualBox sandbox
- Python 3
- SQLite
- JSON and JSONL
- Git and GitHub
- Python `unittest`
- Application and audit logging
- SHA-256 evidence hashing

---

## Stage 1 — Enterprise Project Foundation

### What the component does

Stage 1 adds simulated enterprise users, devices, applications and services to the existing NetShield foundation.

It also adds retention settings, sensitive-field masking and V2 project metadata.

### Why it exists or how it behaves

The upgrade reuses the original RBAC roles, automation ACL, database, logging, evidence controls and sandbox boundaries.

This avoids creating a second security model that could disagree with the completed Phase 3 project.

### Information, rules and capabilities

- Viewer, Analyst, Responder and Administrator roles
- CYOD inventory consistency
- Default-deny automation controls
- Retention settings
- Sensitive-field masking
- Evidence preservation
- Safe local testing boundaries
- Phase 3 compatibility checks

Automatic retention enforcement is not implemented yet. Original evidence remains unchanged when sensitive fields are masked in suitable output.

### Workflow

1. Load the existing settings and enterprise context.
2. Reuse the established database and security controls.
3. Register simulated users with the existing roles.
4. Verify registered devices against the CYOD inventory.
5. Apply retention and masking settings.
6. Store V2 metadata and audit records.
7. Revalidate the original foundation.

### Observed example output

```text
PASS: Phase 3A V2 Stage 1 foundation initialised
Simulated users registered: 4
Simulated devices available: 3
Applications and services available: 5

V2 STAGE 1 VALIDATION: PASS (12/12)
```

### Testing Notes

Stage 1 passed 12 out of 12 validation checks.

Repeated initialisation did not duplicate user-role assignments.

### Engineering observations

`CYOD-002` was registered in the enterprise context but missing from the authoritative CYOD inventory. The inventory was corrected and a consistency test was added.

Sensitive configuration permissions were also checked after tracked files were restored or created.

### What I Learned

Enterprise context must agree with the project’s existing authoritative records. Configuration, inventory and database state cannot become separate sources of truth.

---

## Stage 2 — Extended Security Data Pipeline

### What the component does

Stage 2 extends the existing pipeline to process identity-risk, access-policy, database, vulnerability, incident and response events.

It preserves the original authentication, network, Wi-Fi, endpoint and application sources.

### Why it exists or how it behaves

Later security decisions need consistent and traceable data.

Events are validated before acceptance, normalised to UTC and stored with their original evidence. Malformed and duplicate records remain outside the accepted-event table.

### Information, rules and capabilities

- Common event schema
- Schema-version and source-system fields
- Complete source-name recognition
- Required-field and data-type validation
- UTC normalisation
- Malformed-event quarantine
- Duplicate-event protection
- Raw-event preservation
- SQLite investigation indexes
- Import statistics and failed-batch records

### Workflow

1. Apply the repeatable database migration.
2. Generate separate JSONL source files.
3. Validate each event.
4. Convert accepted timestamps to UTC.
5. Store the normalised and original event.
6. Quarantine malformed records.
7. Reject duplicates.
8. Record batch totals, failures and audit events.

### Observed example output

```text
PASS: Generated 14 V2 events
Source files: 6
Expected valid events: 12
Expected quarantined events: 2

V2 STAGE 2 IMPORT: files=6 total=14 accepted=12 rejected=2 failed=0
V2 STAGE 2 VALIDATION: PASS (13/13)
```

A repeated import accepted no duplicate events.

### Testing Notes

Six files contained 14 events. Twelve valid events were accepted and two malformed events were quarantined.

Stage 2 passed 13 out of 13 validation checks.

### Engineering observations

Compound source names were initially shortened incorrectly. Source recognition was corrected to use the complete supported name.

Updating `schema.sql` did not upgrade the working database, so a repeatable migration was added.

Validation was also corrected to count distinct malformed evidence after repeated imports.

### What I Learned

A database upgrade must work with both a new database and one that already contains project data.

Malformed records, duplicate events and complete file failures are different outcomes and should be recorded separately.

---

## Stage 3 — Enterprise Asset and Device Identity

### What the component does

Stage 3 adds stronger device inventory and identity context for later security decisions.

### Why it exists or how it behaves

Device ID and asset ID are the main identity references.

Hostname, user, address, location and MAC address provide supporting evidence. A MAC address is not treated as proof of identity.

### Information, rules and capabilities

- Registered CYOD inventory
- Unknown, unregistered, stale and mismatched device findings
- Duplicate-safe alerts
- Registration history
- Controlled alert review

### Workflow

1. Synchronise the CYOD inventory with SQLite.
2. Match relevant events with device and asset records.
3. Compare observed and expected context.
4. Store duplicate-safe findings.
5. Preserve registration and review history.

### Observed example output

```text
PASS: One meaningful Stage 3 device alert is stored
PASS: CYOD-003 is correctly classified as an unregistered device
PASS: Approved CYOD-002 activity creates no false alert

Stage 3 validation: 19/19 checks passed
```

### Testing Notes

Three relevant events produced one High-severity Unregistered Device alert.

Repeated detection created no duplicate alert.

### Engineering observations

Non-device assets entered the first evaluation and were removed from the device boundary.

`CYOD-003` was corrected from Unknown Device to Unregistered Device because it already existed in enterprise context.

### What I Learned

Reliable device identity requires several matching pieces of evidence. A MAC address can support the result, but it should not decide identity by itself.

---

## Stage 4 — Identity Monitoring and Risk Detection

### What the component does

Stage 4 detects identity and authentication risks and stores alerts with user, device, location, time and risk context.

### Why it exists or how it behaves

A single sign-in may not provide enough information.

Stage 4 combines related events and user baselines to identify repeated failures, shared-source activity, unusual sign-ins and risky account behaviour.

V2 alerts use separate storage so the original Phase 3 identity implementation remains unchanged.

### Information, rules and capabilities

Stage 4 detects:

- Repeated failed logins and possible brute force
- Password spraying
- Successful login after repeated failures
- Multiple accounts accessed from one source
- Impossible travel
- New-device and unusual-location sign-ins
- Abnormal access time
- MFA failure or fatigue
- Suspicious privilege changes
- Dormant-account activity
- Service-account interactive login
- High sign-in and user risk

Each alert retains severity, confidence, reason codes and supporting event evidence.

Known VPN and approved-testing exceptions apply only when the required evidence matches.

### Workflow

1. Load accepted authentication and identity-risk events.
2. Group related events by identity, source and time window.
3. Compare sign-ins with device, location and time baselines.
4. Evaluate MFA, privilege, dormant-account and service-account activity.
5. Apply approved exceptions.
6. Assign severity, confidence and reason codes.
7. Store duplicate-safe alerts.
8. Record detection and review activity.

### Observed example output

```text
V2 STAGE 4 IDENTITY MONITORING: events=24 detections=16 new=16 existing=0 vpn_exceptions=2 testing_exceptions=1
```

A repeated run produced:

```text
V2 STAGE 4 IDENTITY MONITORING: events=24 detections=16 new=0 existing=16 vpn_exceptions=2 testing_exceptions=1
```

The controlled review produced:

```text
PASS: V2 Stage 4 identity alert reviewed
Alert ID: 16
Detection: Abnormal Access Time
Username: viewer01
Classification: False Positive
Status: Closed
Reviewed by: analyst01 (analyst)
```

### Testing Notes

The monitoring and alert-review groups passed 19 tests.

The database retained 16 alerts and 16 unique alert keys after the repeated run.

Stage 4 passed 12 out of 12 validation checks.

### Engineering observations

The first normal events were created outside configured access hours. They were moved inside the approved period, while one deliberate late event remained for the abnormal-time rule.

The resulting controlled alert was reviewed as a False Positive instead of being deleted.

### What I Learned

A correct rule can still produce misleading findings when test data does not match its configured baseline.

Exceptions and false-positive reviews should remain visible and preserve the original alert.

---

## Stage 5 — Zero Trust and Policy-Based Access Decisions

### What the component does

Stage 5 adds a local policy engine that makes explainable access decisions from identity, role, device, application, location, network, MFA and risk evidence.

### Why it exists or how it behaves

A recognised username or valid role is not enough to approve access.

The complete request must satisfy the applicable policy. Unknown applications and unverifiable conditions follow default deny.

This stage applies Zero Trust, RBAC and Conditional Access concepts locally. It does not reproduce Microsoft Conditional Access.

### Information, rules and capabilities

The engine supports:

| Outcome | Meaning |
|---|---|
| Allow | Required conditions were satisfied. |
| Deny | Access was not permitted. |
| Challenge | Stronger verification or evidence was required. |
| Restrict | Access should be limited because of serious risk. |

Every decision records its winning policy, reason codes, evaluated evidence and ACL result.

When policies have equal priority, the more restrictive outcome wins:

1. Deny
2. Restrict
3. Challenge
4. Allow

### Workflow

1. Load the request and supporting identity context.
2. Check temporary restrictions and role permissions.
3. Evaluate location, network, device, MFA and risk evidence.
4. Collect all matching policies.
5. Resolve policy priority.
6. Check the proposed response against the automation ACL.
7. Store the duplicate-safe decision and audit record.

### Observed example output

```text
V2 STAGE 5 ACCESS POLICY: requests=9 decisions=9 new=9 existing=0 allow=2 deny=4 challenge=2 restrict=1
```

A repeated run produced:

```text
V2 STAGE 5 ACCESS POLICY: requests=9 decisions=9 new=0 existing=9 allow=2 deny=4 challenge=2 restrict=1
```

### Testing Notes

The controlled requests produced:

- 2 Allow decisions
- 4 Deny decisions
- 2 Challenge decisions
- 1 Restrict decision

The database retained nine decisions and nine unique decision keys.

Stage 5 tests passed 13 tests. Stage 5 validation passed 14 out of 14 checks.

### Engineering observations

Policy priority and equal-priority conflict handling were made explicit.

An approved VPN bypassed only its matching network restriction. It did not bypass role, device, MFA or risk rules.

Response permissions remained separate from access decisions. The account-restriction action required approval and was not executed.

### What I Learned

An access result needs more than an outcome. Its evidence, winning policy, reason codes and response permission must remain visible.

---

## Stage 6 — Network, Wi-Fi and Access Monitoring

### What the component does

Stage 6 detects suspicious network and Wi-Fi activity and creates explainable access decisions supported by device, connection and policy context.

It also stores a connection timeline and supports controlled false-positive review.

### Why it exists or how it behaves

Network activity can match several security conditions at the same time.

Stage 6 retains every matching rule and reason code, then applies one deterministic outcome.

Wireless-policy and rogue-access-point scenarios use controlled simulated logs. No wireless attack, firewall change or external network action is performed.

### Information, rules and capabilities

Stage 6 detects:

- Suspicious IP addresses
- Allowlist and blocklist matches
- Port scanning
- Repeated and abnormal connections
- Restricted ports and services
- Unknown CYOD devices
- MAC reuse or possible spoofing
- WPA3 policy violations
- WPA2 downgrade attempts
- Rogue access points
- Wi-Fi zone violations
- Unknown wired devices
- Restricted wired access

Every event receives Allow, Deny, Challenge or Restrict.

The decision order is:

1. Deny
2. Restrict
3. Challenge
4. Allow

Device ID and asset ID remain the primary device references. A MAC address remains supporting evidence only.

### Workflow

1. Load controlled network and Wi-Fi events.
2. Compare addresses with approved, restricted and blocked ranges.
3. Evaluate connection counts, ports, services and access times.
4. Match device and asset evidence with the CYOD inventory.
5. Check wireless security, access points and zones.
6. Apply approved VPN and testing exceptions.
7. Create alerts with severity, confidence and reason codes.
8. Produce one access decision for every event.
9. Validate proposed responses against the automation ACL.
10. Store alerts, decisions and timeline records with duplicate protection.
11. Record authorised alert reviews.

### Observed example output

The first monitoring run produced:

```text
V2 STAGE 6 NETWORK MONITORING: events=34 alerts=18 new_alerts=18 existing_alerts=0 decisions=34 new_decisions=34 existing_decisions=0 timeline_new=34 timeline_existing=0 allow=4 deny=18 challenge=11 restrict=1 vpn_exceptions=1 testing_exceptions=1
```

A repeated run produced:

```text
V2 STAGE 6 NETWORK MONITORING: events=34 alerts=18 new_alerts=0 existing_alerts=18 decisions=34 new_decisions=0 existing_decisions=34 timeline_new=0 timeline_existing=34 allow=4 deny=18 challenge=11 restrict=1 vpn_exceptions=1 testing_exceptions=1
```

The controlled alert review produced:

```text
PASS: V2 Stage 6 network alert reviewed
Alert ID: 18
Detection: Abnormal Connection Pattern
Device: CYOD-002
IP address: 192.0.2.20
Classification: False Positive
Status: Closed
Reviewed by: analyst01 (analyst)
```

### Testing Notes

Two source files contained 34 unique events:

- 27 network events
- 7 Wi-Fi events

The detector produced 18 alerts across all 13 configured detection types.

The 34 decisions contained:

- 4 Allow
- 18 Deny
- 11 Challenge
- 1 Restrict

All 34 timeline records remained unique after the repeated run.

One approved VPN event and one approved-testing event were allowed with their exception reasons preserved.

The Stage 6 focused tests passed 23 tests. Stage 6 validation passed 15 out of 15 checks.

### Engineering observations

The first policy did not define which outcome should win when one event matched several rules. A fixed decision order was added.

The first Restrict mapping proposed an identity action. It was changed to the network-related `apply_ubuntu_firewall_rule` action already controlled by the automation ACL.

The rogue-access-point event produced Restrict, but the proposed firewall action remained approval-required and was not executed.

### What I Learned

One event can match several valid security rules. Keeping every reason while producing one predictable outcome makes the decision easier to explain.

A network decision does not automatically authorise a response.

MAC reuse can support an investigation, but it does not confirm device identity or spoofing by itself.

---

## System Validation

### Clean-state validation workflow

The Phase 3A V2 validation followed this sequence:

1. Compile the Python source.
2. Initialise the V2 foundation.
3. Apply the repeatable database migrations.
4. Generate and import controlled source events.
5. Run device, identity, access-policy and network monitoring.
6. Review controlled false-positive alerts.
7. Repeat migrations, detections and policy runs.
8. Run focused tests for each V2 stage.
9. Run the complete unit-test suite.
10. Run the V2 Stage 1–6 validators.
11. Run the original Phase 3 Stage 11 validator.
12. Check SQLite integrity and foreign keys.
13. Check repository whitespace, permissions and staged files.

### Genuine end-to-end results

```text
V2 STAGE 1 VALIDATION: PASS (12/12)
V2 STAGE 2 VALIDATION: PASS (13/13)
Stage 3 validation: 19/19 checks passed
V2 STAGE 4 VALIDATION: PASS (12/12)
V2 STAGE 5 VALIDATION: PASS (14/14)
V2 STAGE 6 VALIDATION: PASS (15/15)

Ran 174 tests

OK

STAGE 11 VALIDATION: PASS

DATABASE INTEGRITY
ok
```

An earlier project-wide correction was verified with 151 tests passed with zero unclosed-database warnings.

### Problems discovered

Testing found genuine integration and decision problems:

- Enterprise context and device inventory did not initially agree.
- Compound source names were identified incorrectly.
- The tracked schema did not upgrade the existing database.
- Repeated malformed inputs affected validator totals.
- Non-device assets entered device evaluation.
- A known unregistered device was classified as unknown.
- Normal identity events were created outside normal access hours.
- A Stage 3 validator searched beyond its intended evidence.
- Access and network-policy conflicts needed deterministic priority.
- The first Stage 6 Restrict mapping used an identity action.

### How the problems were fixed

- Enterprise context and the CYOD inventory were aligned.
- Complete source names were recognised.
- Repeatable migrations were added.
- Validators were limited to distinct and stage-specific evidence.
- Device evaluation was limited to relevant device context.
- Known unregistered activity received its own classification.
- Normal identity events were moved inside the approved period.
- Fixed decision precedence was added.
- The Stage 6 Restrict mapping was changed to an approval-controlled network action.

### Engineering observations

The most important problems appeared where a new stage reused data or assumptions from earlier work.

Valid later-stage evidence was not removed to satisfy an earlier validator. The validator boundary was corrected instead.

Repeated execution confirmed duplicate protection across migrations, accepted events, alerts, access decisions and timeline records.

### What I Learned

Extending a working security project requires compatibility across configuration, data, permissions, validation and runtime behaviour.

Security results are easier to investigate when supporting evidence, reason codes, exceptions and response permissions remain visible.

### Next expansion scope

Later work can use the identity, device, access-policy and network evidence for:

- Wider cross-source correlation
- Vulnerability prioritisation
- Incident creation and investigation
- Approval-controlled response
- Recovery verification
- Continuous monitoring
- Enterprise reporting

The project will remain local, controlled and simulated unless a future phase introduces an explicitly approved integration.
