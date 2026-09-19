# NetShield Enterprise Upgrade

Phase 3A V2 extends the original NetShield Phase 3 Automation project into a controlled enterprise-security simulation.

The project runs inside an Ubuntu VirtualBox sandbox using Python, SQLite and simulated security data. Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design references only. No production service, external target or real response action is used.

NetShield is my project and part of my engineering journey. Its scope, security logic, configuration, testing, validation, improvements and documentation are recorded here without claiming personal source-code authorship.

---

## Project boundary and controls

The project keeps the following boundaries:

- local Ubuntu sandbox only
- simulated users, devices, assets and security events
- default-deny response controls
- RBAC and automation ACL enforcement
- approval required for disruptive actions
- original evidence preserved
- duplicate-safe storage
- UTC timestamps
- SQLite integrity checks
- no automatic real-world response

The project grows one controlled component at a time and keeps earlier controls available.

---

## Enterprise foundation

### What it does

The foundation adds simulated enterprise users, devices, applications and services to the original project.

### Why it exists

Security decisions need authoritative identity, asset and service context. Retention and sensitive-field policies also protect stored data.

### Main capabilities

- enterprise context and CYOD inventory
- simulated RBAC users and roles
- retention settings
- sensitive-field masking
- SQLite metadata and audit records
- compatibility with the original Phase 3 controls

### Testing notes

Stage 1 validation passed 12/12 checks. The foundation remained compatible with the original project.

### What I learned

An extension is safer when it reuses the existing controls instead of creating a second security model.

---

## Extended security data pipeline

### What it does

The pipeline imports controlled JSONL security events from multiple enterprise-style sources.

### Why it exists

Different security sources need one consistent storage and validation process.

### Workflow

1. Validate the source and required fields.
2. Check data types and schema version.
3. Convert timestamps to UTC.
4. Preserve the raw event.
5. Store accepted data in normalised form.
6. Quarantine malformed records.
7. Ignore duplicates.
8. Record batch totals, failures and audit events.

### Testing notes

Stage 2 validation passed 13/13 checks. Twelve valid events were stored and two malformed events were quarantined.

### Engineering observation

Compound source names were initially shortened incorrectly. Source handling was corrected to retain the complete name. Repeated malformed input was also made duplicate-safe.

### What I learned

Raw preservation and normalised storage serve different purposes and both are needed for investigation.

---

## Asset and device identity

### What it does

The component compares device events with the authoritative CYOD inventory.

### Why it exists

A device decision should use registration, ownership, compliance, asset and last-seen evidence rather than one identifier alone.

### Main rules

- device and asset IDs are primary identity evidence
- MAC addresses are supporting evidence only
- unknown and unregistered devices remain separate
- stale and mismatched states are preserved
- device history is not deleted

### Observed output

Three relevant events produced one High-severity Unregistered Device alert for `CYOD-003`. Approved `CYOD-002` activity produced no false alert.

### Testing notes

Stage 3 validation passed 19/19 checks. Device and web assets were not incorrectly treated as devices.

### What I learned

A MAC address can support an investigation, but it cannot identify a device by itself.

---

## Identity monitoring

### What it does

Identity monitoring detects suspicious authentication and account activity.

### Why it exists

A single sign-in may look normal, while a pattern across time, user, source address, device and location may require investigation.

### Detection areas

- repeated failed logins
- password spraying
- successful login after failures
- impossible travel
- new-device sign-in
- unusual location
- abnormal access time
- MFA failure or fatigue
- privilege changes
- dormant-account activity
- service-account interactive login
- multiple accounts from one source
- risky sign-in and user-risk activity

### Workflow

Events are grouped by user, source address and time window. Device, location, MFA, privilege and account evidence are then evaluated. Approved VPN and controlled-testing exceptions remain narrow and auditable.

### Observed output

Twenty-four events produced 16 identity alerts. One abnormal-access-time alert was reviewed as a False Positive with investigation notes.

### Testing notes

Stage 4 validation passed 12/12 checks. A repeated detector run created no duplicate alerts.

### Engineering observation

Normal sign-in times initially fell outside the configured normal period. The event times were corrected before final validation.

### What I learned

Detection data must agree with the configured baseline before alert results can be interpreted.

---

## Access-policy decisions

### What it does

The policy engine evaluates whether a controlled access request should be allowed, denied, challenged or restricted.

### Why it exists

Access decisions need identity, role, device, application, location, network, MFA and risk evidence together.

### Outcomes

- `allow`
- `deny`
- `challenge`
- `restrict`

The default outcome is `deny`.

### Decision model

Policies use priority values. When outcomes have equal priority, the more restrictive result wins:

`deny → restrict → challenge → allow`

The policy decision is stored separately from any response action. Approval-required actions are not executed automatically.

### Observed output

Nine requests produced:

- 2 allow
- 4 deny
- 2 challenge
- 1 restrict

### Testing notes

Stage 5 validation passed 14/14 checks. Repeated evaluation created no duplicate decisions.

### What I learned

A decision is easier to investigate when the winning policy, matching reasons and supporting evidence are stored together.

---

## Network and Wi-Fi monitoring

### What it does

The component evaluates network connections, wireless events and simulated access decisions.

### Why it exists

Network activity needs context from addresses, ports, services, devices, access zones and Wi-Fi security.

### Main rules

- check allowlists, blocklists and approved networks
- inspect ports, services and connection volume
- match device and asset context
- use MAC addresses only as supporting evidence
- preserve approved VPN and testing exceptions
- store one explainable decision per event

Decision precedence is:

`deny → restrict → challenge → allow`

### Observed output

Thirty-four events produced 18 alerts and 34 access decisions.

### Testing notes

Stage 6 validation passed 15/15 checks. Repeated monitoring created no duplicate alerts, decisions or timeline records.

### Engineering observations

A MAC-reuse rule name, overlap rule and response mapping were corrected before validation. No real firewall or wireless state was changed.

### What I learned

One event can match several rules. Every matching reason should be preserved while one final decision is selected.

---

## Endpoint monitoring

### What it does

Endpoint monitoring evaluates health, compliance, processes, command activity, persistence indicators, hashes and crash patterns.

### Why it exists

Endpoint evidence helps distinguish normal administration, operational problems and suspicious activity.

### Main rules

- three crashes or restarts within eight minutes form the configured pattern
- approved administration and testing exceptions remain recorded
- Critical alerts are consolidated by device
- simulated isolation requires authorised approval
- approval changes the project record only

### Observed output

Twenty-six events produced 26 alerts across 13 detection types. One simulated isolation preserved all 10 supporting Critical alert keys.

### Testing notes

Stage 7 validation passed 14/14 checks. Approved activity created no false alerts.

### Engineering observation

Separate isolation requests were initially created for one device. They were consolidated into one device-level request while preserving all supporting alerts.

### What I learned

Detection, approval and isolation are separate controls and should not be combined.

---

## Vulnerability and application-security findings

### What it does

The vulnerability component stores findings linked to the authoritative sandbox asset and tracks remediation and review.

### Why it exists

A vulnerability finding is risk evidence, not automatic proof that an attack occurred.

### Priority model

The score uses:

- severity
- exploitability
- asset criticality
- exposed-service context
- confidence

### Main rules

- findings require authoritative asset context
- original risk evidence is preserved
- remediation adds status and verification history
- approved testing remains evidence
- alert or incident links require supporting activity
- a vulnerability alone does not create an incident
- false-positive review requires authorised investigation permission

### Observed output

Sixteen events produced seven findings. Final remediation states were one Open, two Planned, three Verified and one False Positive.

### Testing notes

Stage 8 validation passed 16/16 checks. Repeated runs preserved remediation and review state.

### Engineering observations

Verification data initially replaced original risk values. The logic was corrected to preserve the original evidence. Display output was also corrected to show the stored False Positive state.

### What I learned

Remediation and verification add history; they must not rewrite the original finding.

---

## Continuous monitoring and risk scoring

### What it does

The monitoring engine assesses current risk across users, devices, assets and incidents on a scheduled interval.

### Why it exists

One-time detection does not show how risk changes over time.

### Scoring model

The score combines:

- severity
- confidence
- asset criticality
- independent-source agreement
- validated exceptions
- time-based decay

Risk scores support decisions but do not replace source evidence.

### Main rules

- unknown criticality contributes zero points
- repeated source records do not receive agreement credit twice
- validated exceptions reduce risk
- older evidence receives configured decay
- threshold alerts use cooldown
- health records track processed data, failures and last success

### Observed output

The engine assessed 171 evidence mappings and scored 20 entities. Four High-risk alerts were created. Seven monitored components reported healthy status.

### Testing notes

Stage 9 validation passed 20/20 checks. A repeated cycle suppressed the same four alerts during cooldown without deleting evidence.

### Engineering observation

Three mappings contained unknown asset criticality. They were intentionally assigned zero criticality points rather than being treated as Low.

### What I learned

Risk scoring is useful only when its evidence and history remain inspectable.

---

## XDR-style cross-source correlation

### What it does

The correlation engine combines related identity, access, network, endpoint, application and vulnerability evidence.

### Why it exists

Cross-source context can improve confidence, but unrestricted grouping can create misleading incidents.

### Correlation model

Primary anchors are evaluated in a controlled order, including:

- device ID
- asset ID
- username
- IP address
- hostname
- process name
- file hash

MAC address, location and detection type remain supporting context.

Explicit exploitation links can join directly related evidence. Repeated source events are scored once.

### Observed output

The corrected engine produced:

- 10 candidate groups
- 3 incidents
- 65 evidence links
- 10 IoCs
- 3 MAC supporting observables

The `CYOD-001`, `CYOD-002` and `CYOD-003` chains remained separate.

### Testing notes

Stage 10 validation passed 20/20 checks. Repeated correlation created no duplicate incidents, links or indicators.

### Engineering observation

The first run used unrestricted transitive grouping and mixed separate device chains. Ordered primary anchors corrected the problem.

### What I learned

Correlation must explain both why evidence was joined and why unrelated evidence remained separate.

---

## Incident management

### What it does

Incident management converts correlated activity into traceable managed incidents.

### Why it exists

An incident needs ownership, decisions, lifecycle history, evidence integrity and readable output.

### Main capabilities

- unique incident IDs
- source incident keys
- severity and confidence
- risk provenance
- identity, device, asset and network context
- owner and status
- investigation notes
- analyst decisions
- IoCs and behaviours
- ATT&CK references
- vulnerability links
- evidence references and SHA-256 hashes
- approval and timeline records
- JSON and readable reports

### Lifecycle

`New → Triaged → Investigating → Contained → Eradicated → Recovered → Closed`

False-positive closure is allowed only from New, Triaged or Investigating with authorised permission.

Containment, eradication and recovery are recorded only when those actions genuinely occur.

### Observed output

Three XDR incidents were imported. One incident was assigned to `analyst01` and progressed from New to Triaged to Investigating.

### Testing notes

Stage 11 validation passed. Evidence hashes, SQLite integrity, foreign keys, lifecycle records, permissions, reports and audit records were valid.

### Engineering observations

A vulnerability foreign-key mismatch, overly strict lifecycle check and report-generation mismatch were corrected through validation and repeat testing.

### What I learned

An incident status must describe what genuinely happened. It must not imply that an action occurred without supporting evidence and verification.

---

## System Validation

### Clean-state validation workflow

The completed project is checked through:

1. Python syntax compilation.
2. Stage-specific validators.
3. Focused component tests.
4. Full regression tests.
5. SQLite integrity and foreign-key checks.
6. Duplicate-run checks.
7. RBAC and ACL checks.
8. Evidence and audit checks.
9. Final working-tree review.

Operational warning checks are documented in `docs/commands.md`.

### Result

**151 tests passed with zero unclosed-database warnings.**

The completed validation confirmed that the security stages remained operational, original evidence was preserved, duplicate handling worked, permissions were enforced and real-world response actions remained disabled.

### Problems and fixes

The project exposed problems in inventory consistency, source naming, event timing, decision precedence, response mapping, duplicate handling, remediation preservation, correlation grouping, foreign-key design, lifecycle validation and report stability.

Each problem was corrected and revalidated against the affected component.

### Engineering observations

The project became more reliable when decisions were deterministic, evidence remained inspectable and output was compared with stored state.

### What I learned

Security automation is not only about detecting conditions. It must also preserve evidence, explain decisions, enforce permissions, maintain history and prevent unsupported conclusions.

### Next expansion

The next stage is approval-controlled containment and response. It will extend the existing ACL while preserving evidence before disruptive actions, requiring approval, preventing self-approval, recording every outcome and supporting safe rollback where applicable.
