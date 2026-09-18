# NetShield Enterprise Upgrade Security Logic

## Project boundary

Phase 3A V2 extends the completed NetShield Phase 3 Automation project.

It runs locally with Python and SQLite inside an Ubuntu VirtualBox sandbox. Users, devices, applications, security events and responses are simulated.

Microsoft Entra, Conditional Access, Defender, Sentinel and XDR are design references only. The project does not connect to these services or perform real actions against accounts, devices or networks.

---

## Foundation security decisions

| Decision | Why it exists |
|---|---|
| Default deny | Unknown access conditions, permissions and automation actions must not be accepted automatically. |
| Least privilege | Users receive only the permissions assigned to their Viewer, Analyst, Responder or Administrator role. |
| Existing RBAC reuse | Reusing the Phase 3 roles avoids creating a second permission model. |
| Automation ACL | A detection, score or incident cannot bypass response approval rules. |
| Sandbox-only testing | Controlled local testing prevents effects on external systems. |
| Evidence preservation | Original evidence remains available for investigation and integrity checks. |
| Sensitive-field masking | Passwords, tokens, secrets and session identifiers are hidden from suitable output. |
| Duplicate protection | Repeated imports and processing must not create repeated security records. |
| Separate severity and confidence | Possible impact and strength of evidence are assessed independently. |

---

## Security data decisions

### Common event structure

Different event sources are normalised before storage so they can be investigated together.

The common structure can retain event time, source, user, device, asset, application, address, hostname, location, severity, risk and original evidence.

Missing source fields are not invented.

### Complete source names

Compound names such as `identity_risk` and `access_policy` are matched as complete names.

This prevents an event from being processed under the wrong validation or detection rules.

### UTC timestamps

Accepted timestamps are converted to UTC.

One time standard keeps event ordering, thresholds, correlation windows and risk decay consistent.

### Malformed-event quarantine

Malformed records are excluded from accepted security data.

Their source, line number, rejection reason and original content remain available for review.

### Original evidence

The raw event is stored with the normalised record.

Alerts, findings, decisions, scores and incidents can therefore be traced back to their source evidence.

### Duplicate-safe storage

Accepted events use stable source references. Later records use deterministic keys based on their evidence and purpose.

Repeated runs preserve existing records, reviews and investigation states.

### Repeatable migration

Updating `database/schema.sql` prepares a new database but does not upgrade an existing database.

Repeatable migrations add missing objects without deleting earlier records or recreating existing tables and indexes.

---

## Relevant Stage 3 device decisions

Stage 3 provides device context used by later access, network, endpoint, risk and correlation work.

Device ID and asset ID are the primary identity references. A MAC address is supporting evidence only because it can change, be absent or be copied.

Unknown, unregistered, stale and mismatched devices remain separate conditions. Device removal changes registration state instead of deleting history.

---

## Stage 4 — Identity monitoring

Identity detections use user, source address, device, location, time, MFA, privilege and account-purpose evidence.

| Decision | Why it exists |
|---|---|
| Group related failures | Several failures inside a time window provide stronger evidence than an isolated mistake. |
| Separate brute force and password spraying | Repeated attacks against one account differ from attempts spread across several accounts. |
| Retain success after failures | A later successful sign-in may be connected to the earlier attempts. |
| Compare device and location baselines | New context can increase risk without proving compromise. |
| Check dormant and service accounts | Their expected use differs from normal interactive user accounts. |
| Use narrow VPN and testing exceptions | Approved activity should suppress only the condition it explains. |
| Preserve reviewed alerts | A False Positive classification must not delete the original evidence. |

An authorised Analyst can add investigation notes and classify a supported alert. A Viewer cannot perform the review.

---

## Stage 5 — Policy-based access decisions

Each request is evaluated using identity, role, permission, device, application, network, location, MFA and risk evidence.

| Outcome | Meaning |
|---|---|
| Allow | Required access conditions were satisfied. |
| Deny | Access was not permitted. |
| Challenge | Stronger verification or more evidence was required. |
| Restrict | Serious risk justified a controlled restriction request. |

A recognised account or device is not enough by itself. The complete request must satisfy the applicable policy.

When matching policies have equal priority, the more restrictive result wins:

1. Deny
2. Restrict
3. Challenge
4. Allow

Unknown applications and unsupported conditions follow default deny.

The policy decision and response permission remain separate. Any proposed response must still pass the existing automation ACL.

---

## Stage 6 — Network and Wi-Fi monitoring

Network decisions use IP addresses, connections, ports, services, devices, wireless security and zone evidence.

| Decision | Why it exists |
|---|---|
| Check allowlists, blocklists and networks | Source context helps separate approved, unknown and prohibited traffic. |
| Group scan and connection activity | Related connections provide stronger evidence than one isolated connection. |
| Retain every matching rule | One event can match scanning, restricted-port and network rules at the same time. |
| Apply fixed decision precedence | Deny, Restrict, Challenge and Allow produce a deterministic result. |
| Treat MAC as supporting evidence | A MAC address alone cannot reliably identify a device. |
| Separate decisions from responses | A Restrict result cannot change the real firewall without approval. |
| Preserve connection timelines | Investigators need the original sequence and context. |

Controlled Wi-Fi evidence can identify policy violations, downgrade activity, rogue access points and restricted-zone use.

The project does not inspect, attack or change a real wireless network.

---

## Stage 7 — Endpoint monitoring

Endpoint decisions use device state, process activity, ownership, commands, resource use and file evidence.

| Decision | Why it exists |
|---|---|
| Evaluate health, compliance and risk separately | A device state adds context but does not prove compromise. |
| Check process approval and behaviour | An approved process can still behave unexpectedly. |
| Check owner and parent-child relationships | Process names alone may not explain how execution occurred. |
| Use activity windows | Repeated CPU, crash or restart evidence is stronger than one event. |
| Compare file hashes | An unexpected SHA-256 value shows that observed content differs from the approved baseline. |
| Require exact exception evidence | A familiar process name must not become a general bypass. |
| Continue post-isolation monitoring | Simulated isolation must not hide later controlled activity. |

Repeated crash or restart detection uses three related events within eight minutes.

Critical alerts for one device create one consolidated simulated-isolation request while preserving every supporting alert.

Approval changes only the stored record to `simulated_isolated`. It does not disable networking, stop processes or change firewall rules.

---

## Stage 8 — Vulnerability findings

Stage 8 manages controlled vulnerability, configuration, dependency, package, exposed-service and SQL injection lab evidence.

| Decision | Why it exists |
|---|---|
| Require authoritative asset context | Findings need reliable ownership and asset-criticality information. |
| Keep severity and confidence separate | Potential impact and strength of evidence are different questions. |
| Include exploitability and exposure | A reachable and demonstrable weakness requires different priority from a version-only match. |
| Preserve original risk | Remediation or verification must not rewrite the original finding. |
| Store remediation history | Later status and verification changes must remain traceable. |
| Protect against duplicates | Repeated processing must not create another copy of the same finding or history record. |
| Control false-positive review | Only an authorised investigator can close a supported review candidate. |

A vulnerability does not automatically become an incident.

Finding-to-alert or finding-to-incident links require supporting activity or exploitation evidence. Unexploited findings remain prevention and remediation context.

Approved local testing remains evidence and does not become a vulnerability by itself. External targets are not permitted.

---

## Stage 9 — Continuous monitoring and risk scoring

Stage 9 performs repeated assessment across existing security evidence.

Risk scores support decisions but do not replace the original events, alerts or findings.

### Scheduled assessment

Monitoring uses deterministic 15-minute intervals.

Each cycle records its status, processed evidence, scored entities, alerts, component health and last successful run.

A completed interval is not processed again unless a controlled repeat is requested.

### Risk entities

Scores are calculated separately for:

- Users
- Devices
- Assets
- Incidents

This prevents evidence about one entity type from silently becoming risk for another.

### Risk calculation

Risk uses:

- Severity
- Confidence
- Asset criticality
- Independent source agreement
- Validated exception reductions
- Time-based decay

Independent sources can increase risk when they support the same entity. Repeated evidence from one source does not receive the independent-source bonus.

Unknown asset criticality adds zero points. It is not treated as Low.

### Exceptions and decay

Only completed, supported exception or false-positive reviews can reduce risk.

An unreviewed record does not receive an exception reduction.

Older evidence receives configured decay. This changes the current score without deleting or changing the original evidence.

### Alerts and health

Configured thresholds create monitoring alerts.

Repeated alerts during an active cooldown update the existing record instead of creating duplicates. An active alert can close when the current score falls below its threshold.

Monitoring also checks ingestion, identity, access-policy, network, endpoint, vulnerability and risk-assessment health.

Persistent degradation or pipeline failure can create a health alert.

No automatic response action is performed.

---

## Stage 10 — XDR-style correlation

Stage 10 correlates identity, access-policy, network, endpoint, application and vulnerability evidence.

The purpose is to create explainable incidents without merging unrelated activity.

### Correlation anchors

Primary anchors are evaluated in this order:

1. Device ID
2. Asset ID
3. Username
4. IP address
5. Hostname
6. File hash
7. Process

Strong identifiers keep separate device chains apart.

Location, detection type and MAC address provide supporting context but cannot merge unrelated activity by themselves.

### Correlation window

Evidence is evaluated within the configured 2,160-minute window.

Time alone is not enough to create an incident. Records must also share an accepted primary anchor or a supported explicit link.

### Explicit finding links

A supported finding-to-alert or finding-to-incident link can join its named evidence.

This preserves the successful SQL injection relationship without treating every vulnerability as an attack.

Unexploited vulnerabilities remain context and cannot create an incident by themselves.

### Confidence

Independent sources increase confidence when they support the same activity chain.

Repeated detections created from one source event remain available, but that event contributes to scoring only once.

Validated exceptions and verified activity reduce confidence without deleting evidence.

### IoCs and behaviours

Observable IoCs are stored separately from suspicious behaviours.

Supported IP addresses, hostnames, process names and file hashes can be stored as IoCs when their evidence justifies the classification.

Detection names and behaviours remain descriptive labels.

MAC addresses remain supporting observables and are not treated as IoCs or primary identity anchors.

Relevant ATT&CK techniques are preserved where they help explain the observed behaviour. A mapping does not prove that an attack succeeded.

### Incident evidence

Each incident retains:

- Severity and confidence
- Independent source count
- Correlation anchors and reasons
- Active, exception and verified evidence totals
- Original evidence references
- Vulnerability context
- IoCs and supporting observables
- Suspicious behaviours
- Relevant ATT&CK mappings

Repeated correlation preserves existing incidents, evidence links, indicators and investigation state.

No automatic response action is created.

---

## Security checks and improvement

Focused tests and stage validators checked the configured decisions, evidence links, duplicate protection, exception handling and safety boundaries.

Testing found that unrestricted shared values could merge evidence from separate devices. Correlation was corrected to use deterministic primary anchors and explicit exploitation links.

The current scoring weights, decay periods, thresholds, cooldowns, correlation window and anchor order are local engineering choices based on controlled data.

The next improvement is to test them with additional simulated datasets containing longer timelines and more overlapping identities, devices and assets.
