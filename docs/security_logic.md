# Security Logic

## Default deny

Unknown roles, permissions, actions, event sources and invalid fields are denied.

This prevents unrecognised data or actions from being trusted automatically.

## Role-Based Access Control

The project uses four application roles:

- Viewer: views alerts and closed reports.
- Analyst: investigates alerts and classifies false positives.
- Responder: performs approved containment and records recovery.
- Administrator: manages rules, roles, inventories and configuration.

Application RBAC controls NetShield decisions. It does not create separate Ubuntu users.

## Automation-action ACL

Actions use three control levels:

- Automatic: alert creation, evidence hashing, log preservation, simulated blocklisting and increased monitoring.
- Approval required: account restriction, session revocation, process isolation, device quarantine and Wi-Fi rejection.
- Manual only: credential resets, physical-device removal and infrastructure changes.

Undefined actions are denied. Disruptive actions require approval.

## CYOD device decisions

The CYOD inventory identifies approved test devices.

The MAC address is the primary device-matching value. Hostname, assigned user, IP address and location provide supporting evidence.

A MAC address can be copied or spoofed, so it is not treated as proof of identity by itself.

An approved device is not automatically approved in every physical or Wi-Fi zone.

## IP and VPN decisions

The blocklist is checked before the allowlist. An address present in both lists is treated as blocked until investigated.

Malformed IP addresses are rejected instead of being silently corrected.

Known VPN addresses may be treated as exceptions for selected identity checks. A VPN exception explains a known route but does not prove physical location.

## Event-source decisions

The pipeline accepts authentication, network, Wi-Fi, endpoint and application events.

The declared source type must match the source filename. Incorrectly labelled or unsupported events are rejected.

Network and Wi-Fi events are validated separately before they are correlated.

## Event validation

Accepted events require:

- Event ID
- Timezone-aware timestamp
- Source type
- Event type

Timestamps are converted to UTC so events can be compared consistently.

IP addresses, MAC addresses and CPU values are validated before storage.

## Rejected data

Invalid records remain outside the accepted-event table.

The original input, filename, line number and rejection reason are preserved so the problem can be investigated.

## Duplicate protection

The source filename and source event ID must be unique.

The first valid event is accepted. Later copies are rejected as duplicates.

Alert keys and incident keys also prevent repeated processing from creating duplicate records.

## Identity detection

Stage 3 groups authentication activity by user, address and time window.

It detects repeated failures, possible brute force, successful login after failures, MFA anomalies, new devices, unusual locations, impossible travel and suspicious role changes.

These are rule-based detections and require investigation before a final conclusion is made.

## Network and Wi-Fi detection

Stage 4 uses the MAC address as the primary device identity. IP address, hostname, username, location, time and event type provide supporting evidence.

It detects suspicious IPs, repeated connections, port scanning, unknown devices, MAC reuse, Wi-Fi zone violations, WPA3 violations, WPA2 downgrades and rogue access points.

A restricted location is evidence for investigation, not automatic proof of compromise.

## Endpoint and wired-LAN detection

Stage 5 uses the MAC address as the primary endpoint identity.

CPU usage, process name, hostname, username, location, role, switch port, VLAN and event time provide supporting evidence.

Approved CPU stress tests are excluded only when the test identifier, process and approval status match the configured policy.

A location change alone does not prove MAC spoofing. Conflicting identity evidence and overlapping event times are required.

## Severity decisions

Initial stages use rule-based severity labels.

Stage 7 adds configured risk points for detection severity and stronger conditions such as:

- Authentication-bypass evidence
- Database errors
- Repeated abnormal activity
- Unknown endpoint processes
- Suspicious IP activity
- Evidence from multiple source types

The final score maps to Low, Medium, High or Critical.

A severity is a prioritisation decision, not proof of compromise.

## SQL injection boundary

Stage 6 uses a separate local Python application and SQLite database.

The vulnerable query exists only to demonstrate unsafe string concatenation. It is not suitable for real use.

No external target, public system, real account or real credential is used.

## SQL injection detection

Stage 6 records suspicious input, authentication-bypass attempts, database errors, source IPs, query mode and repeated abnormal requests.

Pattern matching provides supporting evidence. It does not replace secure query construction.

## Parameterised SQL

The corrected login query passes input separately from the SQL statement:

```sql
WHERE username = ? AND password = ?
```

This treats input as data instead of executable SQL syntax.

The same controlled injection input that bypassed the vulnerable query was rejected by the parameterised query.

## Stage 7 correlation

Stage 7 groups events when they share configured identity evidence and occur within the configured time window.

Correlation uses:

- Username
- IP address
- MAC address
- Hostname
- Event time

Process, location, source type and detection type provide additional context.

Related events are combined into one incident. Unrelated events remain separate.

## Stage 7 exceptions

Approved-device and known-VPN exceptions reduce risk when the activity has a known explanation.

Exceptions do not remove the original event or erase its evidence.

## Stage 7 isolated activity

One isolated Low or Medium event is not automatically treated as high risk.

The current logic reduces isolated low-value activity when stronger related evidence is absent.

High or Critical activity is not reduced solely because it is isolated.

## IoC extraction

Stage 7 extracts observable values that may support investigation:

- IP address
- MAC address
- Hostname
- Process name

Usernames remain incident context because they identify accounts rather than malicious infrastructure.

## Behaviour classification

Behaviours are kept separate from IoCs.

Examples include:

- Repeated failed logins
- Repeated connection attempts
- Unexpected CPU activity
- Impossible travel
- Suspicious input
- Repeated abnormal requests

An IoC is an observable value. A behaviour describes activity.

## Stage 8 incident management

Stage 8 creates a traceable incident record from each Stage 7 incident.

Each record contains:

- Unique incident ID
- Detection name
- Severity
- Risk score
- Incident status
- Investigation note
- Analyst decision
- False-positive classification
- IoC list
- Evidence reference
- Action timeline
- Audit information

The initial status is `New`. Status changes follow the controlled lifecycle:

```text
New → Investigating → Contained → Eradicated → Recovered → Closed
```

Invalid status changes are denied so an incident cannot skip required handling steps.

## Stage 8 evidence decisions

The Stage 7 report is preserved as Stage 8 evidence.

A SHA-256 hash is calculated for the preserved file and stored with the incident record.

The hash is used to confirm that the preserved evidence has not changed.

Evidence preservation, investigation notes and analyst decisions remain linked to the incident ID.

## Stage 8 false-positive decisions

False-positive fields are recorded instead of silently deleting an alert.

An analyst decision explains whether the activity is authorised, unresolved or still requires investigation.

Stage 8 records the initial incident decision. Later containment, eradication and recovery actions are recorded by their respective stages.

## Stage 9 containment decisions

Stage 9 performs controlled simulated containment for Stage 8 incidents.

The supported actions are:

- Add an IP address to the simulated blocklist.
- Quarantine an unknown CYOD device.
- Restrict an account temporarily.
- Revoke a simulated user session.
- Isolate a suspicious process.
- Reject a non-compliant Wi-Fi connection.

The action must be defined in the allowed action list. Undefined actions are denied.

## Stage 9 approval decisions

Adding an IP address to the simulated blocklist is permitted as an automatic action under the existing ACL.

Device quarantine, account restriction, session revocation, process isolation and Wi-Fi rejection require approval because they can disrupt access or activity.

An action without the required approval fails safely and is recorded as failed.

## Stage 9 evidence-before-action decision

Stage 9 preserves the supporting evidence before every containment action.

The SHA-256 hash is recorded with the action result so the action can be linked to the evidence available before containment.

Evidence preservation occurs whether the action later succeeds or fails.

## Stage 9 action-result decisions

Every containment attempt records:

- Incident ID
- Action name
- Target
- Approval requirement
- Approval decision
- Evidence path
- Evidence SHA-256 hash
- Timestamp
- Success or failure result
- Reason for the result

A failed action remains in the audit trail. It is not treated as successful containment.

## Stage 9 containment boundary

Stage 9 actions are simulated inside the Ubuntu VirtualBox sandbox.

The system does not change a real firewall, device, account, session, process or Wi-Fi network.

Automatic real-world containment remains disabled. Stage 10 performs simulated eradication and recovery separately.

## Stage 10 eradication decisions

Stage 10 records simulated actions intended to remove the cause of the incident after containment.

The implemented actions cover:

- Resetting simulated compromised credentials
- Removing unauthorised privileges
- Registering an unknown device
- Correcting WPA3 configuration
- Removing a simulated rogue access point
- Terminating a suspicious test process
- Replacing vulnerable SQL with parameterised SQL
- Restoring simulated accounts, devices and services
- Increasing monitoring after recovery

Each action preserves the pre-eradication evidence, records its result and writes an audit entry.

## Stage 10 recovery and retesting

After the simulated eradication actions, the original threats are tested again.

The test confirms that:

- The vulnerable SQL injection bypass no longer succeeds.
- The suspicious process is no longer active.
- The unauthorised access conditions are no longer accepted.
- The incident can progress through the controlled lifecycle.

The Stage 10 lifecycle is:

```text
Contained → Eradicated → Recovered → Closed
```

Lessons learned are recorded with the Stage 10 results.

## Evidence handling

Accepted events retain normalised fields and original JSON.

Stage 1 uses SHA-256 evidence hashing and protected permissions.

Stages 3–5 use deterministic alert keys. Stage 7 uses deterministic incident keys.

Stage 8 preserves the Stage 7 report and records its hash with each incident.

Stage 9 preserves evidence before simulated containment and records the result in the containment audit trail.

Stage 10 preserves evidence before eradication and recovery actions and records the retest results.

## Current limitations

- Most project events are simulated.
- The Stage 6 vulnerable function is intentionally retained for demonstration and must not be used in production.
- Pattern-based input detection may not identify every injection technique.
- Source IP does not prove the identity of the requester.
- Risk scoring uses the current learning-project rules and requires further tuning.
- Stage 8 incident records are generated from the Stage 7 report rather than a live incident database.
- Stage 9 containment actions are simulated and do not change real systems.
- Stage 10 eradication and recovery actions are simulated and do not modify real accounts, devices, networks or services.
- Real switch-port, VLAN, physical access and enterprise identity integrations are not available.
- Stage 11 validates the complete project through clean-state checks, regression tests, validators, evidence checks and documentation checks, but it does not replace production monitoring or operational change control.

## Sandbox boundaries

- Testing remains inside Ubuntu VirtualBox.
- External targets are not used.
- Real accounts and credentials are not used.
- The Stage 6 database is separate from the main NetShield database.
- Automatic real-world containment and eradication are disabled.
- Disruptive actions require verification and approval.
