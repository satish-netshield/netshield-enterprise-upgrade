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

- Automatic: alert creation, evidence hashing, log preservation and simulated monitoring.
- Approval required: account restriction, session revocation, process termination, device quarantine and firewall changes.
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

Stage 4 uses MAC address as the primary device identity. IP address, hostname, username, location, time and event type provide supporting evidence.

It detects suspicious IPs, repeated connections, port scanning, unknown devices, MAC reuse, Wi-Fi zone violations, WPA3 violations, WPA2 downgrades and rogue access points.

A restricted location is evidence for investigation, not automatic proof of compromise.

## Endpoint and wired-LAN detection

Stage 5 uses MAC address as the primary endpoint identity.

CPU usage, process name, hostname, username, location, role, switch port, VLAN and event time provide supporting evidence.

Approved CPU stress tests are excluded only when the test identifier, process and approval status match the configured policy.

A location change alone does not prove MAC spoofing. Conflicting identity evidence and overlapping event times are required.

## Severity decisions

Initial stages use rule-based severity labels.

Stage 7 adds configured risk points for detection severity and stronger conditions such as:

- Authentication-bypass evidence.
- Database errors.
- Repeated abnormal activity.
- Unknown endpoint processes.
- Suspicious IP activity.
- Restricted locations.
- Evidence from multiple source types.

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

- Repeated failed logins.
- Repeated connection attempts.
- Unexpected CPU activity.
- Impossible travel.
- Suspicious input.
- Repeated abnormal requests.

An IoC is an observable value. A behaviour describes activity.

## Evidence handling

Accepted events retain normalised fields and original JSON.

Stage 1 uses SHA-256 evidence hashing and protected permissions.

Stages 3–5 use deterministic alert keys. Stage 7 uses deterministic incident keys.

Stage 6 and Stage 7 preserve their request, event and report files for review.

## Testing and engineering notes

The security logic was tested through the existing stage validators and focused unit tests.

Stage 6 validation confirmed the vulnerable query, parameterised remediation, source-IP logging, database-error detection and database integrity.

Stage 7 validation confirmed event grouping, risk scoring, exceptions, IoC extraction and behaviour separation.

During development, the Stage 6 bypass count and cumulative log total did not initially match the clean evidence. The counting logic was corrected and the earlier log was archived before the clean run.

Stage 7 initially treated usernames as IoCs and scored an isolated medium event too strongly. The extraction and scoring logic were corrected before validation.

## Current limitations

- Most project events are simulated.
- The Stage 6 vulnerable function is intentionally retained for demonstration and must not be used in production.
- Pattern-based input detection may not identify every injection technique.
- Source IP does not prove the identity of the requester.
- Risk scoring uses the current learning-project rules and requires further tuning.
- Stage 7 does not yet create incidents in the main NetShield database.
- Controlled incident response remains future project work.

## Sandbox boundaries

- Testing remains inside Ubuntu VirtualBox.
- External targets are not used.
- Real accounts and credentials are not used.
- Automatic containment is disabled.
- Disruptive actions require verification and approval.
- The Windows host and public systems remain outside scope.
