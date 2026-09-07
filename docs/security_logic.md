# Security Logic

## Project boundary

NetShield Enterprise Upgrade extends the completed NetShield Phase 3 Automation project.

The implementation remains Python and SQLite inside the controlled Ubuntu VirtualBox sandbox. All users, devices, applications, services and security events used by the upgrade are simulated.

Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design references only. The project does not connect to Microsoft services or perform real enterprise actions.

## Default deny

Unknown roles, permissions, actions, event sources and invalid fields are denied.

This prevents unrecognised data or actions from being trusted automatically.

## Role-Based Access Control

NetShield uses four application roles:

- Viewer: views alerts and closed reports.
- Analyst: investigates incidents and classifies false positives.
- Responder: requests and performs approved containment.
- Administrator: manages rules, roles, inventories and configuration.

Simulated V2 users are assigned only to these existing roles.

Application RBAC controls NetShield decisions. It does not create Ubuntu accounts or Microsoft Entra identities.

## Automation-action ACL

Actions use three control levels:

- Automatic: alert creation, evidence hashing, log preservation, simulated blocklisting and increased monitoring.
- Approval required: account restriction, session revocation, process termination, device quarantine and simulated firewall changes.
- Manual only: credential resets, physical-device removal, router changes and access-point removal.

Undefined actions are denied. Disruptive actions require approval.

## Enterprise asset and device identity

The CYOD inventory is the authoritative record of approved enterprise test devices.

Each inventory record can contain:

- Asset ID
- Device ID
- Hostname
- Assigned user
- Ownership
- Device type and manufacturer
- Operating system and version
- MAC and IP addresses
- Location and connection type
- Registration status
- Compliance status
- Risk status
- Asset criticality
- Registration and last-seen dates

Device ID and asset ID provide the main identity references. Hostname, assigned user, IP address, location and other inventory values provide supporting context.

MAC addresses remain supporting evidence only because they can be changed, reused or spoofed.

A device marked as registered in enterprise context must also exist in the authoritative CYOD inventory.

## Device inventory decisions

The tracked CSV inventory and the SQLite device inventory must contain consistent device and asset information.

Device IDs and asset IDs must be present and unique.

Registration, compliance, risk and criticality values must match the controlled values in `device_identity.json`.

The current stale-device threshold is 30 days.

The Stage 3 initialisation can be repeated without creating duplicate inventory records.

## Device identity detection

Stored V2 events are evaluated only when they contain a device ID or an asset ID already associated with the device inventory.

This prevents application, database and web assets from being incorrectly treated as endpoint devices.

Stage 3 detects:

- Unknown Device
- Unregistered Device
- Stale Device
- Inventory Mismatch

An Unknown Device has no matching approved inventory record or known enterprise-device context.

An Unregistered Device is already known to the enterprise context but is not registered in the approved inventory.

A Stale Device has not been seen within the configured 30-day period.

An Inventory Mismatch occurs when observed hostname, username, IP address, location or supporting MAC evidence conflicts with the approved inventory context.

Compatible location descriptions, such as `Auckland` and `Auckland-NZ`, are normalised to prevent unnecessary alerts.

A MAC-address difference may support an Inventory Mismatch investigation. It does not make a device unknown when its authoritative device or asset ID is already recognised.

## Device alert decisions

Device findings are stored in the `device_alerts` table with their detection type, severity, device context, source-event IDs and supporting evidence.

Unknown and unregistered devices currently receive High severity. Stale devices and inventory mismatches receive Medium severity.

Repeatable alert keys prevent the same finding for the same source event from creating duplicate stored alerts.

The controlled Stage 3 run evaluated three relevant V2 device events and retained one meaningful alert: High-severity Unregistered Device activity for `CYOD-003`.

Approved `CYOD-002` activity produced no false device alert after compatible location labels were normalised.

## Device registration and removal

The controlled registration workflow adds a new approved device to the tracked inventory and synchronises it with SQLite.

Duplicate device IDs and asset IDs are rejected.

The removal workflow changes the device registration state to `removed`. It does not delete the inventory record or its history.

Registration and removal actions preserve:

- Device and asset identity
- Previous and new status
- Responsible actor
- Reason
- UTC action time

These records are stored in `device_registration_history`.

## Device alert review

A device alert can be reviewed using these controlled statuses:

- New
- Investigating
- Confirmed
- False Positive
- Closed

The review records the classification, investigation notes and responsible actor.

Review actions are written to the established audit trail. Missing alerts and unsupported statuses are rejected.

False-positive review was tested with a temporary database so the genuine `CYOD-003` alert remained unchanged in `New` status.

## IP and VPN decisions

The blocklist is checked before the allowlist. An address found in both lists is treated as blocked until investigated.

Malformed IP addresses are rejected instead of being silently corrected.

Known VPN addresses may explain selected identity activity. A VPN exception does not prove the user’s physical location or remove the original evidence.

## Data retention

V2 settings define retention periods for:

- Raw events
- Processed events
- Audit records
- Incident reports

These settings establish the retention policy for later components. Stage 1 does not automatically delete expired records.

## Sensitive-field masking

The V2 masking helper protects configured fields such as:

- Passwords
- Access and refresh tokens
- API keys
- Secrets
- Session IDs

The helper works with nested dictionaries and lists. Safe fields remain unchanged.

Raw security evidence is preserved in its original form. Logging and reporting components must apply masking before displaying configured sensitive values.

## Event-source decisions

The original pipeline supports:

- Authentication
- Network
- Wi-Fi
- Endpoint
- Application

V2 adds:

- Identity risk
- Access policy
- Database
- Vulnerability
- Incident
- Response

The original sources remain supported.

The declared source type must match the source filename. Compound names such as `identity_risk` and `access_policy` are matched using the longest supported source prefix.

Incorrectly labelled or unsupported events are rejected.

## Common event schema

Every accepted event requires:

- Event ID
- Timezone-aware event timestamp
- Source type
- Event type

V2 events can also contain:

- Schema version
- Source system
- Severity
- Risk score
- Decision
- User and device context
- Asset, application and service IDs
- Vulnerability finding ID
- Incident ID
- Response action ID

Phase 3 events default to schema version `1.0`. V2 events use version `2.0`.

Only supported schema versions are accepted.

## Event validation

Timestamps are converted to UTC so events from different sources can be compared consistently.

IP addresses, MAC addresses, CPU values and risk scores are validated before storage.

Risk scores must be between 0 and 100. Access and response decisions must use an approved value:

- Allow
- Deny
- Challenge
- Restrict

Severity values are standardised as Informational, Low, Medium, High or Critical.

A severity or risk score supports prioritisation. It is not proof that an incident occurred.

## Rejected data and quarantine

Invalid records remain outside the accepted-event table.

The pipeline preserves:

- Source filename
- Import batch ID
- Line number
- Rejection reason
- Original input
- Quarantine status

Malformed records and duplicate events are recorded separately from accepted security events.

Repeated imports may create new rejection records, but they do not duplicate accepted events.

## File-level failures

A record-level rejection means the file was readable but one event was invalid.

A file-level failure means the file could not be processed, such as an unreadable text encoding. The import batch is marked as failed, and the V2 importer reports the failed file separately.

Testing uses a temporary unreadable file and temporary database so the real project evidence is not changed.

## Duplicate protection

The combination of source filename and source event ID must be unique.

The first valid event is accepted. Later copies are rejected as duplicates.

Alert keys and incident keys also prevent repeated processing from creating duplicate records.

## Database upgrade decisions

Updating `schema.sql` prepares a clean database but does not alter an existing SQLite database.

V2 therefore uses a repeatable migration to add missing columns and investigation indexes to the existing database.

The migration checks the current schema before making a change. Running it again adds zero columns and does not remove Phase 3 data.

## Investigation indexes

The existing indexes support searches by time, event type, username, IP address and MAC address.

V2 adds indexes for:

- Schema version
- Source type and source system
- Device ID
- Incident ID

These indexes support later identity, device and cross-source investigations.

## Identity detection

Phase 3 groups authentication activity by user, address and time window.

It detects:

- Repeated failed logins
- Possible brute-force activity
- Successful login after repeated failures
- MFA anomalies
- New-device sign-ins
- Unusual locations
- Impossible travel
- Suspicious role changes

Known VPN activity and approved replacement devices can be investigated as exceptions or false positives.

Every alert requires investigation before a final conclusion is made.

## Network and Wi-Fi detection

Phase 3 groups related network activity using MAC address, IP address, hostname, username, location and time.

It detects:

- Suspicious IP activity
- Repeated connections
- Port scanning
- Unknown devices
- Possible MAC reuse
- Wi-Fi zone violations
- WPA3 violations
- WPA2 downgrade events
- Rogue access points

A location change alone does not prove MAC spoofing. Conflicting identity evidence and overlapping times are required.

A restricted location is evidence for investigation, not automatic proof of compromise.

## Endpoint and wired-LAN detection

Endpoint decisions use:

- CPU usage
- Process name
- Hostname
- Username
- Location
- Role
- Switch port
- VLAN
- Event time

Approved CPU stress tests are excluded only when the test ID, process and approval status match the configured policy.

Unapproved stress tests, unexpected CPU activity, unknown processes and restricted wired access can create alerts.

## Severity decisions

Initial detections use configured severity labels.

The Phase 3 correlation engine adds risk points for stronger conditions such as:

- Authentication-bypass evidence
- Database errors
- Repeated abnormal activity
- Unknown endpoint processes
- Suspicious IP activity
- Agreement between multiple source types

The final score maps to Low, Medium, High or Critical.

Severity is a prioritisation decision, not proof of compromise.

## SQL injection boundary

The SQL injection lab uses a separate local Python application and SQLite database.

The vulnerable query exists only to demonstrate unsafe string concatenation. It is not suitable for real use.

No external target, public system, real account or real credential is used.

## SQL injection detection

The lab records suspicious input, authentication-bypass attempts, database errors, source IPs, query mode and repeated abnormal requests.

Pattern matching provides evidence for investigation. It does not replace secure query construction.

## Parameterised SQL

The corrected query passes user input separately from the SQL statement:

```sql
WHERE username = ? AND password = ?
```

This treats the input as data instead of executable SQL syntax.

The controlled input that bypassed the vulnerable query was rejected by the parameterised query.

## Cross-source correlation

The Phase 3 correlation engine groups events when they share identity evidence and occur within the configured time window.

Correlation uses:

- Username
- IP address
- MAC address
- Hostname
- Event time

Process, location, source type and detection type provide additional context.

Related events are combined into one incident. Unrelated events remain separate.

V2 schema fields prepare the pipeline for later correlation using device, asset, application, finding, incident and action IDs.

## Correlation exceptions

Approved-device and known-VPN exceptions reduce risk when activity has a verified explanation.

Exceptions do not remove the event or erase its evidence.

One isolated Low or Medium event is not automatically treated as high risk. High or Critical activity is not reduced only because it is isolated.

## IoC extraction

The correlation engine extracts observable values that may support investigation:

- IP address
- MAC address
- Hostname
- Process name

Usernames remain incident context because they identify accounts rather than malicious infrastructure.

## Behaviour classification

Behaviours remain separate from IoCs.

Examples include:

- Repeated failed logins
- Repeated connection attempts
- Unexpected CPU activity
- Impossible travel
- Suspicious input
- Repeated abnormal requests

An IoC is an observable value. A behaviour describes activity.

## Incident management

Phase 3 creates a traceable incident record from each correlated incident.

Each record contains:

- Unique incident ID
- Detection name
- Severity and risk score
- Incident status
- Investigation note
- Analyst decision
- False-positive classification
- IoC list
- Evidence reference
- Action timeline
- Audit information

The implemented lifecycle is:

```text
New → Investigating → Contained → Eradicated → Recovered → Closed
```

Invalid status changes are denied so an incident cannot skip required handling steps.

## Incident evidence

The correlation report is preserved as incident evidence.

A SHA-256 hash is calculated and stored with the incident record. The hash confirms whether the preserved evidence has changed.

Evidence references, investigation notes and analyst decisions remain linked to the incident ID.

Sanitised copies of the Stage 7, Stage 8 and Stage 9 outputs are stored as test fixtures. This allows unit tests to run without depending on ignored runtime files or machine-specific paths.

## False-positive decisions

False-positive information is recorded instead of silently deleting an alert.

The analyst decision explains whether the activity is authorised, unresolved or requires further investigation.

Containment, eradication and recovery are recorded only when those actions occur.

## Controlled containment

Phase 3 supports these simulated containment actions:

- Add an IP address to the simulated blocklist.
- Quarantine an unknown CYOD device.
- Restrict an account temporarily.
- Revoke a simulated session.
- Terminate a suspicious test process.
- Reject a non-compliant Wi-Fi connection.

The action must exist in the ACL. Undefined actions are denied.

Blocklisting is automatic under the current ACL. Other disruptive containment actions require approval.

Every action preserves evidence first and records its approval decision, result and responsible actor.

## Eradication and recovery

The implemented simulated actions include:

- Reset compromised credentials
- Remove unauthorised privileges
- Register an unknown device
- Correct WPA3 configuration
- Remove a simulated rogue access point
- Terminate a suspicious test process
- Replace vulnerable SQL
- Restore simulated accounts, devices and services
- Increase monitoring

After eradication, the original threats are tested again.

The retest confirms that the SQL injection bypass, suspicious process and unauthorised access conditions no longer succeed before the incident reaches `Closed`.

## Evidence handling

Accepted events retain their normalised fields and original JSON.

Evidence handling uses:

- SHA-256 hashing
- Protected local permissions
- Raw-event preservation
- Deterministic alert and incident keys
- Evidence-before-action checks
- Incident-linked evidence references
- Action and audit records
- Post-eradication retesting

Raw evidence is not silently rewritten. Sensitive-field masking applies to suitable displayed or generated output, not the preserved source evidence.

## Current limitations

- Project events, users, devices, applications and services are simulated.
- Retention periods are configured but automated expiry is not implemented yet.
- The masking helper is tested, but every later reporting component must explicitly use it.
- The vulnerable SQL function is intentionally retained for controlled demonstration.
- Pattern-based input detection may not identify every injection technique.
- IP and MAC addresses do not prove user or device identity.
- Risk scoring uses learning-project rules and requires further tuning.
- Incident records are generated from local reports rather than a live case-management platform.
- Containment, eradication and recovery actions do not modify real systems.
- Full Phase 3 validation requires generated runtime evidence, while unit tests use tracked sanitised fixtures.
- Microsoft Entra, Defender, Sentinel and XDR integrations are not implemented.

## Sandbox boundaries

- Testing remains inside Ubuntu VirtualBox.
- Only simulated or approved local data is used.
- External targets are not scanned or contacted.
- Real accounts and credentials are not used.
- The SQL injection database remains separate from the main NetShield database.
- Automatic real-world containment and eradication remain disabled.
- Disruptive simulated actions require approval.
