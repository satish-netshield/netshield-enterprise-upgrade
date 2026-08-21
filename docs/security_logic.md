# Security Logic

## Default deny

Access, automation and event processing are allowed only when explicitly defined.

Unknown roles, permissions, actions, event sources and invalid fields are denied.

## Role-Based Access Control

- Viewer: views alerts and closed reports.
- Analyst: investigates incidents and classifies false positives.
- Responder: performs approved containment and records recovery.
- Administrator: manages rules, roles, inventories and configuration.

Application RBAC controls NetShield decisions. It does not create separate Ubuntu users.

## Automation-action ACL

- Automatic: alert creation, evidence hashing, log preservation and simulated monitoring actions.
- Approval required: account restriction, session revocation, process termination, device quarantine and firewall changes.
- Manual only: credential resets, physical-device removal and infrastructure changes.

Undefined actions are denied.

## CYOD allowlist

The CYOD inventory identifies approved test devices.

The allowlist checks the device record, MAC address, hostname, assigned user and approval status. A MAC address supports inventory matching but does not prove identity because it can be spoofed.

An approved device is not automatically approved in every physical or Wi-Fi zone. Stage 4 will add heat-map and zone policy.

## IP and VPN decisions

The blocklist is checked before the allowlist. An address present in both lists is treated as blocked until investigated.

Malformed IP addresses are rejected.

Known approved VPN addresses are treated as exceptions for selected baseline and impossible-travel checks. A VPN exception explains a known route but does not prove the user’s physical location.

## Event-source control

Stage 2 accepts only authentication, network, Wi-Fi, endpoint and application events.

The source type must match the source filename. Unsupported or incorrectly labelled events are rejected.

## Event validation

Every accepted event requires:

- Event ID
- Timezone-aware event timestamp
- Source type
- Event type

Timestamps are converted to UTC so later detection uses one consistent timeline.

IP addresses, MAC addresses and CPU values are validated before storage. Invalid values are rejected rather than silently corrected.

## Rejected data

Malformed data is kept out of the accepted-event table.

The rejected record preserves its source filename, line number, original input and failure reason. This supports troubleshooting and prevents invalid data from influencing detection.

## Duplicate event protection

The source filename and source event ID must be unique.

The first valid event is accepted. A later copy is rejected and preserved as a duplicate.

## Identity detection logic

Stage 3 groups authentication events by user, address and time window.

The current rules detect:

- Three failed logins within the configured window: Repeated Failed Logins — Medium.
- Five failed logins within the configured window: Possible Brute Force — High.
- A successful login after repeated failures: Successful Login After Failures — High.
- Repeated MFA failures: MFA Failure Anomaly — High.
- A device outside the user baseline: Login From New Device — Medium.
- A location outside the user baseline: Login From Unusual Location — Medium.
- Unrealistic movement between successful logins: Impossible Travel — High.
- An unauthorised role change: Suspicious Role Change — Critical in the current baseline.

These are initial rule-based severities, not a final numerical risk score.

## Correlated severity

A single detection may require investigation before escalation.

Impossible travel combined with MFA failure, brute force, a successful suspicious login or unauthorised privilege escalation should be considered for Critical severity.

Suspicious role changes should be assessed according to the actual privilege change and authorisation rather than always being treated as Critical.

## Alert protection

A deterministic SHA-256 alert key prevents the same detection pattern from creating duplicate alert rows.

This controls alert flooding, but it does not yet provide complete tracking for an unresolved condition. Future logic should update last-seen time, observation count, escalation state and alert reopening.

## False-positive handling

A new-device alert is not automatically proof of compromise.

The replacement laptop was authorised but had not yet been registered in the CYOD inventory. The alert was preserved, investigated and classified as a false positive with an audit record.

The correct follow-up is to verify and register the device, then recheck the detection.

## Raw events and evidence

Accepted events retain normalised fields and their original JSON.

Stage 1 evidence uses SHA-256 hashing and protected file permissions. Stage 3 uses SHA-256 alert keys for duplicate protection; it does not yet hash every alert as separate preserved evidence.

## Parameterised SQL

Event values are passed separately from SQL statements.

This treats input as data rather than executable SQL syntax.

## Sandbox boundaries

- Testing remains inside Ubuntu VirtualBox.
- Simulated events do not target real external systems.
- SQL injection testing will use only the local test application.
- Containment begins as a simulation.
- Disruptive actions require approval.
- The Windows host and public systems remain outside scope.
