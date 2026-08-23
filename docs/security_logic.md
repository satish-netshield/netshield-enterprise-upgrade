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

The MAC address is the primary device-matching value. Hostname, assigned user, IP address and location provide supporting evidence.

A MAC address does not prove identity because it can be copied or spoofed.

An approved device is not automatically approved in every physical or Wi-Fi zone.

## IP and VPN decisions

The blocklist is checked before the allowlist. An address present in both lists is treated as blocked until investigated.

Malformed IP addresses are rejected.

Known approved VPN addresses are treated as exceptions for selected baseline and impossible-travel checks. A VPN exception explains a known route but does not prove the user’s physical location.

## Event-source control

Stage 2 accepts only authentication, network, Wi-Fi, endpoint and application events.

The event source type must match the source filename. Unsupported or incorrectly labelled events are rejected.

Network and Wi-Fi events are imported separately and correlated after validation.

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

## Network and Wi-Fi detection logic

Stage 4 uses the MAC address as the primary device identity and keeps IP address, hostname, username, location, time and event type as supporting evidence.

The current network rules detect:

- Suspicious IP addresses.
- Repeated connection attempts.
- Port-scanning behaviour.
- Unknown CYOD devices.
- Unregistered MAC addresses.
- MAC reuse or possible spoofing.

The current Wi-Fi rules detect:

- Wi-Fi zone violations.
- WPA3 policy violations.
- WPA2 downgrade attempts.
- Rogue access points.

The Stage 4 Wi-Fi zones are simulated labels. `Lab Zone A` is approved, while `Lab Zone B`, `Parking Lot` and `Public Area` are restricted for testing.

A restricted-zone event is evidence for investigation. It is not automatic proof of compromise.

## Network and Wi-Fi correlation

Related alerts are grouped by MAC address.

The correlation checks:

- IP address
- Hostname
- Username
- Location
- Event time
- Event type

Conflicting identity evidence for one MAC can create a MAC-reuse or possible-spoofing alert.

High-impact detections such as port scanning, WPA3 violations, WPA2 downgrade attempts and rogue access points are preserved during correlation.

## Correlated severity

A single detection may require investigation before escalation.

Impossible travel combined with MFA failure, brute force, a suspicious successful login or unauthorised privilege escalation should be considered for Critical severity.

Suspicious role changes should be assessed according to the actual privilege change and authorisation rather than always being treated as Critical.

A rogue access point is currently classified as Critical because it can expose devices to an unauthorised wireless network.

## Alert protection

A deterministic SHA-256 alert key prevents the same detection pattern from creating duplicate alert rows.

This controls alert flooding, but it does not provide complete tracking for an unresolved condition. Future logic should update last-seen time, observation count, escalation state and alert reopening.

## False-positive handling

A new-device alert is not automatically proof of compromise.

The replacement laptop was authorised but had not yet been registered in the CYOD inventory. The alert was preserved, investigated and classified as a false positive with an audit record.

The correct follow-up is to verify and register the device, then recheck the detection.

## Raw events and evidence

Accepted events retain normalised fields and their original JSON.

Stage 1 evidence uses SHA-256 hashing and protected file permissions. Stage 3 and Stage 4 use SHA-256 alert keys for duplicate protection; they do not yet hash every alert as separate preserved evidence.

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

## Stage 4 integration lessons

- A mixed network and Wi-Fi file caused Wi-Fi records to fail source verification.
- Separate source files preserved the existing Stage 2 collector rules.
- The Stage 4 runner required dynamic SQL placeholders when four source files were supplied.
- The Stage 3 initializer was corrected so Stage 4 setup did not reset completed Stage 3 metadata.
- Stage 4 validation passed 12/12 and the full regression run passed 44 tests.

## Future expansion

The next stage should add:

- Wired LAN checks for restricted areas.
- Server-room and physical-zone privileges.
- Switch-port or VLAN authorisation.
- Endpoint CPU and process correlation.
- Approved CPU stress-test records.
- Continued investigation of MAC reuse and possible spoofing.
