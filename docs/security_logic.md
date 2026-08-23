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

Stage 5 uses simulated role mappings for endpoint and wired-LAN testing because the application role table contains only the project administrator.

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

Stage 5 endpoint events use `endpoint_stage5_events.jsonl`. Wired-LAN events use the `network` source type and are stored in `network_stage5_events.jsonl`.

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

Stage 5 re-import testing rejected all 14 repeated events and did not increase the accepted-event total.

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

## Endpoint and wired-LAN detection logic

Stage 5 uses the MAC address as the primary endpoint identity.

Supporting evidence includes:

- Hostname
- Username
- Process name
- CPU percentage
- Location
- Event time
- Event type
- Wired connection status
- Switch port
- VLAN

The endpoint rules detect:

- Unexpected CPU activity.
- Repeated high CPU activity.
- Unauthorised CPU stress tests.
- Unknown endpoint processes.
- Restricted wired access.
- Possible MAC reuse or spoofing.

Approved CPU stress tests are excluded when the approved test identifier and process match the configured policy.

CPU activity is classified using the configured thresholds:

- Warning CPU activity: 80 percent or higher.
- Critical CPU activity: 95 percent or higher.
- Repeated high CPU activity: three qualifying events within the configured time window.

## Wired-LAN access rules

`Lab Zone A` is approved for the simulated test roles.

The simulated Server Room policy permits responder and administrator access.

Analyst, trainee and unknown-user access to the Server Room creates a High severity restricted-wired-access alert.

A restricted wired event is evidence for investigation. It is not automatic proof of compromise.

Repeated restricted wired observations are grouped only when the MAC address, detection type, location and time window match.

Different MAC addresses remain separate investigations.

## Stage 5 MAC reuse rules

A location change alone does not create a MAC-reuse alert.

Possible MAC reuse requires:

- The same MAC address.
- Conflicting hostname or username evidence.
- Overlapping event times within the configured window.

This prevents a normal movement between zones from being treated as spoofing while still identifying conflicting device identity evidence.

## Correlated severity

A single detection may require investigation before escalation.

Impossible travel combined with MFA failure, brute force, a suspicious successful login or unauthorised privilege escalation should be considered for Critical severity.

Suspicious role changes should be assessed according to the actual privilege change and authorisation rather than always being treated as Critical.

A rogue access point is currently classified as Critical because it can expose devices to an unauthorised wireless network.

Unexpected CPU activity is Critical when it reaches the configured critical threshold.

Unauthorised CPU stress tests, unknown processes and restricted wired access are High severity in the current baseline.

## Alert protection

A deterministic SHA-256 alert key prevents the same detection pattern from creating duplicate alert rows.

This controls alert flooding, but it does not provide complete tracking for an unresolved condition. Future logic should update last-seen time, observation count, escalation state and alert reopening.

## False-positive handling

A new-device alert is not automatically proof of compromise.

The replacement laptop was authorised but had not yet been registered in the CYOD inventory. The alert was preserved, investigated and classified as a false positive with an audit record.

Approved CPU stress testing is also excluded from endpoint alerts when it matches the configured approval record.

The correct follow-up is to verify the device or activity, update the inventory or approval record when appropriate, and recheck the detection.

## Raw events and evidence

Accepted events retain normalised fields and their original JSON.

Stage 1 evidence uses SHA-256 hashing and protected file permissions.

Stage 3, Stage 4 and Stage 5 use SHA-256 alert keys for duplicate protection. They do not yet hash every alert as separate preserved evidence.

## Parameterised SQL

Event values are passed separately from SQL statements.

This treats input as data rather than executable SQL syntax.

Stage 4 required dynamic SQL placeholders when several source files were queried together.

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

## Stage 5 integration lessons

- The initial wired event filename did not match the `network` source type.
- The generator was corrected to create `network_stage5_events.jsonl` directly.
- The endpoint-alert table was added to the tracked schema instead of relying only on runtime initialization.
- Simulated role mappings were added for endpoint and wired-LAN testing.
- A location-only MAC change was rejected as insufficient evidence for spoofing.
- Repeated restricted wired observations were grouped by MAC, detection type, location and time.
- Approved responder access was allowed while analyst access to the Server Room generated an alert.
- Stage 5 validation passed 12/12 and the complete regression run passed 52 tests.

## Future expansion

The next stage should add:

- Last-seen and observation-count tracking.
- Inventory verification tasks for unresolved devices.
- Switch-port and VLAN authorisation checks.
- More endpoint process baselines.
- Controlled containment workflows.
- Incident records and approved response actions.
