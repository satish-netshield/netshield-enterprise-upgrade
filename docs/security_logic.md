# NetShield Enterprise Upgrade Security Logic

## Project boundary

Phase 3A V2 extends the completed NetShield Phase 3 Automation project.

It runs locally with Python and SQLite inside an Ubuntu VirtualBox sandbox. Enterprise users, devices, applications, identity risks, access requests, network events and endpoint activity are simulated.

Microsoft Entra, Conditional Access, Defender, Sentinel and XDR are security design references only. The project does not connect to these services or perform real enterprise actions.

---

## Foundation security decisions

| Decision | Security reason |
|---|---|
| Default deny | Unknown permissions, access conditions and automation actions must not be accepted automatically. |
| Least privilege | Users receive only the permissions assigned to their Viewer, Analyst, Responder or Administrator role. |
| Existing RBAC reuse | Reusing the Phase 3 roles preserves compatibility and avoids creating a second access model. |
| Automation ACL | A security decision cannot bypass the rules controlling whether a response is automatic, approval-required or manual-only. |
| Sandbox-only operation | Controlled local testing prevents the project from affecting external accounts, devices or networks. |
| Evidence preservation | Original evidence remains unchanged so integrity checks and investigation history remain valid. |
| Sensitive-field masking | Passwords, tokens, API keys, secrets and session identifiers are hidden from suitable output. |
| Retention configuration | Different record types have defined retention periods, although automatic deletion is not implemented yet. |

---

## Security data decisions

### Common event schema

Events from different sources are converted into a common structure before being stored.

The schema can retain:

- Event and source identifiers
- Schema version
- Event and received times
- Source system and source type
- Event type and status
- Username
- Device and asset identifiers
- Application and service identifiers
- IP address, MAC address, hostname and location
- Severity, risk and decision context
- Original event evidence

Not every source requires every field. Validation checks the supported schema and required fields without inventing missing context.

This allows different security sources to be searched together without creating false values for fields they do not use.

### Complete source names

Compound source names such as `identity_risk` and `access_policy` are matched as complete names.

Reading only the first filename word would incorrectly classify `identity_risk` as `identity` and could apply the wrong validation logic.

### UTC timestamps

Accepted event timestamps are converted to UTC.

Using one time standard makes sequence, threshold, travel and connection-window calculations consistent across sources.

### Malformed-event quarantine

Malformed events are excluded from the accepted-event table.

Their source file, line number, reason, quarantine status and original content are retained separately.

This prevents invalid data from influencing detections while preserving evidence for review.

### Raw-event preservation

The original event is stored with the normalised record.

This allows a later alert or policy decision to be traced back to the supplied evidence.

### Duplicate protection

Accepted events are protected by their source file and source event ID.

Alerts and policy decisions use deterministic keys based on their supporting evidence.

Connection and endpoint timeline records use the source event ID as their unique reference.

Repeated imports and processing runs therefore do not create duplicate accepted events, alerts, decisions or timeline records.

### Safe database migration

Updating `database/schema.sql` prepares new databases but does not upgrade an existing SQLite database.

Repeatable migrations add missing columns, tables and indexes without deleting earlier records. Running a migration again does not recreate existing objects.

---

## Relevant Stage 3 device decisions

Stage 3 provides device evidence used by later identity, access, network and endpoint decisions.

Device ID and asset ID are the main identity references. A MAC address is supporting evidence only because it can change, be absent or be copied.

The project separates unknown, unregistered, stale and mismatched devices. A known but unregistered device is not treated as completely unknown.

Device removal changes its registration state rather than deleting its inventory and history.

---

## Stage 4 — Identity monitoring and risk detection

Stage 4 evaluates controlled authentication and identity-risk events.

The original Phase 3 identity storage remains unchanged. V2 findings are stored separately with user, device, location, time, risk, severity, confidence, reason-code and investigation context.

### Identity detection decisions

| Detection | Security decision and reason |
|---|---|
| Repeated Failed Logins | Several failures for the same user and source inside the configured window indicate more than an isolated password mistake. |
| Possible Brute Force | A higher failure count for one account and source represents a stronger concentrated attack pattern. |
| Password Spraying Pattern | Failures against several usernames from one source can reveal low-volume attempts spread across accounts. |
| Successful Login After Failures | A success following repeated failures may mean that earlier attempts eventually gained access. |
| Multiple Accounts From One Source | Activity involving several accounts from one suspicious source provides shared-source risk context. |
| Impossible Travel | Consecutive successful logins requiring travel above the configured speed require investigation. |
| New-Device Sign-In | A sign-in from outside the user’s approved device baseline may represent new or unauthorised access. |
| Unusual Sign-In Location | A location outside the user’s normal baseline adds risk context to the sign-in. |
| Abnormal Access Time | A sign-in outside configured normal UTC hours may require review, although legitimate after-hours work is possible. |
| MFA Failure or Fatigue Pattern | Repeated MFA failures may indicate repeated prompts, user error or attempted account access. |
| Suspicious Privilege Change | A role change outside the expected baseline can materially increase account permissions. |
| Dormant-Account Activity | An account marked dormant should not normally perform an interactive login. |
| Service-Account Interactive Login | A service account is expected to perform defined non-interactive work. |
| Risky Sign-In Behaviour | High sign-in risk or high user risk provides direct evidence for stronger investigation or access controls. |

### Severity and confidence

Severity describes the possible security impact.

Confidence describes how strongly the available evidence supports the detection.

Keeping these values separate prevents a strong match from automatically being presented as the highest operational impact.

### Reason codes

Every alert contains a reason code explaining why it was created.

Examples include:

- `REPEATED_FAILED_LOGINS`
- `POSSIBLE_BRUTE_FORCE`
- `PASSWORD_SPRAYING_PATTERN`
- `SUCCESS_AFTER_REPEATED_FAILURES`
- `IMPOSSIBLE_TRAVEL_SPEED`
- `DEVICE_NOT_IN_USER_BASELINE`
- `LOCATION_NOT_IN_USER_BASELINE`
- `ACCESS_OUTSIDE_NORMAL_UTC_HOURS`
- `REPEATED_MFA_FAILURES`
- `ROLE_CHANGE_OUTSIDE_BASELINE`
- `DORMANT_ACCOUNT_USED`
- `SERVICE_ACCOUNT_INTERACTIVE_LOGIN`
- `HIGH_RISK_SIGN_IN`
- `HIGH_USER_RISK`

Reason codes make alerts easier to explain, search and test.

### VPN and testing exceptions

Approved VPN evidence is checked before relevant device, location and impossible-travel alerts are created.

Approved testing evidence can suppress a finding only when it matches the configured test boundary.

Exceptions are counted instead of being silently ignored. They do not bypass unrelated security checks.

### False-positive review

An authorised Analyst can classify an alert, update its investigation status and add notes.

Empty notes, unknown classifications and unknown alert IDs are rejected. A Viewer cannot perform the review.

The alert and its audit history remain available after review.

---

## Stage 5 — Zero Trust and policy-based access decisions

Stage 5 uses local identity, role, device, application, location, network, MFA and risk evidence to make explainable access decisions.

It applies Zero Trust, RBAC and Conditional Access concepts locally. It does not reproduce Microsoft Conditional Access.

### Explicit verification

A valid account or recognised device is not enough by itself.

The engine evaluates:

- User identity and active role
- Requested permission
- Device registration and compliance
- Application sensitivity
- Asset criticality
- Location and network
- Sign-in risk and user risk
- MFA evidence
- Temporary restrictions
- Approved VPN evidence

The complete request must satisfy the relevant policy.

### Least privilege

The requested permission must belong to the user’s assigned role.

A recognised user without the required permission is denied.

Higher sensitivity, criticality or risk can require stronger evidence even when the role normally permits the action.

### Device requirements

Higher-risk access can require a registered and compliant device.

An unregistered or non-compliant device can produce a Challenge decision with separate reason codes:

- `DEVICE_NOT_REGISTERED`
- `DEVICE_NOT_COMPLIANT`

This shows which device conditions were not satisfied.

### Restricted locations and networks

Configured restricted locations and networks produce Deny decisions.

The reason codes are:

- `RESTRICTED_LOCATION`
- `RESTRICTED_NETWORK`

An approved VPN address can bypass the matching network restriction. It does not bypass unrelated role, device, MFA or risk requirements.

### Risk-based controls

Critical identity risk can produce a Restrict decision.

The risk affects the current request. It does not silently change the user’s assigned role.

### MFA requirements

When required MFA evidence is missing, the result is Challenge with `MFA_REQUIRED`.

The project records the challenge and can simulate increased monitoring. It does not send a real MFA prompt.

### Temporary restrictions

An active temporary restriction denies access for the matching user.

Temporary restrictions have the highest policy priority so a general allow policy cannot override them.

### Access outcomes

| Outcome | Meaning |
|---|---|
| Allow | The required access conditions were satisfied. |
| Deny | The request was not permitted. |
| Challenge | Stronger verification or additional evidence was required. |
| Restrict | Access should be limited because of serious risk. |

Every outcome includes its winning policy, reason codes and evaluated evidence.

### Policy priority and conflicts

A lower numeric priority represents a stronger policy.

When policies share the same priority, the more restrictive result wins:

1. Deny
2. Restrict
3. Challenge
4. Allow

This makes the result deterministic and prevents configuration order from creating an accidental Allow decision.

### Default-deny fallback

Unknown applications and unsupported access conditions do not receive an Allow result.

They follow default deny because their security requirements cannot be verified.

### ACL-controlled responses

The access decision and response permission are evaluated separately.

A Challenge can use the approved automatic `increase_monitoring` action.

A Restrict decision can propose `restrict_account`, but that action requires approval and is not executed automatically.

### Decision audit trail

Every stored decision retains the request, identity, device, application, outcome, winning policy, reason codes, evaluated evidence and ACL result.

Deterministic decision keys prevent repeated policy runs from creating duplicates.

---

## Stage 6 — Network, Wi-Fi and access monitoring

Stage 6 evaluates controlled network and Wi-Fi events using IP, connection, device, wireless and zone evidence.

It stores alerts, one access decision for every event and a connection timeline.

### Suspicious IP addresses

Source addresses are compared with:

- The IP allowlist
- The IP blocklist
- Approved networks
- Restricted networks
- The approved VPN list

A blocklist match, restricted-network match or unapproved source can create a Suspicious IP Address alert.

The reason codes show which control produced the finding:

- `IP_BLOCKLIST_MATCH`
- `RESTRICTED_NETWORK`
- `IP_NOT_APPROVED`

### Port scanning

Several unique destination ports from one source inside the configured time window indicate possible scanning.

The rule creates one Port Scanning alert for the related event window.

A scan can also match restricted-port or suspicious-IP rules. All matching reasons are retained for the final decision.

### Repeated connection attempts

Repeated connections from one source inside the configured window can indicate retry activity, probing or an automated attempt.

The rule requires five related connections within two minutes.

The configured network decision is Challenge unless a stronger matching rule takes priority.

### Abnormal connection pattern

Connection volume is compared with the configured time and count thresholds.

Eight related connections within ten minutes outside normal UTC hours create an Abnormal Connection Pattern alert.

This is a review indicator because legitimate maintenance or controlled load testing can also create the pattern.

### Restricted ports and services

Connections involving configured restricted ports or named services are denied.

The controlled rules include:

- Port 23 and Telnet
- Port 445 and SMB
- Port 3389 and RDP

Separate reason codes identify a restricted port and a restricted service.

### Unknown CYOD device

A wireless event containing a device or asset identifier that is not present in the approved inventory creates an Unknown CYOD Device alert.

The decision is Challenge because the device requires further verification.

### Unknown wired device

An unknown device using a wired connection creates an Unknown Wired Device alert.

The decision is Deny because the device identity cannot be verified for wired access.

### MAC reuse or possible spoofing

A MAC address is never treated as proof of device identity.

The rule checks whether different primary device identities use the same MAC address within the configured overlap window.

A match creates a Challenge decision for investigation. It does not automatically state that spoofing has been confirmed.

### WPA3 policy violation

Approved Wi-Fi access requires WPA3 with the configured AES cipher.

A connection that does not satisfy both requirements is denied with `WIFI_SECURITY_POLICY_NOT_SATISFIED`.

The project evaluates controlled log evidence and does not inspect or attack a real wireless network.

### WPA2 downgrade attempt

A controlled event showing a change from WPA3 to WPA2 creates a High-severity downgrade alert.

The decision is Deny because WPA2 downgrade is not allowed by the configured policy.

### Rogue access point

A Wi-Fi event is compared with the approved access-point identifier, SSID and location.

An access point outside that approved context creates a Critical Rogue Access Point alert.

The network decision is Restrict. The proposed firewall action remains approval-required and is not executed.

### Wi-Fi zone violation

Wireless activity in a configured restricted zone is denied.

The location remains in the alert and decision evidence so the result can be investigated.

### Restricted wired access

A wired connection in a restricted physical zone creates a Restricted Wired Access alert and a Deny decision.

This keeps physical network location separate from device identity. An approved device can still be denied in a restricted wired zone.

### Approved exceptions

An approved VPN event can receive Allow when its required identity and connection evidence match.

Controlled testing can also receive Allow when the configured testing user and event evidence both match.

The exception reason is stored in the decision. Exceptions do not silently disable unrelated rules.

### Network-access outcomes

| Outcome | Stage 6 use |
|---|---|
| Allow | Approved connections, verified VPN activity and approved test activity |
| Deny | Prohibited IP, port, service, wireless or zone conditions |
| Challenge | Activity requiring more verification or monitoring |
| Restrict | Serious activity requiring an approval-controlled network response |

### Decision precedence

One event can match several rules.

Stage 6 resolves overlapping outcomes in this order:

1. Deny
2. Restrict
3. Challenge
4. Allow

For example, a port scan from a restricted network matches both Port Scanning and Suspicious IP Address. Deny wins, while both matching rules and reason codes remain in the decision evidence.

### ACL-controlled network responses

A network decision does not automatically authorise a response.

Challenge uses `increase_monitoring`, which is an approved automatic simulated action.

Restrict proposes `apply_ubuntu_firewall_rule`. The existing automation ACL marks this action as approval-required, so no firewall rule is applied automatically.

### Connection timeline

Every accepted Stage 6 event is stored once in the connection timeline.

The timeline keeps the event time, source, user, device, address, connection and location context required to reconstruct the activity sequence.

### False-positive review

An authorised Analyst can classify a Stage 6 alert as Confirmed or False Positive and add evidence-based investigation notes.

The review records the actor and UTC review time. A Viewer cannot perform the review.

The controlled Abnormal Connection Pattern alert was closed as a False Positive after the activity was confirmed as approved connection-volume testing.

---

## Stage 7 — Endpoint monitoring and investigation

Stage 7 evaluates controlled endpoint activity using device, process, user and inventory evidence.

Its alerts, timeline and simulated-isolation records are stored separately from the original Phase 3 endpoint storage.

### Endpoint detection decisions

| Detection | Security decision and reason |
|---|---|
| Endpoint Health State | Degraded, unhealthy or unknown health states require review because protection or telemetry may be incomplete. |
| Device Compliance State | Non-compliant or unknown compliance states identify devices that may not satisfy the expected controls. |
| Device Risk State | High, Critical or unknown device-risk states provide context for investigation; they do not prove compromise by themselves. |
| Suspicious Process | A match against the configured suspicious-process list identifies activity requiring investigation. |
| Unknown or Unapproved Process | A process outside the approved baseline or carrying an unapproved status requires verification. |
| Unexpected Process Owner | A process owner outside the configured baseline may indicate execution under an unexpected account. |
| Suspicious Parent-Child Process Relationship | A configured unexpected process relationship can reveal activity that process names alone would miss. |
| High CPU Activity | Sustained high CPU activity can indicate abnormal execution, although legitimate workloads can produce the same symptom. |
| Repeated Process Crash or Restart | Repeated failures or restarts can indicate instability or suspicious interference and require investigation. |
| Suspicious Command Activity | Configured command indicators identify potentially unsafe behaviour in controlled event evidence. |
| Possible Persistence Indicator | Startup, scheduled-task or service-autostart indicators may represent an attempt to maintain execution. |
| Unexpected File-Hash Change | A hash outside the approved baseline indicates that the observed file content differs from the expected content. |
| Post-Isolation Endpoint Activity | Controlled activity marked as occurring after simulated isolation remains visible for investigation. |

### Activity thresholds

The CPU warning threshold is 80%, and the Critical threshold is 95%. The repeated CPU rule uses three related events within two minutes.

The crash or restart rule uses three related events within eight minutes.

These are fixed local detection thresholds, not universal indicators of an attack. Alerts retain the related events so the pattern can be reviewed.

### File-integrity evidence

SHA-256 hashes are compared with configured approved values.

An unexpected hash change creates an investigation finding. It does not automatically remove, replace or repair the file.

### Administrative and testing exceptions

Exceptions must match the configured administrative or testing evidence.

A familiar process name alone does not permit all activity from that process. Narrow exceptions prevent controlled testing from becoming a general bypass.

### Consolidated simulated isolation

Critical endpoint alerts create one consolidated isolation request per device, retaining all supporting Critical alert keys.

The request uses `quarantine_device` with the existing approval-required automation ACL. Several alerts on one device therefore remain separate findings without creating several identical device-isolation requests.

### Authorised approval

The initial status is `approval_required`.

An active Responder or Administrator with `execute_approved_containment` may record approval. The stored status then becomes `simulated_isolated`.

Approval preserves the supporting alert evidence and records the actor, UTC time and notes. Repeated approval is rejected.

No real isolation occurs. The project does not disable Wi-Fi, block network traffic, terminate processes, enter safe mode or change firewall rules.

### Post-isolation monitoring

Endpoint processing continues after simulated approval.

The post-isolation rule evaluates the simulated isolation context supplied by the controlled logs. It does not verify that a real device has been disconnected.

Repeated processing preserves the existing approved isolation record instead of resetting it to a pending request.

### Endpoint timeline

Every accepted Stage 7 endpoint event is stored once in the activity timeline.

Process, owner, parent, command, CPU, file and device-state evidence remain available to reconstruct the activity sequence.

### Endpoint-alert review

An authorised investigator can classify an alert as Confirmed or False Positive and record notes.

False-positive classification requires the existing investigation, note-taking and false-positive permissions. A Viewer cannot review an alert.

A False Positive is closed without deleting its original evidence. Closed alerts cannot be reviewed again through this command, and repeated detection preserves the recorded review.

An approved process or compliant device is not automatically harmless. Crash, CPU and other behavioural findings still need investigation before classification.

---

## Security-logic checks and corrections

The first Stage 6 policy did not define how conflicting outcomes should be resolved. A fixed precedence was added so the same evidence always produces the same final result.

The first Restrict mapping proposed `restrict_account`, which was an identity action. It was replaced with the network-related `apply_ubuntu_firewall_rule` action already controlled by the automation ACL.

Testing also confirmed that one port-scan event could correctly match scanning, restricted-network and restricted-port rules at the same time. The final decision keeps every reason while applying one outcome.

Stage 7 isolation requests were consolidated by device without removing the supporting findings. The runner was also corrected to display the stored approval state rather than a newly calculated pending state.

---

## Verification

The security decisions were checked through focused tests, V2 stage validators, the complete regression and the original Phase 3 full-project validation.

Stored events, alerts, timelines, reviews and approvals were checked against SQLite evidence. Repeated processing preserved duplicate protection and investigation state.

Detailed results and test observations are recorded in the README and testing notes.

---

## What I learned

Identity, device, network and endpoint evidence become more useful when the reason for each decision is stored clearly.

One event can match several valid rules. Preserving all matching reasons while applying deterministic precedence makes the final outcome easier to explain.

A security decision remains separate from permission to perform a response.

Exceptions should be narrow, supported by matching evidence and recorded.

Endpoint symptoms such as high CPU activity or repeated crashes require investigation; a threshold match alone does not establish malicious activity.

A MAC address can support an investigation, but it should not identify a device by itself.

---

## Current limitations and next improvement

The project uses controlled local data instead of live identity-provider, device-management, network-sensor, wireless-controller or endpoint telemetry.

Locations, network zones, risk values, wireless security events and endpoint activity are simulated.

Access outcomes and responses are stored or simulated locally. They do not change real accounts, devices, applications, processes, firewall rules or networks.

Stage 8 will add vulnerability and application-security findings using the prepared asset context and controlled events. Its finding-processing engine has not yet been implemented or validated.
