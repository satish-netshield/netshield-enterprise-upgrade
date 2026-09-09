# NetShield Enterprise Upgrade Security Logic

## Project boundary

Phase 3A V2 extends the completed NetShield Phase 3 Automation project.

It runs locally with Python and SQLite inside an Ubuntu VirtualBox sandbox. Enterprise users, devices, applications, identity risks and access requests are simulated.

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
- Username and role
- Device and asset identifiers
- Application and service identifiers
- IP address, MAC address, hostname and location
- Severity, risk and decision context
- Original event evidence

Not every source requires every field. Validation depends on the event type and schema version.

This allows different security sources to be searched together without creating false values for fields they do not use.

### Complete source names

Compound source names such as `identity_risk` and `access_policy` are matched as complete names.

Reading only the first filename word would incorrectly classify `identity_risk` as `identity` and could apply the wrong validation logic.

### UTC timestamps

Accepted event timestamps are converted to UTC.

Using one time standard makes sequence, threshold and travel calculations consistent across sources.

### Malformed-event quarantine

Malformed events are excluded from the accepted-event table.

Their source file, line number, reason, quarantine status and original content are retained separately.

This prevents invalid data from influencing detections while preserving evidence for review.

### Raw-event preservation

The original event is stored with the normalised record.

This allows a later alert or policy decision to be traced back to the supplied evidence.

### Duplicate protection

Accepted events are protected by their source file and source event ID.

Identity alerts and access decisions use deterministic keys based on their supporting evidence.

Repeated imports and processing runs therefore do not create duplicate accepted events, alerts or policy decisions.

### Safe database migration

Updating `database/schema.sql` prepares new databases but does not upgrade an existing SQLite database.

Repeatable migrations add missing columns, tables and indexes without deleting earlier records. Running the migration again does not recreate existing objects.

---

## Relevant Stage 3 device decisions

Stage 3 provides the device evidence required by Stages 4 and 5.

Device ID and asset ID are the main identity references. A MAC address is supporting evidence only because it can change, be absent or be copied.

The project distinguishes between:

- Unknown Device
- Unregistered Device
- Stale Device
- Inventory Mismatch

A known but unregistered device is not treated as completely unknown.

Device removal changes its registration state and preserves its inventory and registration history.

Only records containing a device ID or an asset ID recognised by the device inventory are evaluated as device activity. Database and application assets are not treated as devices.

---

## Stage 4 — Identity monitoring and risk detection

Stage 4 evaluates controlled authentication and identity-risk events.

The original Phase 3 identity storage remains unchanged. V2 findings are stored separately in `v2_identity_alerts` with user, device, location, time, risk, severity, confidence, reason-code and investigation context.

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

Examples from the controlled run included:

| Detection | Severity | Confidence |
|---|---:|---:|
| Repeated Failed Logins | Medium | 70 |
| Possible Brute Force | High | 85 |
| Successful Login After Failures | High | 90 |
| Impossible Travel | High | 80 |
| New-Device Sign-In | Medium | 65 |
| MFA Failure or Fatigue Pattern | High | 85 |
| Suspicious Privilege Change | Critical | 95 |
| Dormant-Account Activity | High | 90 |
| Service-Account Interactive Login | High | 95 |
| Abnormal Access Time | Medium | 60 |

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

Approved testing evidence can also suppress a finding when it matches the configured test boundary.

Exceptions are counted instead of being silently ignored.

The controlled run recorded two VPN exceptions and one approved-testing exception.

### Duplicate-safe alerts

Identity-alert keys are created from the detection type and supporting event evidence.

A repeated Stage 4 run found the same 16 detections but stored no new alerts:

- 16 stored alerts
- 16 unique alert keys
- 0 duplicate alerts

### False-positive review

An authorised Analyst can classify an alert, change its investigation status and add notes.

Empty notes, unknown classifications and unknown alert IDs are rejected. A Viewer cannot perform the review.

The controlled Abnormal Access Time alert was classified as a False Positive and closed after it was confirmed as approved after-hours test activity.

The alert and audit history were preserved.

---

## Stage 5 — Zero Trust and policy-based access decisions

Stage 5 uses local identity, role, device, application, location, network, MFA and risk evidence to make explainable access decisions.

It applies Zero Trust, RBAC and Conditional Access concepts locally. It does not reproduce Microsoft Conditional Access.

### Explicit verification

The engine evaluates the available request context:

- User identity
- Assigned role
- Requested permission
- Device registration
- Device compliance
- Application sensitivity
- Asset criticality
- Location
- Network
- Sign-in risk
- User risk
- MFA evidence
- Temporary restrictions
- Approved VPN evidence

A valid account or device is not enough by itself. The complete request must satisfy the relevant policy.

### Least privilege

The requested permission must belong to the user’s assigned role.

A recognised user without the required permission is denied.

Higher application sensitivity, asset criticality or risk can require stronger evidence even when the role normally permits the action.

### Device requirements

Higher-risk access can require a registered and compliant device.

An unregistered or non-compliant device can produce a Challenge decision with separate reason codes:

- `DEVICE_NOT_REGISTERED`
- `DEVICE_NOT_COMPLIANT`

This explains exactly which device conditions were not satisfied.

### Restricted locations and networks

Configured restricted locations and networks produce Deny decisions.

The reason codes are:

- `RESTRICTED_LOCATION`
- `RESTRICTED_NETWORK`

An approved VPN address can bypass the matching network restriction. It does not bypass unrelated role, device, MFA or risk requirements.

### Risk-based controls

Critical identity risk can produce a Restrict decision.

The risk changes the decision for the current request. It does not silently change the user’s assigned role.

### MFA requirements

When a request requires MFA but the required evidence is missing, the result is Challenge with `MFA_REQUIRED`.

The project records the challenge and can simulate increased monitoring. It does not send a real MFA prompt.

### Temporary restrictions

An active temporary access restriction denies a matching user.

The restriction records its active state, reason, start time and optional end time.

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

The policy engine first selects Allow, Deny, Challenge or Restrict. It then checks any proposed response against the automation ACL.

In the controlled run:

- Challenge used `increase_monitoring`, an approved automatic simulated action.
- Restrict proposed `restrict_account`, which required approval and was not executed.

A correct policy result therefore cannot bypass the response-control boundary.

### Decision audit trail

Each stored decision includes:

- Request event ID
- User and role
- Device and application
- Decision
- Winning policy
- Reason codes
- Evaluated evidence
- Proposed response
- ACL control level
- Response status
- Evaluation time

Decision keys are deterministic.

Repeating Stage 5 found the same nine requests and created no duplicate decisions.

---

## SQLite connection security and reliability

Python’s SQLite transaction context commits or rolls back work but does not automatically close the connection object.

Under Python 3.14, the earlier connection pattern generated `ResourceWarning` messages.

A shared managed connection helper now:

1. Opens the connection.
2. Commits successful work.
3. Rolls back failed work.
4. Closes the connection in every case.

The change preserved transaction behaviour while removing unclosed connection warnings across the project.

---

## Testing evidence

Stage 4 used 24 controlled authentication and identity-risk events.

It stored 16 traceable identity alerts and passed 12 out of 12 validation checks.

Stage 5 evaluated nine controlled access requests:

- 2 Allow
- 4 Deny
- 2 Challenge
- 1 Restrict

It passed 14 out of 14 validation checks.

The combined Stage 4–5 unit tests passed 32 tests.

After adding explicit SQLite connection handling, the complete project passed 151 unit tests with zero unclosed-database `ResourceWarning` messages.

SQLite integrity checking returned `ok`, and the original Stage 11 full-project validation passed.

---

## Problems found and corrected

- Normal Stage 4 authentication events originally began outside the configured normal access hours. They were moved inside the approved period, while one deliberate late event remained to test abnormal access.
- New Stage 4–5 events affected a Stage 3 validator that used a broad event query. The validator was limited to the intended Stage 3 source files.
- SQLite connections were completing transactions without explicitly closing. A shared managed connection helper corrected the connection lifecycle.
- Updating the schema file alone did not upgrade the existing database. A repeatable migration was used.
- Compound source names required complete matching.
- Policy conflicts required explicit priority and restrictive tie handling.

These were implementation or validation problems. They were corrected without deleting valid earlier evidence.

---

## What I learned

Identity findings are stronger when user, device, source, location, time and risk evidence are considered together.

A suspicious location, device or login time can still have a legitimate explanation, so exceptions and investigation history are important.

Access decisions need clear reason codes and predictable policy priority.

A security decision must remain separate from permission to perform a disruptive response.

Later-stage data can expose assumptions in earlier validators, so each validator needs a clear evidence boundary.

Database resource handling remains important even when functional tests pass.

---

## Current limitations and next improvement

The project uses controlled local data instead of live identity-provider, MFA, device-management or cloud-policy telemetry.

Locations and risk scores are simulated inputs.

Access outcomes and responses are stored or simulated locally. They do not change real accounts, sessions, devices, applications or networks.

A later stage can add wider correlation and incident context while preserving the same evidence, default-deny, audit and approval controls.
