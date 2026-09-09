# NetShield Enterprise Upgrade Handbook

## Welcome

This handbook explains the engineering journey behind Phase 3A V2 — NetShield Enterprise Upgrade.

It is written for someone who wants to understand the project without reading every script, configuration file or database table.

The README shows the completed components, evidence and test results in more detail. This handbook focuses on the wider goals, important decisions, improvements and lessons learned while building the upgrade.

NetShield Enterprise Upgrade extends the completed Phase 3 Automation project. It remains a local Python and SQLite project inside an Ubuntu VirtualBox sandbox.

The users, devices, applications, identity risks and access requests are simulated. Microsoft Entra, Defender, Sentinel, Conditional Access and XDR are design references only. No Microsoft services or real enterprise actions are used.

---

## Engineering Goals

The main goal is to move NetShield from a smaller security-automation project towards a more complete enterprise security-operations model.

The upgrade is being built gradually so each component can be understood, tested and corrected before the next one depends on it.

The current work aims to:

- Preserve the completed Phase 3 controls.
- Add simulated enterprise users, devices, applications and services.
- Process more types of security data.
- Improve device identity and inventory checks.
- Detect wider identity and sign-in risks.
- Make explainable access decisions.
- Apply default deny and least privilege.
- Keep disruptive responses behind approval controls.
- Preserve evidence and audit history.
- Support safe repeated runs.
- Prepare the project for later cloud and security-operations work.

The project is not intended to copy a commercial security platform. It applies the main security ideas locally so I can understand how the decisions work.

---

## Engineering Principles

### Build incrementally

Each stage adds a limited capability to the existing project.

I first verify the current project, add the new component, test it independently and then run the wider regression.

This makes it easier to identify which change caused a failure.

### Preserve compatibility

The enterprise upgrade extends NetShield instead of replacing it.

Existing roles, access controls, evidence handling, alert storage and validation continue to operate unless a genuine improvement is required.

### Use controlled evidence

The project uses simulated events designed for specific security scenarios.

Normal, suspicious, malformed, duplicate and exception cases are included so the result is based on evidence rather than only a successful script run.

### Fix genuine problems

When testing exposes a real issue, I correct the implementation, data or validation boundary responsible for it.

I do not change a security rule only to make a test pass.

### Keep decisions explainable

Alerts and access decisions retain their supporting events, reason codes and relevant context.

A result should be understandable without guessing why the project created it.

### Keep responses controlled

Detection, access decisions and automated responses remain separate.

A serious alert does not automatically permit a disruptive action. The automation ACL still decides whether the response is automatic, approval-required or manual-only.

### Validate repeated behaviour

Initialisation, imports, detections and policy decisions are run more than once.

A secure automation project should handle repeated execution without duplicating valid records or changing earlier evidence unexpectedly.

### Maintain meaningful Git history

Implementation, tests and documentation are reviewed together before a stage is committed.

Runtime databases, logs and generated outputs remain outside Git unless they are controlled project fixtures or test inputs.

---

## What Was Built

### Enterprise foundation

Stage 1 added simulated enterprise users, devices, applications and services while preserving the existing Phase 3 foundation.

The upgrade reused the original RBAC roles, automation ACL, logging, SQLite database, evidence controls and sandbox restrictions.

Retention settings and sensitive-field masking were also added.

### Extended security data pipeline

Stage 2 expanded the pipeline to accept more enterprise-style sources, including identity risk, access policy, database, vulnerability, incident and response events.

Events are validated, normalised to UTC and stored in SQLite. Malformed records are quarantined, original evidence is preserved and duplicate accepted events are prevented.

### Enterprise asset and device identity

Stage 3 added a stronger device inventory and separated unknown, unregistered, stale and mismatched device findings.

Device ID and asset ID are the main identity references. MAC addresses remain supporting evidence only.

This device context is reused by identity monitoring and access-policy decisions.

### Identity monitoring and risk detection

Stage 4 added wider identity monitoring across authentication and identity-risk events.

It can identify patterns such as repeated failures, password spraying, successful login after failures, impossible travel, new-device activity, unusual location, abnormal access time, MFA failures, suspicious privilege changes, dormant-account use, service-account interactive login and risky sign-in behaviour.

Alerts contain user, device, location, time, risk, severity, confidence and reason-code context.

Known VPN and approved-testing exceptions are also considered.

### Identity-alert investigation

An authorised Analyst can review an identity alert, record investigation notes and classify it.

The controlled abnormal-time alert was reviewed, classified as a False Positive and closed without deleting the original alert or audit history.

### Zero Trust access policy

Stage 5 added a local policy engine that evaluates identity, role, device, application, location, network, MFA and risk evidence.

The engine supports four outcomes:

- Allow
- Deny
- Challenge
- Restrict

Every decision records its winning policy, reason codes, evaluated evidence and response status.

This applies Zero Trust, RBAC and Conditional Access ideas locally without reproducing Microsoft Conditional Access.

### SQLite connection management

A shared connection helper was added after Python 3.14 exposed unclosed SQLite connection warnings.

The helper commits successful work, rolls back failed work and closes the connection in every case.

The correction was applied across existing and new project components.

### Validation

The completed work through Stage 5 passed:

- V2 Stage 1 validation: 12 out of 12
- V2 Stage 2 validation: 13 out of 13
- V2 Stage 3 validation: 19 out of 19
- V2 Stage 4 validation: 12 out of 12
- V2 Stage 5 validation: 14 out of 14
- Complete unit-test suite: 151 tests
- Unclosed-database warnings: 0
- SQLite integrity check: `ok`
- Original Stage 11 full-project validation: PASS

---

## Major Engineering Decisions

### Extend the existing project

I kept the original Phase 3 project as the foundation.

This avoided creating separate roles, databases or response rules that could disagree with each other.

### Keep default deny

Unknown permissions, applications, policy conditions and automation actions are not accepted automatically.

Access is allowed only when the required evidence is present.

### Separate severity from confidence

Severity describes the possible impact of an identity finding.

Confidence describes how strongly the available evidence supports it.

Keeping them separate makes the alert easier to understand.

### Treat device identity as combined evidence

A MAC address alone is not reliable proof of device identity.

The project uses device ID, asset ID, registration, compliance, user, hostname, location and network context together.

### Preserve malformed evidence

Malformed events remain outside the accepted-event table, but they are not discarded.

Their original content and rejection reason are retained for investigation.

### Use repeatable migrations

The tracked schema file supports new databases, but it cannot upgrade an existing database by itself.

Repeatable migrations allow the working database to gain new tables and indexes without deleting earlier project data.

### Make policy conflicts predictable

Access policies use explicit priority.

When policies have the same priority, the more restrictive result wins. This prevents configuration order from creating an unintended Allow decision.

### Keep policy and response separate

A Restrict decision can propose an account restriction, but the response still requires approval under the automation ACL.

This keeps decision logic from silently gaining permission to perform disruptive actions.

### Preserve investigation history

Alerts, classifications, notes and audit events remain available after review.

Closing an alert changes its investigation state but does not remove the original evidence.

---

## Improvements Made

### Enterprise-context consistency

A registered device appeared in the enterprise context but was missing from the authoritative CYOD inventory.

The inventory was corrected and a consistency check was added.

### Complete source-name handling

The first source-name logic read only the first filename word.

It was corrected so a source such as `identity_risk` remains `identity_risk`.

### Safe migration for existing databases

The first schema changes prepared only new databases.

A repeatable migration was added so the existing NetShield database could be upgraded safely.

### More accurate malformed-event validation

Repeated imports could create several rejection rows for the same malformed input.

The validator was changed to verify distinct malformed evidence rather than treating every rejection row as a separate malformed event.

### Compatible source validation

The original Stage 2 validator expected exactly five source types.

It was corrected to require the original five while allowing approved V2 sources.

### Better device boundaries

Database and application assets were initially considered during device evaluation.

The detector was limited to records containing device identity evidence known to the device inventory.

### Correct unregistered-device classification

`CYOD-003` was initially classified as unknown.

The enterprise context showed that it was known but unregistered, so the result was corrected.

### Accurate access-time test data

Normal Stage 4 events originally began outside the configured normal access period.

The normal events were moved inside the approved hours, while one deliberate late event remained to test abnormal access.

### Clear validator boundaries

Later Stage 4–5 data affected a Stage 3 validator that searched too broadly.

The validator was limited to its intended Stage 3 source evidence instead of removing valid later-stage records.

### Explicit SQLite closure

Python 3.14 reported unclosed SQLite connections even though the tests passed.

The connection lifecycle was corrected across the project, and focused tests were added for commit, rollback and closure behaviour.

### Sensitive configuration permissions

The new Stage 4–5 configuration files were initially created with permission `664`.

Their permissions were changed to `640` to match the project’s sensitive configuration standard.

---

## Lessons Learned

### Security context must agree

User, device, role, inventory and application records are connected.

A mismatch between them can produce a technically valid but incorrect security result.

### Test data is part of the engineering work

A detector can behave correctly and still produce misleading findings when the controlled data does not match its baseline.

Test timestamps, locations, devices and risk values must be designed carefully.

### Exceptions need evidence

VPN and approved-testing exceptions should not be hidden.

Recording them shows why a finding was suppressed and helps confirm that the exception was actually applied.

### Explainability matters

An Allow, Deny, Challenge or Restrict result is not enough by itself.

The winning policy, reason codes and evidence make the decision useful for investigation.

### Passing tests are not the only signal

The test suite passed while Python still reported unclosed database connections.

Warnings can reveal reliability problems that functional assertions do not detect.

### Validators must grow with the project

A validator that works in one stage can become inaccurate when later stages add valid records to the same database.

Each validator needs a clear evidence boundary.

### Repeated runs need deliberate testing

Duplicate protection cannot be assumed because a database has unique fields.

Initialisation, imports, detections and policy evaluation need to be repeated and checked directly.

### Automation still needs limits

Detection confidence and risk severity do not automatically justify a disruptive response.

Approval and manual-control boundaries remain necessary even when the decision itself is clear.

---

## Future Expansion

The identity alerts and access-policy decisions can support later event correlation, incident management and response work.

Future expansion can include:

- Wider correlation between identity, device, application and network evidence
- Incident creation from combined V2 risk
- Temporary restriction management
- More detailed policy simulation
- Retention enforcement
- Additional evidence reporting
- Live cloud identity and security telemetry
- AWS migration and cloud-native monitoring
- AI-assisted security analysis in a later project phase

Any future integration should preserve the same principles used here:

- Verify the evidence.
- Use least privilege.
- Follow default deny.
- Preserve audit history.
- Keep disruptive actions controlled.
- Test repeated behaviour.
- Maintain compatibility with completed work.
