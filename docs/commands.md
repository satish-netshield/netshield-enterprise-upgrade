# NetShield Enterprise Upgrade Commands

## Project location

```bash
cd ~/netshield-enterprise-upgrade
source .venv/bin/activate
```

Confirm the repository and branch:

```bash
pwd
git status --short --branch
git log -1 --oneline --decorate
```

---

## General safety checks

Confirm the project remains inside the sandbox:

```bash
python -m scripts.validate_stage1
```

Check Python syntax:

```bash
python -m compileall -q src scripts tests
```

Check tracked-file formatting:

```bash
git diff --check
```

Check SQLite integrity:

```bash
sqlite3 database/netshield.db \
  "PRAGMA integrity_check; PRAGMA foreign_key_check;"
```

Check for Python resource warnings after a test run:

```bash
grep -R "ResourceWarning: unclosed database" /tmp/netshield_tests.log
```

A successful clean check returns no matching warning.

---

## Stage 1 — Enterprise foundation

Initialise the V2 enterprise foundation:

```bash
python -m scripts.initialize_v2_stage1
```

Validate the foundation:

```bash
python -m scripts.validate_v2_stage1
```

The validation checks enterprise context, simulated users and devices, retention, masking, RBAC, database metadata, audit records and compatibility with the original Phase 3 controls.

---

## Stage 2 — Extended security data pipeline

Generate the controlled V2 source events:

```bash
python -m scripts.generate_v2_stage2_events
```

Import the events:

```bash
python -m scripts.import_v2_stage2_events
```

Run the Stage 2 pipeline validation:

```bash
python -m scripts.validate_v2_stage2
```

The pipeline validates required fields, source names, data types, UTC timestamps, duplicate handling, raw-event preservation, quarantine records, ingestion totals and audit events.

---

## Stage 3 — Asset and device identity

Initialise the Stage 3 device tables:

```bash
python -m scripts.initialize_v2_stage3
```

Run device detection:

```bash
python -m scripts.run_v2_stage3_device_identity
```

Review a controlled device alert when required:

```bash
python -m scripts.review_v2_stage3_device_alert
```

Validate Stage 3:

```bash
python -m scripts.validate_v2_stage3
```

Stage 3 must keep MAC addresses as supporting evidence and must not treat database or web assets as devices.

---

## Stage 4 — Identity monitoring

Initialise Stage 4 storage:

```bash
python -m scripts.initialize_v2_stage4
```

Generate and import controlled identity events:

```bash
python -m scripts.generate_v2_stage4_events
python -m scripts.import_v2_stage4_events
```

Run identity detection:

```bash
python -m scripts.run_v2_stage4_identity_monitoring
```

Validate Stage 4:

```bash
python -m scripts.validate_v2_stage4
```

Review a controlled identity alert through RBAC:

```bash
python -m scripts.review_v2_stage4_identity_alert
```

VPN and approved-testing exceptions must remain narrow and auditable.

---

## Stage 5 — Access policy decisions

Initialise Stage 5 policy storage:

```bash
python -m scripts.initialize_v2_stage5
```

Run policy evaluation:

```bash
python -m scripts.run_v2_stage5_access_policy
```

Validate Stage 5:

```bash
python -m scripts.validate_v2_stage5
```

Stage 5 uses default deny, deterministic policy priority and the existing RBAC and automation ACL. A policy result does not automatically execute a response action.

---

## Stage 6 — Network and Wi-Fi monitoring

Initialise Stage 6 storage:

```bash
python -m scripts.initialize_v2_stage6
```

Generate and import controlled network events:

```bash
python -m scripts.generate_v2_stage6_events
python -m scripts.import_v2_stage6_events
```

Run network monitoring:

```bash
python -m scripts.run_v2_stage6_network_monitoring
```

Review a controlled network alert:

```bash
python -m scripts.review_v2_stage6_network_alert
```

Validate Stage 6:

```bash
python -m scripts.validate_v2_stage6
```

No command in this project changes the real Ubuntu firewall or wireless state.

---

## Stage 7 — Endpoint monitoring

Initialise Stage 7 storage:

```bash
python -m scripts.initialize_v2_stage7_8
```

Generate the controlled Stage 7 and Stage 8 events:

```bash
python -m scripts.generate_v2_stage7_8_events
```

Import the events:

```bash
python -m scripts.import_v2_stage7_8_events
```

Run endpoint monitoring:

```bash
python -m scripts.run_v2_stage7_endpoint_monitoring
```

Attempt approval with an unauthorised actor:

```bash
python -m scripts.approve_v2_stage7_endpoint_isolation \
  --device CYOD-002 \
  --actor analyst01
```

Approve the controlled simulated isolation with an authorised responder:

```bash
python -m scripts.approve_v2_stage7_endpoint_isolation \
  --device CYOD-002 \
  --actor responder01
```

Review a controlled endpoint alert:

```bash
python -m scripts.review_v2_stage7_endpoint_alert
```

Validate Stage 7:

```bash
python -m scripts.validate_v2_stage7
```

The isolation result is simulated. It does not change network connectivity, Wi-Fi, processes or the operating system.

---

## Stage 8 — Vulnerability management

Initialise Stage 8 storage:

```bash
python -m scripts.initialize_v2_stage7_8
```

Import the controlled application-security and vulnerability events:

```bash
python -m scripts.import_v2_stage7_8_events
```

Run vulnerability management:

```bash
python -m scripts.run_v2_stage8_vulnerability_management
```

Attempt review with an unauthorised actor:

```bash
python -m scripts.review_v2_stage8_vulnerability_finding \
  --finding S78-FND-FP-001 \
  --actor viewer01
```

Review the supported false-positive candidate with an authorised analyst:

```bash
python -m scripts.review_v2_stage8_vulnerability_finding \
  --finding S78-FND-FP-001 \
  --actor analyst01
```

Validate Stage 8:

```bash
python -m scripts.validate_v2_stage8
```

A vulnerability does not automatically become an incident. Approved testing remains evidence and uses no external targets.

---

## Stage 9 — Continuous monitoring and risk scoring

Initialise Stage 9 storage:

```bash
python -m scripts.initialize_v2_stage9
```

Run one scheduled monitoring cycle:

```bash
python -m scripts.run_v2_stage9_continuous_monitoring
```

Run a controlled repeat to test interval suppression and alert cooldown:

```bash
python -m scripts.run_v2_stage9_continuous_monitoring \
  --force-repeat
```

Validate Stage 9:

```bash
python -m scripts.validate_v2_stage9
```

Stage 9 checks risk scores, independent-source agreement, validated exceptions, time decay, threshold alerts, cooldown state, component health, cycle summaries and last-successful-run tracking.

Risk scores support decisions but do not replace original evidence.

---

## Stage 10 — XDR-style correlation

Initialise Stage 10 storage:

```bash
python -m scripts.initialize_v2_stage10
```

Run cross-source correlation:

```bash
python -m scripts.run_v2_stage10_xdr_correlation
```

Run correlation again to confirm duplicate safety:

```bash
python -m scripts.run_v2_stage10_xdr_correlation
```

Validate Stage 10:

```bash
python -m scripts.validate_v2_stage10
```

Stage 10 preserves original evidence, keeps unrelated device chains separate, records why evidence was correlated, separates IoCs from behaviours and keeps MAC addresses as supporting observables.

---

## Stage 11 — Incident management and evidence

Initialise Stage 11 incident-management storage:

```bash
python -m scripts.initialize_v2_stage11
```

Apply the Stage 11 risk-provenance migration:

```bash
python -m scripts.initialize_v2_stage11_risk
```

Import the Stage 10 incidents:

```bash
python -m scripts.import_v2_stage11_incidents
```

Import incident context:

```bash
python -m scripts.import_v2_stage11_context
```

Assign an incident owner:

```bash
python -m scripts.assign_v2_stage11_incident \
  --incident INC-V2-11-0001 \
  --actor analyst01
```

Review and triage an incident:

```bash
python -m scripts.review_v2_stage11_incident \
  --incident INC-V2-11-0001 \
  --actor analyst01 \
  --status Triaged
```

Move the incident into investigation:

```bash
python -m scripts.review_v2_stage11_incident \
  --incident INC-V2-11-0001 \
  --actor analyst01 \
  --status Investigating
```

Test rejection of an unauthorised false-positive review:

```bash
python -m scripts.close_v2_stage11_false_positive \
  --incident INC-V2-11-0003 \
  --actor viewer01 \
  --notes "Permission test only." \
  --reason "Permission test only." \
  --evidence-key "identity:test" \
  --request-id stage11-fp-permission-test-001
```

Generate JSON and readable incident reports:

```bash
python -m scripts.generate_v2_stage11_reports
```

Run report generation again to confirm duplicate safety:

```bash
python -m scripts.generate_v2_stage11_reports
```

Validate Stage 11:

```bash
python -m scripts.validate_v2_stage11
```

Stage 11 preserves evidence hashes, lifecycle decisions, permissions, vulnerability relationships, reports and audit records. Containment, eradication and recovery states must not be recorded unless those actions genuinely occur.

---

## Full project validation

Run Python syntax validation:

```bash
python -m compileall -q src scripts tests
```

Run the complete test suite and save the output:

```bash
set -o pipefail
PYTHONTRACEMALLOC=5 python -W always::ResourceWarning \
  -m unittest discover -s tests 2>&1 | tee /tmp/netshield_tests.log
```

Check for unclosed-database warnings:

```bash
if grep -q "ResourceWarning: unclosed database" /tmp/netshield_tests.log; then
  echo "FAIL: unclosed-database warning found"
  exit 1
else
  echo "PASS: no unclosed-database warning found"
fi
```

Run the Stage 11 full-project validator:

```bash
python -m scripts.validate_stage11
```

Check SQLite integrity after validation:

```bash
sqlite3 database/netshield.db \
  "PRAGMA integrity_check; PRAGMA foreign_key_check;"
```

Review the final working tree:

```bash
git diff --check
git status --short --branch
git log -1 --oneline --decorate
```

---

## Evidence and audit review

List managed incidents:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT incident_id, status, incident_owner, severity, confidence
   FROM v2_managed_incidents
   ORDER BY incident_id;"
```

List incident evidence counts:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT incident_id, COUNT(*) AS evidence_records
   FROM v2_incident_evidence
   GROUP BY incident_id
   ORDER BY incident_id;"
```

List audit records for Stage 11:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT actor, action, target, result
   FROM audit_events
   WHERE action LIKE '%stage11%'
   ORDER BY event_time;"
```

Check report records:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT incident_id, report_type, report_path, report_sha256
   FROM v2_incident_reports
   ORDER BY incident_id, report_type;"
```

---

## Git save and push

Review changes:

```bash
git status --short --branch
git diff --stat
git diff --check
```

Stage only reviewed files:

```bash
git add README.md docs config database scripts src tests reports
```

Review the staged change:

```bash
git diff --cached --stat
git diff --cached --check
```

Commit:

```bash
git commit -m "Update NetShield project documentation"
```

Push the reviewed commit:

```bash
git push
```

Confirm the branch is clean and aligned:

```bash
git status --short --branch
git log -1 --oneline --decorate
```

---

## Operational boundary

All stages remain local and simulated.

No command in this project is permitted to:

- target an external system
- change real network connectivity
- change the real Ubuntu firewall
- disable a real account
- terminate a real process
- remove a real file
- perform an unapproved response action

Every disruptive action must be denied by default or require the existing approval and ACL controls.
