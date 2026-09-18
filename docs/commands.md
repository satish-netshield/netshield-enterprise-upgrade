# NetShield Enterprise Upgrade Commands

All commands are run from the Phase 3A V2 project directory inside the Ubuntu VirtualBox sandbox.

## Project setup

```bash
cd /home/netshield01/netshield-enterprise-upgrade
source .venv/bin/activate

python --version
git --version
sqlite3 --version
git status --short --branch
```

## Phase 3 baseline verification

Phase 3A V2 extends the completed Phase 3 Automation project.

```bash
python -m unittest discover -s tests
python -m scripts.validate_stage11
```

The Stage 8–10 results printed by the original Stage 11 validator refer to the original Phase 3 incident-response stages. They are separate from the Phase 3A V2 Stage 8–10 validators.

---

## Stage 1 — Enterprise foundation

Initialise and validate the foundation:

```bash
python -m scripts.initialize_v2_stage1
python -m scripts.validate_v2_stage1

python -m unittest -v \
  tests.test_v2_stage1_foundation
```

Review the enterprise context and settings:

```bash
python -m json.tool config/enterprise_context.json
python -m json.tool config/settings.json
```

Review simulated role assignments:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  username,
  role,
  active
FROM user_roles
WHERE username IN (
  'viewer01',
  'analyst01',
  'responder01',
  'admin01'
)
ORDER BY username;
"
```

Review protected permissions:

```bash
stat -c '%a %n' \
  config \
  config/settings.json \
  database \
  database/netshield.db \
  evidence
```

---

## Stage 2 — Extended security data pipeline

Run the repeatable migration twice:

```bash
python -m scripts.initialize_v2_stage2
python -m scripts.initialize_v2_stage2
```

Generate and import the controlled events:

```bash
python -m scripts.generate_v2_stage2_events
python -m scripts.import_v2_stage2_events
```

Repeat the import to check duplicate protection:

```bash
python -m scripts.import_v2_stage2_events
```

Run the tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage2_pipeline

python -m scripts.validate_v2_stage2
```

Review the source files:

```bash
find data/raw/v2 \
  -maxdepth 1 \
  -type f \
  -name '*.jsonl' \
  -print | sort

wc -l data/raw/v2/*.jsonl
```

Review accepted events by source:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_type,
  COUNT(*) AS accepted_events
FROM security_events
WHERE schema_version = '2.0'
  AND source_file LIKE '%_v2_events.jsonl'
GROUP BY source_type
ORDER BY source_type;
"
```

Review quarantined malformed records:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_file,
  line_number,
  reason,
  quarantine_status
FROM rejected_events
WHERE source_file LIKE '%_v2_events.jsonl'
  AND quarantine_status = 'quarantined'
  AND reason NOT LIKE 'Duplicate%'
ORDER BY rejection_id;
"
```

Review ingestion batches:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_file,
  total_records,
  accepted_records,
  rejected_records,
  status
FROM import_batches
WHERE source_file LIKE '%_v2_events.jsonl'
ORDER BY started_at;
"
```

---

## Stage 3 — Enterprise asset and device identity

Initialise the inventory and run device identity detection:

```bash
python -m scripts.initialize_v2_stage3
python -m scripts.run_v2_stage3_device_identity
python -m scripts.run_v2_stage3_device_identity
```

Run the focused tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage3_device_identity \
  tests.test_v2_stage3_device_alert_review

python -m scripts.validate_v2_stage3
```

Review the relevant inventory and alert records:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  asset_id,
  device_id,
  hostname,
  assigned_user,
  registration_status,
  compliance_status,
  risk_status,
  criticality
FROM device_inventory
ORDER BY device_id;

SELECT
  alert_id,
  detection_type,
  severity,
  device_id,
  hostname,
  username,
  status
FROM device_alerts
ORDER BY alert_id;
"
```

Review the controlled management commands:

```bash
python -m scripts.manage_v2_stage3_device --help
python -m scripts.review_v2_stage3_device_alert --help
```

---

## Combined Stage 4–5 preparation

Run the shared migration twice:

```bash
python -m scripts.initialize_v2_stage4_5
python -m scripts.initialize_v2_stage4_5
```

Generate and import the controlled events:

```bash
python -m scripts.generate_v2_stage4_5_events
python -m scripts.import_v2_stage4_5_events
```

Review the source totals:

```bash
find data/raw/v2/stage4_5 \
  -maxdepth 1 \
  -type f \
  -name '*.jsonl' \
  -printf '%f %s bytes\n' | sort

wc -l data/raw/v2/stage4_5/*.jsonl
```

Review imported Stage 4–5 events:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_type,
  COUNT(*) AS accepted_events
FROM security_events
WHERE source_file LIKE '%_v2_stage4_5_events.jsonl'
GROUP BY source_type
ORDER BY source_type;
"
```

Review the shared tables and configuration permissions:

```bash
sqlite3 -header -column database/netshield.db "
SELECT name
FROM sqlite_master
WHERE type = 'table'
  AND name IN (
    'v2_identity_alerts',
    'temporary_access_restrictions',
    'access_policy_decisions'
  )
ORDER BY name;
"

stat -c '%a %n' \
  config/v2_identity_monitoring.json \
  config/v2_access_policy.json
```

---

## Stage 4 — Identity monitoring and risk detection

Run identity monitoring twice:

```bash
python -m scripts.run_v2_stage4_identity_monitoring
python -m scripts.run_v2_stage4_identity_monitoring
```

Run the focused tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage4_identity_monitoring \
  tests.test_v2_stage4_identity_review

python -m scripts.validate_v2_stage4
```

Review the stored alerts:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  alert_id,
  detection_type,
  severity,
  confidence,
  username,
  device_id,
  location,
  risk_score,
  reason_codes,
  status
FROM v2_identity_alerts
ORDER BY first_event_time, detection_type;
"
```

Review totals and duplicate protection:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  detection_type,
  COUNT(*) AS alert_count
FROM v2_identity_alerts
GROUP BY detection_type
ORDER BY detection_type;

SELECT
  COUNT(*) AS stored_alerts,
  COUNT(DISTINCT alert_key) AS unique_alert_keys
FROM v2_identity_alerts;
"
```

Review the controlled investigation:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  alert_id,
  detection_type,
  username,
  status,
  classification,
  investigation_notes
FROM v2_identity_alerts
WHERE alert_id = 16;

SELECT
  actor,
  action,
  target,
  result,
  details
FROM audit_events
WHERE action = 'review_v2_stage4_identity_alert'
ORDER BY event_id DESC
LIMIT 1;
"
```

Review the alert-review command:

```bash
python -m scripts.review_v2_stage4_identity_alert --help
```

---

## Stage 5 — Policy-based access decisions

Run the access-policy engine twice:

```bash
python -m scripts.run_v2_stage5_access_policy
python -m scripts.run_v2_stage5_access_policy
```

Run the focused tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage5_access_policy

python -m scripts.validate_v2_stage5
```

Review the stored decisions:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  request_event_id,
  username,
  role,
  device_id,
  application_id,
  decision,
  winning_policy_id,
  reason_codes,
  response_action,
  acl_control_level,
  response_status
FROM access_policy_decisions
ORDER BY request_event_id;
"
```

Review decision totals and duplicate protection:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  decision,
  COUNT(*) AS decision_count
FROM access_policy_decisions
GROUP BY decision
ORDER BY decision;

SELECT
  COUNT(*) AS stored_decisions,
  COUNT(DISTINCT decision_key) AS unique_decision_keys
FROM access_policy_decisions;
"
```

Review policy, RBAC and ACL configuration:

```bash
python -m json.tool config/v2_access_policy.json
python -m json.tool config/rbac.json
python -m json.tool config/automation_acl.json
```

---

## Stage 6 — Network, Wi-Fi and access monitoring

Run the migration twice:

```bash
python -m scripts.initialize_v2_stage6
python -m scripts.initialize_v2_stage6
```

Generate and import the controlled events:

```bash
python -m scripts.generate_v2_stage6_events
python -m scripts.import_v2_stage6_events
```

Review the source files and imported totals:

```bash
find data/raw/v2/stage6 \
  -maxdepth 1 \
  -type f \
  -name '*.jsonl' \
  -printf '%f %s bytes\n' | sort

wc -l data/raw/v2/stage6/*.jsonl

sqlite3 -header -column database/netshield.db "
SELECT
  source_type,
  COUNT(*) AS accepted_events
FROM security_events
WHERE source_file IN (
  'network_v2_stage6_events.jsonl',
  'wifi_v2_stage6_events.jsonl'
)
GROUP BY source_type
ORDER BY source_type;
"
```

Run monitoring twice:

```bash
python -m scripts.run_v2_stage6_network_monitoring
python -m scripts.run_v2_stage6_network_monitoring
```

Run the focused tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage6_network_monitoring \
  tests.test_v2_stage6_network_alert_review

python -m scripts.validate_v2_stage6
```

Review alert and decision totals:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  detection_type,
  severity,
  confidence,
  COUNT(*) AS alert_count
FROM v2_network_alerts
GROUP BY detection_type, severity, confidence
ORDER BY detection_type;

SELECT
  decision,
  COUNT(*) AS decision_count
FROM v2_network_access_decisions
GROUP BY decision
ORDER BY decision;
"
```

Review stored network decisions:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_event_id,
  device_id,
  ip_address,
  decision,
  matching_rules,
  reason_codes,
  response_action,
  acl_control_level,
  response_status
FROM v2_network_access_decisions
ORDER BY event_time, source_event_id;
"
```

Check duplicate protection:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  COUNT(*) AS stored_alerts,
  COUNT(DISTINCT alert_key) AS unique_alert_keys
FROM v2_network_alerts;

SELECT
  COUNT(*) AS stored_decisions,
  COUNT(DISTINCT decision_key) AS unique_decision_keys
FROM v2_network_access_decisions;

SELECT
  COUNT(*) AS timeline_events,
  COUNT(DISTINCT source_event_id) AS unique_timeline_events
FROM v2_network_connection_timeline;
"
```

Review the connection timeline:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_event_id,
  event_time,
  source_type,
  device_id,
  username,
  ip_address,
  connection_type,
  location
FROM v2_network_connection_timeline
ORDER BY event_time, source_event_id;
"
```

Review the controlled false-positive investigation:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  alert_id,
  detection_type,
  device_id,
  ip_address,
  status,
  classification,
  investigation_notes,
  reviewed_by,
  reviewed_at
FROM v2_network_alerts
WHERE alert_id = 18;

SELECT
  actor,
  action,
  target,
  result,
  details
FROM audit_events
WHERE action = 'review_v2_stage6_network_alert'
ORDER BY event_id DESC
LIMIT 1;
"
```

Review configuration and permission:

```bash
python -m json.tool config/v2_network_monitoring.json

stat -c '%a %n' \
  config/v2_network_monitoring.json
```

---

## Combined Stage 7–8 preparation

Stage 7 and Stage 8 share migration, event-generation and import commands.

Run the migration twice:

```bash
python -m scripts.initialize_v2_stage7_8
python -m scripts.initialize_v2_stage7_8
```

Generate and import the controlled events:

```bash
python -m scripts.generate_v2_stage7_8_events
python -m scripts.import_v2_stage7_8_events
```

Repeat the import to check duplicate-event protection:

```bash
python -m scripts.import_v2_stage7_8_events
```

Review the shared source files:

```bash
find data/raw/v2/stage7_8 \
  -maxdepth 1 \
  -type f \
  -name '*.jsonl' \
  -printf '%f %s bytes\n' | sort

wc -l data/raw/v2/stage7_8/*.jsonl
```

Review accepted Stage 7–8 events:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_file,
  source_type,
  COUNT(*) AS stored_events,
  COUNT(DISTINCT source_event_id) AS unique_events
FROM security_events
WHERE source_file IN (
  'endpoint_v2_stage7_8_events.jsonl',
  'application_security_v2_stage7_8_events.jsonl',
  'vulnerability_v2_stage7_8_events.jsonl'
)
GROUP BY source_file, source_type
ORDER BY source_file;
"
```

---

## Stage 7 — Endpoint monitoring and investigation

Run endpoint monitoring twice:

```bash
python -m scripts.run_v2_stage7_endpoint_monitoring
python -m scripts.run_v2_stage7_endpoint_monitoring
```

Run the focused tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage7_endpoint_monitoring

python -m scripts.validate_v2_stage7
```

Review endpoint-alert totals:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  detection_type,
  severity,
  COUNT(*) AS alert_count
FROM v2_endpoint_alerts
GROUP BY detection_type, severity
ORDER BY detection_type, severity;
"
```

Review the crash or restart evidence:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  alert_id,
  detection_type,
  first_event_time,
  last_event_time,
  source_event_ids,
  json_extract(
    evidence,
    '$.observations.event_count'
  ) AS event_count,
  json_extract(
    evidence,
    '$.observations.configured_window_minutes'
  ) AS configured_window_minutes,
  json_extract(
    evidence,
    '$.observations.observed_window_minutes'
  ) AS observed_window_minutes,
  status,
  classification
FROM v2_endpoint_alerts
WHERE detection_type = 'Repeated Process Crash or Restart';
"
```

Review the endpoint timeline:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_event_id,
  event_time,
  event_type,
  device_id,
  username,
  process_name,
  process_owner,
  parent_process_name,
  cpu_percent,
  isolation_state,
  status
FROM v2_endpoint_activity_timeline
ORDER BY event_time, source_event_id;
"
```

Check Stage 7 duplicate protection:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  COUNT(*) AS stored_alerts,
  COUNT(DISTINCT alert_key) AS unique_alert_keys
FROM v2_endpoint_alerts;

SELECT
  COUNT(*) AS timeline_events,
  COUNT(DISTINCT source_event_id) AS unique_timeline_events
FROM v2_endpoint_activity_timeline;

SELECT
  COUNT(*) AS isolation_records,
  COUNT(DISTINCT isolation_key) AS unique_isolation_keys
FROM v2_endpoint_isolation_actions;
"
```

### Simulated isolation

Review the isolation records:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  isolation_id,
  device_id,
  action,
  acl_control_level,
  status,
  approved_by,
  approved_at,
  json_extract(
    evidence,
    '$.alert_count'
  ) AS critical_alerts,
  json_array_length(
    json_extract(evidence, '$.alert_keys')
  ) AS preserved_alert_keys,
  network_state_changed,
  real_action_executed
FROM v2_endpoint_isolation_actions
ORDER BY isolation_id;
"
```

Review the approval options:

```bash
python -m scripts.approve_v2_stage7_endpoint_isolation --help
```

The following controlled approval has already been completed in the current database. Do not repeat it as a routine validation command.

```bash
python -m scripts.approve_v2_stage7_endpoint_isolation \
  --isolation-id 11 \
  --actor responder01 \
  --notes "Reviewed the 10 Critical endpoint alerts and approved the simulated isolation record. No real isolation or network change was performed."
```

Review approval evidence and audit history:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  isolation_id,
  device_id,
  status,
  approved_by,
  approved_at,
  network_state_changed,
  real_action_executed
FROM v2_endpoint_isolation_actions
ORDER BY isolation_id;

SELECT
  actor,
  action,
  target,
  result,
  details
FROM audit_events
WHERE action = 'approve_v2_stage7_endpoint_isolation'
ORDER BY event_id DESC;
"
```

### Endpoint-alert investigation

Review the investigation options:

```bash
python -m scripts.review_v2_stage7_endpoint_alert --help
```

The following controlled review has already been completed. Do not repeat it against the closed alert.

```bash
python -m scripts.review_v2_stage7_endpoint_alert \
  --alert-id 18 \
  --actor analyst01 \
  --classification "False Positive" \
  --notes "Reviewed three crash and restart events within seven minutes. The detected process is approved, and the registered device is compliant with a low-risk state. No malicious activity is established by this alert evidence."
```

Review the stored investigation:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  alert_id,
  detection_type,
  source_event_ids,
  device_id,
  process_name,
  status,
  classification,
  investigation_notes,
  reviewed_by,
  reviewed_at
FROM v2_endpoint_alerts
WHERE detection_type = 'Repeated Process Crash or Restart';

SELECT
  actor,
  action,
  target,
  result,
  details
FROM audit_events
WHERE action = 'review_v2_stage7_endpoint_alert'
ORDER BY event_id DESC;
"
```

Review configuration, schema and metadata:

```bash
python -m json.tool config/v2_endpoint_monitoring.json

stat -c '%a %n' \
  config/v2_endpoint_monitoring.json

grep -n \
  'CREATE TABLE IF NOT EXISTS v2_endpoint_' \
  database/schema.sql

sqlite3 -header -column database/netshield.db "
SELECT key, value
FROM system_metadata
WHERE key = 'v2_stage_7_status';
"
```

---

## Stage 8 — Vulnerability and application-security findings

Run vulnerability management twice:

```bash
python -m scripts.run_v2_stage8_vulnerability_management
python -m scripts.run_v2_stage8_vulnerability_management
```

Run the focused tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage8_vulnerability_management

python -m scripts.validate_v2_stage8
```

Review the stored findings:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_finding_id,
  title,
  finding_type,
  asset_id,
  severity,
  confidence,
  exploitability,
  exploitation_status,
  priority_score,
  priority_level,
  remediation_status,
  classification,
  reviewed_by
FROM v2_vulnerability_findings
ORDER BY priority_score DESC, source_finding_id;
"
```

Review findings by priority and status:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  priority_level,
  remediation_status,
  COUNT(*) AS finding_count
FROM v2_vulnerability_findings
GROUP BY priority_level, remediation_status
ORDER BY
  CASE priority_level
    WHEN 'Critical' THEN 1
    WHEN 'High' THEN 2
    WHEN 'Medium' THEN 3
    ELSE 4
  END,
  remediation_status;
"
```

Review remediation history:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_event_id,
  previous_status,
  new_status,
  verification_result
FROM v2_vulnerability_remediation_history
ORDER BY history_id;
"
```

Review finding links:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_finding_id,
  link_type,
  linked_record_id,
  exploitation_status,
  created_at
FROM v2_vulnerability_links
ORDER BY link_id;
"
```

Check duplicate protection:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  COUNT(*) AS stored_findings,
  COUNT(DISTINCT finding_key) AS unique_finding_keys
FROM v2_vulnerability_findings;

SELECT
  COUNT(*) AS history_records,
  COUNT(DISTINCT history_key) AS unique_history_keys
FROM v2_vulnerability_remediation_history;

SELECT
  COUNT(*) AS stored_links,
  COUNT(DISTINCT link_key) AS unique_link_keys
FROM v2_vulnerability_links;
"
```

Review the false-positive command:

```bash
python -m scripts.review_v2_stage8_vulnerability_finding --help
```

The following controlled review has already been completed. Do not repeat it against the reviewed finding.

```bash
python -m scripts.review_v2_stage8_vulnerability_finding \
  --finding-id S78-FND-FP-001 \
  --actor analyst01 \
  --notes "Reviewed the version-only match for demo-utility 3.0.0-simulated. The controlled evidence contains no exploitation activity and does not confirm that the component is vulnerable."
```

Review the stored false-positive investigation:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_finding_id,
  title,
  remediation_status,
  classification,
  investigation_notes,
  reviewed_by,
  reviewed_at
FROM v2_vulnerability_findings
WHERE source_finding_id = 'S78-FND-FP-001';

SELECT
  actor,
  action,
  target,
  result,
  details
FROM audit_events
WHERE action = 'review_v2_stage8_vulnerability_finding'
ORDER BY event_id DESC;
"
```

Review approved testing evidence:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_event_id,
  source_type,
  event_type,
  raw_event
FROM security_events
WHERE source_event_id IN (
  'S78-APPSEC-TEST-001',
  'S78-VULN-TEST-001'
)
ORDER BY source_event_id;
"
```

Review Stage 8 configuration, schema and metadata:

```bash
python -m json.tool config/v2_vulnerability_management.json

stat -c '%a %n' \
  config/v2_vulnerability_management.json

grep -n \
  'CREATE TABLE IF NOT EXISTS v2_vulnerability_' \
  database/schema.sql

sqlite3 -header -column database/netshield.db "
SELECT key, value
FROM system_metadata
WHERE key = 'v2_stage_8_status';
"
```

---

## Stage 9 — Continuous monitoring and dynamic risk scoring

Run the Stage 9 migration twice:

```bash
python -m scripts.initialize_v2_stage9
python -m scripts.initialize_v2_stage9
```

Run one scheduled monitoring cycle:

```bash
python -m scripts.run_v2_stage9_continuous_monitoring
```

Run the same interval again to check scheduled-cycle suppression:

```bash
python -m scripts.run_v2_stage9_continuous_monitoring
```

Force a controlled repeat to check alert cooldown behaviour:

```bash
python -m scripts.run_v2_stage9_continuous_monitoring \
  --force
```

Review the available monitoring options:

```bash
python -m scripts.run_v2_stage9_continuous_monitoring --help
```

Run the focused tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage9_continuous_monitoring

python -m scripts.validate_v2_stage9
```

Review current risk scores:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  entity_type,
  entity_id,
  risk_score,
  risk_level,
  independent_source_count,
  source_types,
  agreement_adjustment,
  exception_adjustment,
  decay_adjustment,
  last_evidence_time
FROM v2_continuous_risk_scores
ORDER BY risk_score DESC, entity_type, entity_id;
"
```

Review scores by entity and level:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  entity_type,
  risk_level,
  COUNT(*) AS entity_count
FROM v2_continuous_risk_scores
GROUP BY entity_type, risk_level
ORDER BY entity_type, risk_level;
"
```

Review monitoring cycles:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  cycle_id,
  scheduled_for,
  status,
  ingestion_status,
  detection_status,
  risk_status,
  records_assessed,
  entities_scored,
  alerts_created,
  alerts_suppressed,
  last_successful_run
FROM v2_monitoring_cycles
ORDER BY cycle_id;
"
```

Review threshold and health alerts:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  alert_type,
  entity_type,
  entity_id,
  component,
  risk_score,
  severity,
  status,
  occurrence_count,
  suppression_reason,
  cooldown_until
FROM v2_monitoring_alerts
ORDER BY alert_id;
"
```

Review component health:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  component,
  status,
  records_processed,
  consecutive_failures,
  last_successful_run
FROM v2_detection_health
ORDER BY component;
"
```

Check current-score and history duplicate protection:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  COUNT(*) AS current_scores,
  COUNT(DISTINCT risk_key) AS unique_risk_keys
FROM v2_continuous_risk_scores;

SELECT
  COUNT(*) AS history_records,
  COUNT(DISTINCT history_key) AS unique_history_keys
FROM v2_continuous_risk_history;

SELECT
  COUNT(*) AS monitoring_alerts,
  COUNT(DISTINCT alert_key) AS unique_alert_keys
FROM v2_monitoring_alerts;
"
```

Review Stage 9 configuration, schema and metadata:

```bash
python -m json.tool config/v2_continuous_monitoring.json

stat -c '%a %n' \
  config/v2_continuous_monitoring.json

grep -n -E \
  'CREATE TABLE IF NOT EXISTS v2_(monitoring|continuous|detection_health)' \
  database/schema.sql

sqlite3 -header -column database/netshield.db "
SELECT key, value
FROM system_metadata
WHERE key = 'v2_stage_9_status';

SELECT
  actor,
  action,
  target,
  result,
  details
FROM audit_events
WHERE action IN (
  'initialize_v2_stage9',
  'run_v2_stage9_continuous_monitoring'
)
ORDER BY event_id DESC
LIMIT 10;
"
```

---

## Stage 10 — XDR-style cross-source correlation

Run the Stage 10 migration twice:

```bash
python -m scripts.initialize_v2_stage10
python -m scripts.initialize_v2_stage10
```

Run XDR correlation:

```bash
python -m scripts.run_v2_stage10_xdr_correlation
```

Run it again to check duplicate protection:

```bash
python -m scripts.run_v2_stage10_xdr_correlation
```

Run the focused tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage10_xdr_correlation

python -m scripts.validate_v2_stage10
```

Review the stored incidents:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  incident_id,
  title,
  severity,
  confidence,
  independent_source_count,
  evidence_count,
  active_evidence_count,
  exception_count,
  verified_activity_count,
  status
FROM v2_xdr_incidents
ORDER BY incident_id;
"
```

Review incident evidence by source:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  incident_key,
  source_type,
  relationship,
  contribution_status,
  COUNT(*) AS evidence_records
FROM v2_xdr_incident_evidence
GROUP BY
  incident_key,
  source_type,
  relationship,
  contribution_status
ORDER BY
  incident_key,
  source_type,
  relationship,
  contribution_status;
"
```

Review indicator totals:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  indicator_type,
  classification,
  COUNT(*) AS records
FROM v2_xdr_indicators
GROUP BY indicator_type, classification
ORDER BY indicator_type, classification;
"
```

Review the explicit SQL injection link retained from Stage 8:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_finding_id,
  link_type,
  linked_record_id,
  exploitation_status,
  created_at
FROM v2_vulnerability_links
WHERE source_finding_id = 'S78-FND-SQL-001'
ORDER BY link_type;
"
```

Check incident totals and separated device chains:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  incident_id,
  primary_entity_type,
  primary_entity_id,
  severity,
  confidence,
  independent_source_count,
  evidence_count
FROM v2_xdr_incidents
ORDER BY primary_entity_type, primary_entity_id;
"
```

Review Stage 10 configuration, schema and metadata:

```bash
python -m json.tool config/v2_xdr_correlation.json

stat -c '%a %n' \
  config/v2_xdr_correlation.json

grep -n \
  'CREATE TABLE IF NOT EXISTS v2_xdr_' \
  database/schema.sql

sqlite3 -header -column database/netshield.db "
SELECT key, value
FROM system_metadata
WHERE key = 'v2_stage_10_status';

SELECT
  actor,
  action,
  target,
  result,
  details
FROM audit_events
WHERE action IN (
  'initialize_v2_stage10',
  'run_v2_stage10_xdr_correlation'
)
ORDER BY event_id DESC
LIMIT 10;
"
```

Confirm that no automatic Stage 10 response was created:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  COUNT(*) AS automatic_stage10_actions
FROM audit_events
WHERE action = 'run_v2_stage10_xdr_correlation'
  AND details LIKE '%automatic_action_executed%true%';
"
```

---

## Phase 3A V2 focused tests

Run all Phase 3A V2 focused test groups:

```bash
python -m unittest -v \
  tests.test_v2_stage1_foundation \
  tests.test_v2_stage2_pipeline \
  tests.test_v2_stage3_device_identity \
  tests.test_v2_stage3_device_alert_review \
  tests.test_v2_stage4_identity_monitoring \
  tests.test_v2_stage4_identity_review \
  tests.test_v2_stage5_access_policy \
  tests.test_v2_stage6_network_monitoring \
  tests.test_v2_stage6_network_alert_review \
  tests.test_v2_stage7_endpoint_monitoring \
  tests.test_v2_stage8_vulnerability_management \
  tests.test_v2_stage9_continuous_monitoring \
  tests.test_v2_stage10_xdr_correlation
```

Run the shared SQLite connection tests:

```bash
python -m unittest -v \
  tests.test_sqlite_connection
```

---

## Phase 3A V2 validators

```bash
python -m scripts.validate_v2_stage1
python -m scripts.validate_v2_stage2
python -m scripts.validate_v2_stage3
python -m scripts.validate_v2_stage4
python -m scripts.validate_v2_stage5
python -m scripts.validate_v2_stage6
python -m scripts.validate_v2_stage7
python -m scripts.validate_v2_stage8
python -m scripts.validate_v2_stage9
python -m scripts.validate_v2_stage10
```

---

## Complete project validation

Compile all Python source:

```bash
python -m compileall -q \
  src \
  scripts \
  tests \
  lab
```

Run all V2 validators:

```bash
python -m scripts.validate_v2_stage1
python -m scripts.validate_v2_stage2
python -m scripts.validate_v2_stage3
python -m scripts.validate_v2_stage4
python -m scripts.validate_v2_stage5
python -m scripts.validate_v2_stage6
python -m scripts.validate_v2_stage7
python -m scripts.validate_v2_stage8
python -m scripts.validate_v2_stage9
python -m scripts.validate_v2_stage10
```

Run the original Phase 3 full-project validator:

```bash
python -m scripts.validate_stage11
```

Run the complete unit-test suite:

```bash
python -m unittest discover -s tests
```

Check for unclosed SQLite connection warnings:

```bash
(
  set -o pipefail

  PYTHONTRACEMALLOC=5 \
  python -W always::ResourceWarning \
    -m unittest discover -s tests 2>&1 |
    tee /tmp/netshield_resource_check.log
)

echo
echo "RESOURCE WARNINGS"

grep -c \
  'ResourceWarning: unclosed database' \
  /tmp/netshield_resource_check.log \
  || true
```

Check SQLite integrity and foreign keys:

```bash
sqlite3 database/netshield.db "
PRAGMA integrity_check;
PRAGMA foreign_key_check;
"
```

Check repository whitespace:

```bash
git diff --check
git diff --cached --check
```

Review the final repository state:

```bash
git status --short --branch
```

---

## Documentation checks

```bash
for file in \
  README.md \
  docs/workflow.md \
  docs/security_logic.md \
  docs/notes.md \
  docs/commands.md \
  docs/handbook.md
do
  test -s "$file" \
    && echo "PASS: $file exists and is not empty" \
    || {
      echo "FAIL: $file is missing or empty"
      exit 1
    }
done

git diff --check
```

---

## Git review

Review the working tree without opening the pager:

```bash
git status --short --branch
git --no-pager diff --stat
git --no-pager diff
git --no-pager log --oneline --decorate -5
```

Review staged changes:

```bash
git diff --cached --check
git --no-pager diff --cached --stat
git --no-pager diff --cached --name-status
```

Check that runtime files have not been staged:

```bash
git diff --cached --name-only | \
  grep -E '(\.venv|__pycache__|\.pyc$|\.db$|\.sqlite$|\.log$|lab/sql_injection/(data|logs|outputs))' \
  && echo "ERROR: Runtime file staged" \
  || echo "PASS: No runtime files staged"
```

---

## Runtime files

Runtime databases, logs, evidence and generated outputs remain outside Git tracking.

The SQL injection lab runtime directories are excluded:

```text
lab/sql_injection/data/
lab/sql_injection/logs/
lab/sql_injection/outputs/
```

Sanitised Phase 3 output fixtures required by inherited tests are tracked separately:

```text
tests/fixtures/phase3_outputs/
```
