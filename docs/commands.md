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

Phase 3A V2 extends the completed Phase 3 Automation project. The original components are verified before and after upgrade work.

```bash
python -m unittest discover -s tests
python -m scripts.validate_stage11
```

The Stage 8–10 results printed by the original Stage 11 validator refer to the completed Phase 3 project. They are separate from the Phase 3A V2 stage validators.

## Stage 1 — Enterprise project foundation

Initialise and validate the V2 foundation:

```bash
python -m scripts.initialize_v2_stage1
python -m scripts.validate_v2_stage1

python -m unittest -v \
  tests.test_v2_stage1_foundation
```

Review the simulated enterprise context and project settings:

```bash
python -m json.tool config/enterprise_context.json
python -m json.tool config/settings.json
```

Review simulated user-role assignments:

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

Review protected file and directory permissions:

```bash
stat -c '%a %n' \
  config \
  config/settings.json \
  database \
  database/netshield.db \
  evidence
```

## Stage 2 — Extended security data pipeline

Run the repeatable database migration twice:

```bash
python -m scripts.initialize_v2_stage2
python -m scripts.initialize_v2_stage2
```

Generate and import the V2 events:

```bash
python -m scripts.generate_v2_stage2_events
python -m scripts.import_v2_stage2_events
```

Run the import again to check duplicate-event protection:

```bash
python -m scripts.import_v2_stage2_events
```

Run the Stage 2 tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage2_pipeline

python -m scripts.validate_v2_stage2
```

Review the V2 source files:

```bash
find data/raw/v2 \
  -maxdepth 1 \
  -type f \
  -name '*.jsonl' \
  -print | sort

wc -l data/raw/v2/*.jsonl
```

Review accepted V2 events by source:

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

Review V2 ingestion batches:

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

## Stage 3 — Enterprise asset and device identity

Initialise the approved device inventory and run the detector:

```bash
python -m scripts.initialize_v2_stage3
python -m scripts.run_v2_stage3_device_identity
```

Run the detector again to check duplicate-alert protection:

```bash
python -m scripts.run_v2_stage3_device_identity
```

Run the Stage 3 tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage3_device_identity \
  tests.test_v2_stage3_device_alert_review

python -m scripts.validate_v2_stage3
```

Review the device inventory and stored alerts:

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
"

sqlite3 -header -column database/netshield.db "
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

Review the controlled device-management and alert-review options:

```bash
python -m scripts.manage_v2_stage3_device --help
python -m scripts.review_v2_stage3_device_alert --help
```

## Combined Stage 4–5 setup

Run the shared Stage 4–5 database migration twice:

```bash
python -m scripts.initialize_v2_stage4_5
python -m scripts.initialize_v2_stage4_5
```

Generate and import the controlled Stage 4–5 events:

```bash
python -m scripts.generate_v2_stage4_5_events
python -m scripts.import_v2_stage4_5_events
```

Review the source-file totals:

```bash
find data/raw/v2/stage4_5 \
  -maxdepth 1 \
  -type f \
  -name '*.jsonl' \
  -printf '%f %s bytes\n' | sort

wc -l data/raw/v2/stage4_5/*.jsonl
```

Review accepted Stage 4–5 events:

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

Review the Stage 4–5 tables:

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
```

Review the Stage 4–5 configuration permissions:

```bash
stat -c '%a %n' \
  config/v2_identity_monitoring.json \
  config/v2_access_policy.json
```

## Stage 4 — Identity monitoring and risk detection

Run identity monitoring:

```bash
python -m scripts.run_v2_stage4_identity_monitoring
```

Run it again to check duplicate-alert protection:

```bash
python -m scripts.run_v2_stage4_identity_monitoring
```

Run the Stage 4 tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage4_identity_monitoring \
  tests.test_v2_stage4_identity_review

python -m scripts.validate_v2_stage4
```

Review the identity alerts:

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

Review alert totals by detection type:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  detection_type,
  COUNT(*) AS alert_count
FROM v2_identity_alerts
GROUP BY detection_type
ORDER BY detection_type;
"
```

Check identity-alert duplicate protection:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  COUNT(*) AS stored_alerts,
  COUNT(DISTINCT alert_key) AS unique_alert_keys
FROM v2_identity_alerts;
"
```

Review the controlled false-positive investigation:

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
"

sqlite3 -header -column database/netshield.db "
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

Review the Stage 4 alert-review options:

```bash
python -m scripts.review_v2_stage4_identity_alert --help
```

## Stage 5 — Zero Trust and policy-based access decisions

Run the local access-policy engine:

```bash
python -m scripts.run_v2_stage5_access_policy
```

Run it again to check duplicate-decision protection:

```bash
python -m scripts.run_v2_stage5_access_policy
```

Run the Stage 5 tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage5_access_policy

python -m scripts.validate_v2_stage5
```

Review the stored access decisions:

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

Review decision totals:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  decision,
  COUNT(*) AS decision_count
FROM access_policy_decisions
GROUP BY decision
ORDER BY decision;
"
```

Check decision duplicate protection:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  COUNT(*) AS stored_decisions,
  COUNT(DISTINCT decision_key) AS unique_decision_keys
FROM access_policy_decisions;
"
```

Review policy and ACL configuration:

```bash
python -m json.tool config/v2_access_policy.json
python -m json.tool config/rbac.json
python -m json.tool config/automation_acl.json
```

## Stage 6 — Network, Wi-Fi and access monitoring

Run the Stage 6 database migration twice:

```bash
python -m scripts.initialize_v2_stage6
python -m scripts.initialize_v2_stage6
```

Generate and import the controlled network and Wi-Fi events:

```bash
python -m scripts.generate_v2_stage6_events
python -m scripts.import_v2_stage6_events
```

Review the Stage 6 source files:

```bash
find data/raw/v2/stage6 \
  -maxdepth 1 \
  -type f \
  -name '*.jsonl' \
  -printf '%f %s bytes\n' | sort

wc -l data/raw/v2/stage6/*.jsonl
```

Review imported Stage 6 events:

```bash
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

Run Stage 6 network monitoring:

```bash
python -m scripts.run_v2_stage6_network_monitoring
```

Run it again to check alert, decision and timeline duplicate protection:

```bash
python -m scripts.run_v2_stage6_network_monitoring
```

Run the Stage 6 tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage6_network_monitoring \
  tests.test_v2_stage6_network_alert_review

python -m scripts.validate_v2_stage6
```

Review Stage 6 alert totals:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  detection_type,
  severity,
  confidence,
  COUNT(*) AS alert_count
FROM v2_network_alerts
GROUP BY
  detection_type,
  severity,
  confidence
ORDER BY detection_type;
"
```

Review the stored network alerts:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  alert_id,
  detection_type,
  severity,
  confidence,
  device_id,
  ip_address,
  location,
  reason_codes,
  status
FROM v2_network_alerts
ORDER BY alert_id;
"
```

Review network-access decision totals:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  decision,
  COUNT(*) AS decision_count
FROM v2_network_access_decisions
GROUP BY decision
ORDER BY decision;
"
```

Review stored network-access decisions:

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

Check Stage 6 duplicate protection:

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

Review the controlled Stage 6 false-positive investigation:

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
"

sqlite3 -header -column database/netshield.db "
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

Review the Stage 6 configuration and protected-file permission:

```bash
python -m json.tool config/v2_network_monitoring.json

stat -c '%a %n' \
  config/v2_network_monitoring.json
```

Review the controlled IP blocklist entry:

```bash
grep -n '198.51.100.66' \
  data/blocklists/ip_blocklist.txt
```

## Stage 7 — Endpoint monitoring and investigation

### Existing shared preparation

Stage 7 and Stage 8 share database preparation, event generation and import. Their monitoring and vulnerability engines run separately.

The preparation is already complete. Repeat it only when checking migration or import behaviour, or rebuilding the controlled inputs.

```bash
python -m scripts.initialize_v2_stage7_8
python -m scripts.initialize_v2_stage7_8

python -m scripts.generate_v2_stage7_8_events
python -m scripts.import_v2_stage7_8_events
```

Run the shared import again to check duplicate-event protection:

```bash
python -m scripts.import_v2_stage7_8_events
```

Review the prepared source files:

```bash
find data/raw/v2/stage7_8 \
  -maxdepth 1 \
  -type f \
  -name '*.jsonl' \
  -printf '%f %s bytes\n' | sort

wc -l data/raw/v2/stage7_8/*.jsonl
```

Review accepted Stage 7 endpoint events only:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_file,
  source_type,
  COUNT(*) AS stored_events,
  COUNT(DISTINCT source_event_id) AS unique_events
FROM security_events
WHERE source_file = 'endpoint_v2_stage7_8_events.jsonl'
GROUP BY source_file, source_type;
"
```

### Endpoint monitoring

Run Stage 7 endpoint monitoring:

```bash
python -m scripts.run_v2_stage7_endpoint_monitoring
```

Run it again to check duplicate protection and preservation of reviews and approvals:

```bash
python -m scripts.run_v2_stage7_endpoint_monitoring
```

Run the Stage 7 tests and validator:

```bash
python -m unittest -v \
  tests.test_v2_stage7_endpoint_monitoring

python -m scripts.validate_v2_stage7
```

### Endpoint alerts and timeline

Review stored endpoint alerts:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  alert_id,
  source_event_ids,
  detection_type,
  severity,
  confidence,
  device_id,
  process_name,
  process_owner,
  parent_process_name,
  reason_codes,
  status,
  classification
FROM v2_endpoint_alerts
ORDER BY alert_id;
"
```

Review alert totals:

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

Review the endpoint activity timeline:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_event_id,
  event_time,
  event_type,
  device_id,
  username,
  health_state,
  compliance_state,
  device_risk_state,
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

### Simulated isolation and approval

Review the current isolation records before performing any approval:

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

Review the approval command options:

```bash
python -m scripts.approve_v2_stage7_endpoint_isolation --help
```

The following command was used to approve the controlled request. It updates the project record only and performs no real isolation.

Record `11` is already approved in the current database. Do not repeat this as a routine validation command. For another database, verify the request ID and pending status first.

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
  json_extract(
    evidence,
    '$.simulated_approval.approver_role'
  ) AS approver_role,
  json_extract(
    evidence,
    '$.simulated_approval.notes'
  ) AS approval_notes,
  network_state_changed,
  real_action_executed
FROM v2_endpoint_isolation_actions
ORDER BY isolation_id;
"

sqlite3 -header -column database/netshield.db "
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

Review the endpoint-alert review options:

```bash
python -m scripts.review_v2_stage7_endpoint_alert --help
```

The following command was used for the controlled false-positive investigation. It changes the alert classification and investigation state.

Alert `18` is already closed in the current database. Do not repeat this as a routine validation command. Verify the alert ID, status and evidence before reviewing another record.

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
"

sqlite3 -header -column database/netshield.db "
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

### Configuration, schema and completion records

Review the Stage 7 configuration and permission:

```bash
python -m json.tool config/v2_endpoint_monitoring.json

stat -c '%a %n' \
  config/v2_endpoint_monitoring.json
```

Review the tracked Stage 7 table definitions:

```bash
grep -n \
  'CREATE TABLE IF NOT EXISTS v2_endpoint_' \
  database/schema.sql
```

Inspect complete working table definitions, including constraints:

```bash
sqlite3 database/netshield.db "
SELECT sql
FROM sqlite_master
WHERE type = 'table'
  AND name IN (
    'v2_endpoint_alerts',
    'v2_endpoint_activity_timeline',
    'v2_endpoint_isolation_actions'
  )
ORDER BY name;
"
```

Review Stage 7 metadata and audit records:

```bash
sqlite3 -header -column database/netshield.db "
SELECT key, value
FROM system_metadata
WHERE key = 'v2_stage_7_status';

SELECT
  actor,
  action,
  target,
  result,
  details
FROM audit_events
WHERE action IN (
  'initialize_v2_stage7_8',
  'import_v2_stage7_8_events',
  'run_v2_stage7_endpoint_monitoring',
  'approve_v2_stage7_endpoint_isolation',
  'review_v2_stage7_endpoint_alert'
)
ORDER BY event_id DESC
LIMIT 10;
"
```

## Stage 8 — Vulnerability and application-security findings

The shared Stage 7–8 preparation commands create and import the controlled Stage 8 inputs. Run them only when rebuilding the source data or checking repeatable migration and import behaviour.

Review the accepted Stage 8 events:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_file,
  source_type,
  COUNT(*) AS stored_events,
  COUNT(DISTINCT source_event_id) AS unique_events
FROM security_events
WHERE source_file IN (
  'application_security_v2_stage7_8_events.jsonl',
  'vulnerability_v2_stage7_8_events.jsonl'
)
GROUP BY source_file, source_type
ORDER BY source_file;
"
```

Run Stage 8 vulnerability management:

```bash
python -m scripts.run_v2_stage8_vulnerability_management
```

Run it again to check finding, history and link duplicate protection and preservation of the completed review:

```bash
python -m scripts.run_v2_stage8_vulnerability_management
```

Run the Stage 8 tests and validator:

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
  asset_id,
  finding_source,
  severity,
  confidence,
  exploitability,
  exploitation_status,
  exposure_level,
  exposed_service,
  asset_criticality,
  priority_score,
  priority_level,
  remediation_status,
  classification,
  reviewed_by
FROM v2_vulnerability_findings
ORDER BY priority_score DESC, source_finding_id;
"
```

Review finding totals by priority and remediation status:

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
    WHEN 'Low' THEN 4
  END,
  remediation_status;
"
```

Review remediation and verification history:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  history_id,
  source_finding_id,
  source_event_id,
  previous_status,
  new_status,
  verification_result,
  recorded_at
FROM v2_vulnerability_remediation_history
ORDER BY history_id;
"
```

Review finding-to-alert and finding-to-incident links:

```bash
sqlite3 -header -column database/netshield.db "
SELECT
  source_finding_id,
  link_type,
  linked_record_id,
  exploitation_status,
  created_at
FROM v2_vulnerability_links
ORDER BY link_type, linked_record_id;
"
```

Check Stage 8 duplicate protection:

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

Review the Stage 8 finding-review options:

```bash
python -m scripts.review_v2_stage8_vulnerability_finding --help
```

Review the completed false-positive investigation:

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

Review the Stage 8 configuration and protected-file permission:

```bash
python -m json.tool config/v2_vulnerability_management.json

python -m json.tool \
  lab/sql_injection/outputs/stage6_detection_report.json

stat -c '%a %n' \
  config/v2_vulnerability_management.json
```

Review the tracked Stage 8 table definitions:

```bash
grep -n \
  'CREATE TABLE IF NOT EXISTS v2_vulnerability_' \
  database/schema.sql
```

Inspect the complete working table definitions and named indexes:

```bash
sqlite3 database/netshield.db "
SELECT type, name, sql
FROM sqlite_master
WHERE sql IS NOT NULL
  AND (
    name LIKE 'v2_vulnerability_%'
    OR (
      type = 'index'
      AND tbl_name LIKE 'v2_vulnerability_%'
    )
  )
ORDER BY
  CASE type WHEN 'table' THEN 0 ELSE 1 END,
  name;
"
```

Review Stage 8 completion metadata and audit records:

```bash
sqlite3 -header -column database/netshield.db "
SELECT key, value
FROM system_metadata
WHERE key = 'v2_stage_8_status';

SELECT
  actor,
  action,
  target,
  result,
  details
FROM audit_events
WHERE action IN (
  'initialize_v2_stage7_8',
  'import_v2_stage7_8_events',
  'run_v2_stage8_vulnerability_management',
  'review_v2_stage8_vulnerability_finding'
)
ORDER BY event_id DESC
LIMIT 12;
"
```

## Phase 3A V2 focused tests

Run the V2 Stage 1–8 test groups:

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
  tests.test_v2_stage8_vulnerability_management
```

Run the SQLite connection tests:

```bash
python -m unittest -v \
  tests.test_sqlite_connection
```

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
```

## Complete project validation

Compile the Python source:

```bash
python -m compileall -q \
  src \
  scripts \
  tests \
  lab
```

Run the complete unit-test suite:

```bash
python -m unittest discover -s tests
```

Run the V2 validators and original Phase 3 full-project validator:

```bash
python -m scripts.validate_v2_stage1
python -m scripts.validate_v2_stage2
python -m scripts.validate_v2_stage3
python -m scripts.validate_v2_stage4
python -m scripts.validate_v2_stage5
python -m scripts.validate_v2_stage6
python -m scripts.validate_v2_stage7
python -m scripts.validate_v2_stage8

python -m scripts.validate_stage11
```

Check SQLite integrity and foreign keys:

```bash
sqlite3 database/netshield.db "
PRAGMA integrity_check;
PRAGMA foreign_key_check;
"
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

Check repository whitespace:

```bash
git diff --check
git diff --cached --check
```

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

## Git review

Review the working tree without opening the Git pager:

```bash
git status --short --branch
git --no-pager diff --stat
git --no-pager diff
git --no-pager log --oneline --decorate -5
```

Review staged changes without opening the Git pager:

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

## Runtime files

Runtime databases, logs, evidence and generated outputs remain outside Git tracking.

The SQL injection lab runtime directories are also excluded:

```text
lab/sql_injection/data/
lab/sql_injection/logs/
lab/sql_injection/outputs/
```

Sanitised Phase 3 output fixtures required by inherited unit tests are tracked separately:

```text
tests/fixtures/phase3_outputs/
```
