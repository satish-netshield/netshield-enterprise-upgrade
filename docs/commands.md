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

## Stage 1 — Enterprise project foundation

Initialise and validate the V2 foundation:

```bash
python -m scripts.initialize_v2_stage1
python -m scripts.validate_v2_stage1

python -m unittest -v tests.test_v2_stage1_foundation
```

Review the simulated enterprise context and project settings:

```bash
python -m json.tool config/enterprise_context.json
python -m json.tool config/settings.json
```

Review the simulated user-role assignments:

```bash
sqlite3 database/netshield.db "
SELECT username, role, active
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

Run the repeatable database migration:

```bash
python -m scripts.initialize_v2_stage2
```

Run it again to confirm that existing columns are not duplicated:

```bash
python -m scripts.initialize_v2_stage2
```

Generate and import the V2 events:

```bash
python -m scripts.generate_v2_stage2_events
python -m scripts.import_v2_stage2_events
```

Run the import again to confirm duplicate-event protection:

```bash
python -m scripts.import_v2_stage2_events
```

Run the Stage 2 tests and validator:

```bash
python -m unittest -v tests.test_v2_stage2_pipeline
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
sqlite3 database/netshield.db "
SELECT source_type, COUNT(*) AS accepted_events
FROM security_events
WHERE schema_version = '2.0'
  AND source_file LIKE '%_v2_events.jsonl'
GROUP BY source_type
ORDER BY source_type;
"
```

Review quarantined malformed records:

```bash
sqlite3 database/netshield.db "
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
sqlite3 database/netshield.db "
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

Initialise the device inventory and run the detector:

```bash
python -m scripts.initialize_v2_stage3
python -m scripts.run_v2_stage3_device_identity
```

Run the detector again to confirm duplicate-alert protection:

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

Review the stored inventory and device alerts:

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

Review the controlled management and alert-review commands:

```bash
python -m scripts.manage_v2_stage3_device --help
python -m scripts.review_v2_stage3_device_alert --help
```

## Phase 3A V2 Stage 1–3 tests

```bash
python -m unittest -v \
  tests.test_v2_stage1_foundation \
  tests.test_v2_stage2_pipeline \
  tests.test_v2_stage3_device_identity \
  tests.test_v2_stage3_device_alert_review
```

## Phase 3A V2 Stage 1–3 validators

```bash
python -m scripts.validate_v2_stage1
python -m scripts.validate_v2_stage2
python -m scripts.validate_v2_stage3
```

## Complete project validation

```bash
python -m compileall -q src scripts tests lab

python -m unittest discover -s tests

python -m scripts.validate_v2_stage1
python -m scripts.validate_v2_stage2
python -m scripts.validate_v2_stage3
python -m scripts.validate_stage11

git diff --check
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
git log --oneline --decorate -5
```

Review staged changes:

```bash
git diff --cached --check
git diff --cached --stat
git diff --cached --name-status
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
