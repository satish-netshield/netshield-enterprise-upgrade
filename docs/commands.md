# Commands

## Working directory

```bash
cd /home/netshield01/netshield-phase3
```

## Python environment

```bash
source .venv/bin/activate
```

## Compilation

```bash
python -m compileall -q src scripts tests lab
```

## Stage 1

Initialise:

```bash
python -m scripts.initialize_stage1
```

Validate:

```bash
python -m scripts.validate_stage1
```

## Stage 2

Initialise:

```bash
python -m scripts.initialize_stage2
```

Generate simulated events:

```bash
python -m scripts.generate_stage2_events
wc -l data/raw/*.jsonl
```

Import events:

```bash
python -m scripts.import_stage2_events
```

Validate:

```bash
python -m scripts.validate_stage2
```

## Stage 3

Validate the configuration:

```bash
python -m json.tool config/identity_detection.json > /dev/null
```

Generate identity events:

```bash
python -m scripts.generate_stage3_events
wc -l data/raw/stage3/authentication_stage3_events.jsonl
```

Import identity events:

```bash
python -m scripts.import_stage3_events
```

Initialise Stage 3 storage:

```bash
python -m scripts.initialize_stage3
```

Run identity detection:

```bash
python -m scripts.run_stage3_detection
```

Classify the approved replacement-device false positive:

```bash
python -m scripts.investigate_stage3_false_positive
```

Validate Stage 3:

```bash
python -m scripts.validate_stage3
```

## Stage 4

Validate the configuration:

```bash
python -m json.tool config/network_detection.json > /dev/null
```

Generate network and Wi-Fi events:

```bash
python -m scripts.generate_stage4_events
```

Review generated event counts:

```bash
wc -l \
  data/raw/stage4/network_stage4_events.jsonl \
  data/raw/stage4/wifi_stage4_events.jsonl
```

Generate correlation events:

```bash
python -m scripts.generate_stage4_correlation_events
```

Review correlation-event counts:

```bash
wc -l \
  data/raw/stage4/network_correlation_stage4_events.jsonl \
  data/raw/stage4/wifi_correlation_stage4_events.jsonl
```

Initialise Stage 4 storage:

```bash
python -m scripts.initialize_stage3
```

Import Stage 4 events:

```bash
python -m scripts.import_stage4_events
```

Run network and Wi-Fi detection:

```bash
python -m scripts.run_stage4_detection
```

Validate Stage 4:

```bash
python -m scripts.validate_stage4
```

## Stage 5

Validate the configuration:

```bash
python -m json.tool config/endpoint_detection.json > /dev/null
```

Generate endpoint and wired-LAN events:

```bash
python -m scripts.generate_stage5_events
```

Review generated event counts:

```bash
wc -l \
  data/raw/stage5/endpoint_stage5_events.jsonl \
  data/raw/stage5/network_stage5_events.jsonl
```

Initialise Stage 5 storage:

```bash
python -m scripts.initialize_stage5
```

Import Stage 5 events:

```bash
python -m scripts.import_stage5_events
```

Run endpoint and wired-LAN detection:

```bash
python -m scripts.run_stage5_detection
```

Validate Stage 5:

```bash
python -m scripts.validate_stage5
```

## Stage 6 — SQL injection detection

Initialise the isolated local lab:

```bash
python -m lab.sql_injection.app
```

Run Stage 6 unit tests:

```bash
python -m unittest -v lab.sql_injection.test_lab
```

Compile the Stage 6 files:

```bash
python -m py_compile \
  lab/sql_injection/app.py \
  lab/sql_injection/test_lab.py \
  lab/sql_injection/generate_requests.py \
  lab/sql_injection/detect_stage6.py \
  lab/sql_injection/validate_stage6.py
```

Generate controlled SQL injection requests:

```bash
python -m lab.sql_injection.generate_requests
```

Review request evidence:

```bash
cat lab/sql_injection/data/stage6_requests.jsonl
```

Run Stage 6 detection:

```bash
python -m lab.sql_injection.detect_stage6
```

Review the detection report:

```bash
cat lab/sql_injection/outputs/stage6_detection_report.json
```

Validate Stage 6:

```bash
python -m lab.sql_injection.validate_stage6
```

Archive a cumulative application log before a clean run:

```bash
mkdir -p lab/sql_injection/logs/archive

mv lab/sql_injection/logs/application_events.jsonl \
  lab/sql_injection/logs/archive/application_events_before_clean_run.jsonl
```

Run the clean Stage 6 evidence cycle:

```bash
python -m lab.sql_injection.generate_requests
python -m lab.sql_injection.detect_stage6
python -m lab.sql_injection.validate_stage6
```

Review clean application events:

```bash
cat lab/sql_injection/logs/application_events.jsonl
```

## Stage 7 — Event correlation, risk scoring and IoC extraction

Validate the configuration:

```bash
python -m json.tool config/stage7_correlation.json > /dev/null
```

Compile the Stage 7 files:

```bash
python -m py_compile \
  src/correlation/stage7_engine.py \
  scripts/generate_stage7_events.py \
  scripts/run_stage7_correlation.py \
  scripts/validate_stage7.py \
  tests/test_stage7_correlation.py
```

Generate controlled correlation events:

```bash
python scripts/generate_stage7_events.py
```

Review the generated events:

```bash
cat lab/sql_injection/data/stage7_correlation_events.jsonl
```

Run event correlation and risk scoring:

```bash
python scripts/run_stage7_correlation.py
```

Review the Stage 7 report:

```bash
cat lab/sql_injection/outputs/stage7_correlation_report.json
```

Run Stage 7 unit tests:

```bash
python -m unittest -v tests.test_stage7_correlation
```

Validate Stage 7:

```bash
python scripts/validate_stage7.py
```

## Unit tests

Stage 1:

```bash
python -m unittest -v tests.test_stage1_controls
```

Stage 2 normalisation:

```bash
python -m unittest -v tests.test_stage2_normalizer
```

Stage 2 pipeline:

```bash
python -m unittest -v tests.test_stage2_pipeline
```

Stage 3 identity detection:

```bash
python -m unittest -v tests.test_stage3_identity_detector
```

Stage 4 network correlation:

```bash
python -m unittest -v tests.test_stage4_network_correlation
```

Stage 5 endpoint detection:

```bash
python -m unittest -v tests.test_stage5_endpoint_detector
```

Stage 6 SQL injection lab:

```bash
python -m unittest -v lab.sql_injection.test_lab
```

Stage 7 correlation:

```bash
python -m unittest -v tests.test_stage7_correlation
```

All current tests:

```bash
python -m unittest -v \
  tests.test_stage1_controls \
  tests.test_stage2_normalizer \
  tests.test_stage2_pipeline \
  tests.test_stage3_identity_detector \
  tests.test_stage4_network_correlation \
  tests.test_stage5_endpoint_detector \
  lab.sql_injection.test_lab \
  tests.test_stage7_correlation
```

## Complete validation

Compile all project files:

```bash
python -m compileall -q src scripts tests lab
```

Run all tests:

```bash
python -m unittest -q \
  tests.test_stage1_controls \
  tests.test_stage2_normalizer \
  tests.test_stage2_pipeline \
  tests.test_stage3_identity_detector \
  tests.test_stage4_network_correlation \
  tests.test_stage5_endpoint_detector \
  lab.sql_injection.test_lab \
  tests.test_stage7_correlation
```

Run the Stage 1–5 validators:

```bash
python -m scripts.validate_stage1
python -m scripts.validate_stage2
python -m scripts.validate_stage3
python -m scripts.validate_stage4
python -m scripts.validate_stage5
```

Run the Stage 6 validator:

```bash
python -m lab.sql_injection.validate_stage6
```

Run the Stage 7 validator:

```bash
python scripts/validate_stage7.py
```

Check documentation and Git whitespace:

```bash
git diff --check
```

## Stage 6 database review

Open the isolated Stage 6 database:

```bash
sqlite3 lab/sql_injection/data/sql_injection_lab.db
```

Useful commands:

```text
.tables
.schema users
SELECT * FROM users;
.quit
```

Review Stage 6 request evidence:

```bash
cat lab/sql_injection/data/stage6_requests.jsonl
```

Review Stage 6 application events:

```bash
cat lab/sql_injection/logs/application_events.jsonl
```

Review Stage 6 detection report:

```bash
cat lab/sql_injection/outputs/stage6_detection_report.json
```

## Stage 7 report review

Review the Stage 7 correlation report:

```bash
cat lab/sql_injection/outputs/stage7_correlation_report.json
```

Review only incident severity and scores:

```bash
python -c "
import json
from pathlib import Path

report = json.loads(
    Path(
        'lab/sql_injection/outputs/stage7_correlation_report.json'
    ).read_text(encoding='utf-8')
)

for incident in report['incidents']:
    print(
        incident['severity'],
        incident['risk_score'],
        incident['event_count'],
        len(incident['iocs']),
        len(incident['behaviours'])
    )
"
```

## Main database review

Open the main NetShield database:

```bash
sqlite3 database/netshield.db
```

Useful commands:

```text
.tables
.schema security_events
.schema identity_alerts
.schema network_alerts
.schema endpoint_alerts
.quit
```

Review event totals:

```sql
SELECT source_type, COUNT(*) AS total_events
FROM security_events
GROUP BY source_type
ORDER BY source_type;
```

Review identity alerts:

```sql
SELECT
    alert_id,
    detection_type,
    severity,
    username,
    hostname,
    location,
    status,
    classification
FROM identity_alerts
ORDER BY alert_id;
```

Review network alerts:

```sql
SELECT
    alert_id,
    detection_type,
    severity,
    mac_address,
    ip_address,
    hostname,
    location,
    status
FROM network_alerts
ORDER BY alert_id;
```

Review endpoint alerts:

```sql
SELECT
    alert_id,
    detection_type,
    severity,
    mac_address,
    hostname,
    username,
    location,
    process_name,
    cpu_percent,
    status
FROM endpoint_alerts
ORDER BY alert_id;
```

Review rejected records:

```sql
SELECT source_file, line_number, reason
FROM rejected_events
ORDER BY rejection_id;
```

Review import batches:

```sql
SELECT
    source_file,
    total_records,
    accepted_records,
    rejected_records,
    status
FROM import_batches
ORDER BY started_at;
```

Review audit activity:

```sql
SELECT
    event_id,
    event_time,
    actor,
    action,
    target,
    result,
    details
FROM audit_events
ORDER BY event_id;
```

Review stage metadata:

```sql
SELECT key, value
FROM system_metadata
ORDER BY key;
```

## Evidence verification

Verify the Stage 1 evidence hash:

```bash
sha256sum --check evidence/stage1_permission_test.sha256
```

Review the archived Stage 6 log:

```bash
cat lab/sql_injection/logs/archive/application_events_before_clean_run.jsonl
```

## Git review

Check repository status:

```bash
git status
```

Review unstaged changes:

```bash
git diff
```

Check unstaged whitespace:

```bash
git diff --check
```

Check staged whitespace:

```bash
git diff --cached --check
```

Review recent commits:

```bash
git log --oneline --decorate -5
```
