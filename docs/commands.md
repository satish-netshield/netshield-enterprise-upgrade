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
python -m compileall -q src scripts tests
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

All current tests:

```bash
python -m unittest -v \
  tests.test_stage1_controls \
  tests.test_stage2_normalizer \
  tests.test_stage2_pipeline \
  tests.test_stage3_identity_detector \
  tests.test_stage4_network_correlation
```

## Complete validation

```bash
python -m compileall -q src scripts tests

python -m unittest -q \
  tests.test_stage1_controls \
  tests.test_stage2_normalizer \
  tests.test_stage2_pipeline \
  tests.test_stage3_identity_detector \
  tests.test_stage4_network_correlation

python -m scripts.validate_stage1
python -m scripts.validate_stage2
python -m scripts.validate_stage3
python -m scripts.validate_stage4

git diff --check
```

## Database review

Open SQLite:

```bash
sqlite3 database/netshield.db
```

Useful commands:

```text
.tables
.schema security_events
.schema identity_alerts
.schema network_alerts
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

```bash
sha256sum --check evidence/stage1_permission_test.sha256
```

## Git review

```bash
git status
git diff
git diff --check
git diff --cached --check
git log --oneline --decorate -5
```
