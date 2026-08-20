# Commands

## Working directory

Run project commands from the repository root:

```bash
cd /home/netshield01/netshield-phase3
```

## Python environment

Activate the project environment:

```bash
source .venv/bin/activate
```

## Stage 1 initialisation

```bash
python -m scripts.initialize_stage1
```

## Stage 2 initialisation

```bash
python -m scripts.initialize_stage2
```

## Generate Stage 2 events

```bash
python -m scripts.generate_stage2_events
```

Count the generated records:

```bash
wc -l data/raw/*.jsonl
```

## Import Stage 2 events

```bash
python -m scripts.import_stage2_events
```

The first import accepts the valid records and preserves the malformed records.

Running the same import again does not create duplicate accepted events. Previously accepted source events are recorded as rejected duplicates.

## Python compilation

Compile all current Python files:

```bash
python -m compileall -q src scripts tests
```

## Unit tests

Run the Stage 1 tests:

```bash
python -m unittest -v tests.test_stage1_controls
```

Run the Stage 2 normalisation tests:

```bash
python -m unittest -v tests.test_stage2_normalizer
```

Run the Stage 2 pipeline tests:

```bash
python -m unittest -v tests.test_stage2_pipeline
```

Run all current tests:

```bash
python -m unittest -v \
  tests.test_stage1_controls \
  tests.test_stage2_normalizer \
  tests.test_stage2_pipeline
```

## Complete validation

Validate Stage 1:

```bash
python -m scripts.validate_stage1
```

Validate Stage 2:

```bash
python -m scripts.validate_stage2
```

## JSON validation

```bash
python -m json.tool config/settings.json
python -m json.tool config/rbac.json
python -m json.tool config/automation_acl.json
```

## Database review

Open the database:

```bash
sqlite3 database/netshield.db
```

Useful SQLite commands:

```text
.tables
.schema security_events
.schema rejected_events
.schema import_batches
.quit
```

Review project metadata:

```sql
SELECT key, value
FROM system_metadata
ORDER BY key;
```

Review accepted events by source:

```sql
SELECT source_type, COUNT(*) AS accepted
FROM security_events
GROUP BY source_type
ORDER BY source_type;
```

Review normalised events:

```sql
SELECT
    source_event_id,
    event_time,
    source_type,
    event_type,
    username,
    ip_address,
    mac_address,
    cpu_percent
FROM security_events
ORDER BY event_time;
```

Review rejected events:

```sql
SELECT
    source_file,
    line_number,
    reason
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

Review audit events:

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
