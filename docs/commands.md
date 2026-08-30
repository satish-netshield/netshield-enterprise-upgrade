# NetShield Phase 3 Commands

All commands are run from the project directory inside the Ubuntu VirtualBox sandbox.

## Project setup

```bash
cd /home/netshield01/netshield-phase3
source .venv/bin/activate

python --version
git status --short --branch
```

## Stage 1 — Environment and access control

```bash
python -m compileall -q src scripts tests

python -m scripts.initialize_stage1
python -m scripts.validate_stage1

python -m unittest -q tests.test_stage1_controls
```

## Stage 2 — Security data pipeline

```bash
python -m scripts.generate_stage2_events
python -m scripts.initialize_stage2
python -m scripts.import_stage2_events
python -m scripts.validate_stage2

python -m unittest -q \
  tests.test_stage2_normalizer \
  tests.test_stage2_pipeline
```

## Stage 3 — Identity and authentication detection

```bash
python -m scripts.generate_stage3_events
python -m scripts.initialize_stage3
python -m scripts.import_stage3_events
python -m scripts.run_stage3_detection
python -m scripts.investigate_stage3_false_positive
python -m scripts.validate_stage3

python -m unittest -q tests.test_stage3_identity_detector
```

To check duplicate alert protection:

```bash
python -m scripts.run_stage3_detection
```

## Stage 4 — Network, CYOD and Wi-Fi detection

```bash
python -m scripts.generate_stage4_events
python -m scripts.generate_stage4_correlation_events
python -m scripts.import_stage4_events
python -m scripts.run_stage4_detection
python -m scripts.validate_stage4

python -m unittest -q tests.test_stage4_network_correlation
```

To check duplicate detection:

```bash
python -m scripts.run_stage4_detection
```

## Stage 5 — Endpoint and wired-LAN detection

```bash
python -m scripts.initialize_stage5
python -m scripts.generate_stage5_events
python -m scripts.import_stage5_events
python -m scripts.run_stage5_detection
python -m scripts.validate_stage5

python -m unittest -q tests.test_stage5_endpoint_detector
```

To check duplicate imports and repeated detection:

```bash
python -m scripts.import_stage5_events
python -m scripts.run_stage5_detection
```

## Stage 6 — SQL injection detection

### Prepare the local SQL injection lab

```bash
python -m py_compile \
  lab/sql_injection/app.py \
  lab/sql_injection/test_lab.py \
  lab/sql_injection/generate_requests.py \
  lab/sql_injection/detect_stage6.py \
  lab/sql_injection/validate_stage6.py

python -m lab.sql_injection.app
```

### Run Stage 6 unit tests

```bash
python -m unittest -v lab.sql_injection.test_lab
```

### Generate and analyse controlled requests

```bash
python -m lab.sql_injection.generate_requests
python -m lab.sql_injection.detect_stage6
python -m lab.sql_injection.validate_stage6
```

### Start a clean Stage 6 log run

```bash
mkdir -p lab/sql_injection/logs/archive

mv lab/sql_injection/logs/application_events.jsonl \
  lab/sql_injection/logs/archive/application_events_before_clean_run.jsonl

python -m lab.sql_injection.generate_requests
python -m lab.sql_injection.detect_stage6

cat lab/sql_injection/data/stage6_requests.jsonl
cat lab/sql_injection/outputs/stage6_detection_report.json
```

## Stage 7 — Event correlation, risk scoring and IoC extraction

### Validate the configuration

```bash
python -m json.tool config/stage7_correlation.json > /dev/null
```

### Compile the Stage 7 files

```bash
python -m py_compile \
  src/correlation/stage7_engine.py \
  scripts/generate_stage7_events.py \
  scripts/run_stage7_correlation.py \
  scripts/validate_stage7.py \
  tests/test_stage7_correlation.py
```

### Generate and analyse correlation events

```bash
python scripts/generate_stage7_events.py
python scripts/run_stage7_correlation.py

cat lab/sql_injection/data/stage7_correlation_events.jsonl
cat lab/sql_injection/outputs/stage7_correlation_report.json
```

### Run Stage 7 tests and validation

```bash
python -m unittest -v tests.test_stage7_correlation
python scripts/validate_stage7.py
```

## Stage 8 — Incident management and evidence handling

### Compile the Stage 8 files

```bash
python -m py_compile \
  src/incident_management/stage8_manager.py \
  tests/test_stage8_incident_management.py \
  scripts/validate_stage8.py
```

### Create incident records and reports

```bash
python -m src.incident_management.stage8_manager
```

### Review Stage 8 outputs

```bash
find lab/sql_injection/outputs/stage8 -maxdepth 3 -type f -print | sort

cat lab/sql_injection/outputs/stage8/stage8_incident_summary.json
cat lab/sql_injection/outputs/stage8/audit_trail.jsonl

sed -n '1,220p' \
  lab/sql_injection/outputs/stage8/reports/INC-ST8-001-0AFD600A25B0.md
```

### Run Stage 8 tests and validation

```bash
python -m unittest -v tests.test_stage8_incident_management
python scripts/validate_stage8.py
```

## Stage 9 — Controlled containment automation

### Compile the Stage 9 files

```bash
python -m py_compile \
  src/response/stage9_containment.py \
  tests/test_stage9_containment.py \
  scripts/validate_stage9.py
```

### Run simulated containment

```bash
python -m src.response.stage9_containment
```

### Review the Stage 9 outputs

```bash
find lab/sql_injection/outputs/stage9 -maxdepth 3 -type f -print | sort

cat lab/sql_injection/outputs/stage9/stage9_containment_report.json
cat lab/sql_injection/outputs/stage9/containment_audit.jsonl
```

### Run Stage 9 tests and validation

```bash
python -m unittest -v tests.test_stage9_containment
python scripts/validate_stage9.py
```

## Stage 10 — Eradication and recovery

### Compile the Stage 10 files

```bash
python -m py_compile \
  src/response/stage10_eradication.py \
  tests/test_stage10_eradication.py \
  scripts/validate_stage10.py
```

### Run simulated eradication and recovery

```bash
python -m src.response.stage10_eradication
```

### Review the Stage 10 outputs

```bash
find lab/sql_injection/outputs/stage10 -maxdepth 3 -type f -print | sort

cat lab/sql_injection/outputs/stage10/stage10_eradication_report.json
cat lab/sql_injection/outputs/stage10/eradication_audit.jsonl
```

### Run Stage 10 tests and validation

```bash
python -m unittest -v tests.test_stage10_eradication
python scripts/validate_stage10.py
```

## Stage 11 — Full project validation

### Compile the Stage 11 validator

```bash
python -m py_compile scripts/validate_stage11.py
```

### Run complete project validation

```bash
python scripts/validate_stage11.py
```

Stage 11 checks syntax, the combined Stage 1–10 regression, individual validators, evidence integrity, IoC extraction, audit records, response results, previous-stage outputs and documentation presence.

## Combined Stage 1–10 regression

```bash
python -m compileall -q src scripts tests lab

python -m unittest -q \
  tests.test_stage1_controls \
  tests.test_stage2_normalizer \
  tests.test_stage2_pipeline \
  tests.test_stage3_identity_detector \
  tests.test_stage4_network_correlation \
  tests.test_stage5_endpoint_detector \
  lab.sql_injection.test_lab \
  tests.test_stage7_correlation \
  tests.test_stage8_incident_management \
  tests.test_stage9_containment \
  tests.test_stage10_eradication
```

## Run all validators

```bash
python -m scripts.validate_stage1
python -m scripts.validate_stage2
python -m scripts.validate_stage3
python -m scripts.validate_stage4
python -m scripts.validate_stage5
python -m lab.sql_injection.validate_stage6
python scripts/validate_stage7.py
python scripts/validate_stage8.py
python scripts/validate_stage9.py
python scripts/validate_stage10.py
python scripts/validate_stage11.py
```

## Documentation and Git checks

```bash
for file in README.md \
  docs/workflow.md \
  docs/security_logic.md \
  docs/notes.md \
  docs/commands.md \
  docs/handbook.md
do
  test -s "$file" && echo "PASS: $file exists and is not empty" \
    || { echo "FAIL: $file missing or empty"; exit 1; }
done

git diff --check
git status --short --branch
git log --oneline --decorate -3
```

## Review excluded runtime files

The following runtime directories are intentionally excluded from Git:

```text
lab/sql_injection/data/
lab/sql_injection/logs/
lab/sql_injection/outputs/
```

Check staged files before committing:

```bash
git diff --cached --check
git diff --cached --name-status

git diff --cached --name-only | \
  grep -E '(\.venv|__pycache__|\.pyc$|\.db$|\.sqlite$|\.log$|lab/sql_injection/outputs|lab/sql_injection/data)' \
  && echo "ERROR: Runtime files are staged" \
  || echo "PASS: No runtime files are staged"
```
