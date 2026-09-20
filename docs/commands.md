# NetShield Enterprise Upgrade Commands

## Operational boundary

All project actions remain local and simulated.

No command may target an external system, change real connectivity, modify the real Ubuntu firewall, disable a real account, terminate a real process, remove a real file or bypass RBAC, ACL or approval controls.

Undefined actions remain denied. Disruptive actions require the configured approval and separation-of-duty controls.

---

## Project location

```bash
cd ~/netshield-enterprise-upgrade
source .venv/bin/activate
```

Confirm the repository:

```bash
pwd
git status --short --branch
git log -1 --oneline --decorate
```

---

## General safety checks

Validate the original sandbox:

```bash
python -m scripts.validate_stage1
```

Check Python syntax without retaining bytecode:

```bash
PYTHONDONTWRITEBYTECODE=1 \
python -m compileall -q src scripts tests lab
```

Check JSON configuration:

```bash
for file in config/*.json
do
  python -m json.tool "$file" >/dev/null
done
```

Check SQLite integrity and foreign keys:

```bash
sqlite3 database/netshield.db \
  "PRAGMA integrity_check; PRAGMA foreign_key_check;"
```

Check working-tree formatting:

```bash
git diff --check
git status --short --branch
```

---

## Stage 1 — Enterprise foundation

Initialise and validate:

```bash
python -m scripts.initialize_v2_stage1
python -m scripts.validate_v2_stage1
```

Review V2 metadata:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT key, value
   FROM system_metadata
   WHERE key LIKE 'v2_%'
   ORDER BY key;"
```

---

## Stage 2 — Extended security data pipeline

Initialise, generate, import and validate:

```bash
python -m scripts.initialize_v2_stage2
python -m scripts.generate_v2_stage2_events
python -m scripts.import_v2_stage2_events
python -m scripts.validate_v2_stage2
```

Review accepted events:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT source_type, COUNT(*) AS records
   FROM security_events
   WHERE schema_version = '2.0'
   GROUP BY source_type
   ORDER BY source_type;"
```

Review quarantined events:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT source_file, rejection_reason, quarantine_status
   FROM rejected_events
   ORDER BY rejected_event_id;"
```

---

## Stage 3 — Asset and device identity

Initialise, evaluate and validate:

```bash
python -m scripts.initialize_v2_stage3
python -m scripts.run_v2_stage3_device_identity
python -m scripts.validate_v2_stage3
```

Review the controlled device alert when required:

```bash
python -m scripts.review_v2_stage3_device_alert
```

Review stored alerts:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT device_id, asset_id, alert_type, severity, review_status
   FROM device_alerts
   ORDER BY device_alert_id;"
```

---

## Stage 4 — Identity monitoring

Initialise shared storage and load controlled evidence:

```bash
python -m scripts.initialize_v2_stage4_5
python -m scripts.generate_v2_stage4_5_events
python -m scripts.import_v2_stage4_5_events
```

Run, review and validate identity monitoring:

```bash
python -m scripts.run_v2_stage4_identity_monitoring
python -m scripts.review_v2_stage4_identity_alert
python -m scripts.validate_v2_stage4
```

Review identity alerts:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT detection_type, severity, COUNT(*) AS records
   FROM v2_identity_alerts
   GROUP BY detection_type, severity
   ORDER BY detection_type;"
```

---

## Stage 5 — Zero Trust access policy

Run and validate policy evaluation:

```bash
python -m scripts.run_v2_stage5_access_policy
python -m scripts.validate_v2_stage5
```

Review outcomes:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT outcome, COUNT(*) AS decisions
   FROM access_policy_decisions
   GROUP BY outcome
   ORDER BY outcome;"
```

Review policy reasons:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT request_id, outcome, winning_policy, reason_codes
   FROM access_policy_decisions
   ORDER BY access_policy_decision_id;"
```

---

## Stage 6 — Network and Wi-Fi monitoring

Initialise, generate, import and run:

```bash
python -m scripts.initialize_v2_stage6
python -m scripts.generate_v2_stage6_events
python -m scripts.import_v2_stage6_events
python -m scripts.run_v2_stage6_network_monitoring
```

Review and validate:

```bash
python -m scripts.review_v2_stage6_network_alert
python -m scripts.validate_v2_stage6
```

Review alerts and decisions:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT detection_type, severity, COUNT(*) AS records
   FROM v2_network_alerts
   GROUP BY detection_type, severity
   ORDER BY detection_type;

   SELECT outcome, COUNT(*) AS decisions
   FROM v2_network_access_decisions
   GROUP BY outcome
   ORDER BY outcome;"
```

---

## Stage 7 — Endpoint monitoring

Initialise shared storage and load controlled evidence:

```bash
python -m scripts.initialize_v2_stage7_8
python -m scripts.generate_v2_stage7_8_events
python -m scripts.import_v2_stage7_8_events
python -m scripts.run_v2_stage7_endpoint_monitoring
```

Test an unauthorised approval:

```bash
python -m scripts.approve_v2_stage7_endpoint_isolation \
  --device CYOD-002 \
  --actor analyst01
```

Approve the simulated isolation:

```bash
python -m scripts.approve_v2_stage7_endpoint_isolation \
  --device CYOD-002 \
  --actor responder01
```

Review and validate:

```bash
python -m scripts.review_v2_stage7_endpoint_alert
python -m scripts.validate_v2_stage7
```

Review simulated isolation:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT device_id, status, requested_by, approved_by
   FROM v2_endpoint_isolation_actions
   ORDER BY endpoint_isolation_action_id;"
```

---

## Stage 8 — Vulnerability management

Run vulnerability management:

```bash
python -m scripts.run_v2_stage8_vulnerability_management
```

Test an unauthorised review:

```bash
python -m scripts.review_v2_stage8_vulnerability_finding \
  --finding S78-FND-FP-001 \
  --actor viewer01
```

Complete the authorised review and validation:

```bash
python -m scripts.review_v2_stage8_vulnerability_finding \
  --finding S78-FND-FP-001 \
  --actor analyst01

python -m scripts.validate_v2_stage8
```

Review findings:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT source_finding_id, severity, priority_level,
          remediation_status, exploitation_status
   FROM v2_vulnerability_findings
   ORDER BY source_finding_id;"
```

---

## Stage 9 — Continuous monitoring and risk scoring

Initialise and run two controlled cycles:

```bash
python -m scripts.initialize_v2_stage9
python -m scripts.run_v2_stage9_continuous_monitoring
python -m scripts.run_v2_stage9_continuous_monitoring \
  --force-repeat
python -m scripts.validate_v2_stage9
```

Review risk and health:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT entity_type, entity_id, risk_score, risk_level
   FROM v2_continuous_risk_scores
   ORDER BY risk_score DESC, entity_type, entity_id;

   SELECT component_name, health_status, last_successful_run
   FROM v2_detection_health
   ORDER BY component_name;"
```

---

## Stage 10 — XDR-style correlation

Initialise and run correlation twice:

```bash
python -m scripts.initialize_v2_stage10
python -m scripts.run_v2_stage10_xdr_correlation
python -m scripts.run_v2_stage10_xdr_correlation
python -m scripts.validate_v2_stage10
```

Review incidents and indicators:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT incident_key, title, severity, confidence, status
   FROM v2_xdr_incidents
   ORDER BY incident_key;

   SELECT indicator_type, COUNT(*) AS records
   FROM v2_xdr_indicators
   GROUP BY indicator_type
   ORDER BY indicator_type;"
```

---

## Stage 11 — Incident management and evidence

Initialise and import incidents:

```bash
python -m scripts.initialize_v2_stage11
python -m scripts.initialize_v2_stage11_risk
python -m scripts.import_v2_stage11_incidents
python -m scripts.import_v2_stage11_context
```

Assign the evidence-backed incident:

```bash
python -m scripts.assign_v2_stage11_incident \
  --incident INC-V2-11-0001 \
  --actor analyst01 \
  --owner analyst01 \
  --notes "Assign the evidence-backed incident for investigation."
```

Triage the incident:

```bash
python -m scripts.review_v2_stage11_incident \
  --incident INC-V2-11-0001 \
  --actor analyst01 \
  --status Triaged \
  --notes "Review the correlated evidence." \
  --decision "Prioritise further investigation of the correlated activity." \
  --request-id stage11-triage-001
```

Begin investigation:

```bash
python -m scripts.review_v2_stage11_incident \
  --incident INC-V2-11-0001 \
  --actor analyst01 \
  --status Investigating \
  --notes "Begin investigation of the preserved evidence." \
  --decision "Begin investigation of the preserved cross-source evidence." \
  --request-id stage11-investigation-001
```

Test an unauthorised false-positive review:

```bash
python -m scripts.close_v2_stage11_false_positive \
  --incident INC-V2-11-0003 \
  --actor viewer01 \
  --notes "Permission test only." \
  --reason "Permission test only." \
  --evidence-key "identity:test" \
  --request-id stage11-fp-permission-test-001
```

Generate reports twice and validate them:

```bash
python -m scripts.generate_v2_stage11_reports
python -m scripts.generate_v2_stage11_reports
python -m scripts.validate_v2_stage11
```

Review managed incidents and reports:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT incident_id, status, incident_owner, severity, confidence
   FROM v2_incidents
   ORDER BY incident_id;

   SELECT incident_id, report_type, report_path, report_sha256
   FROM v2_incident_reports
   ORDER BY incident_id, report_type;"
```

Confirm the final closed report state:

```bash
python - <<'PY'
import json
from pathlib import Path

report = json.loads(
    Path(
        "reports/v2/incidents/json/INC-V2-11-0001.json"
    ).read_text(encoding="utf-8")
)

assert report["status"] == "Closed"
assert report["closure_reason"]
assert report["closed_at"]
assert any(
    row["new_status"] == "Closed"
    for row in report["decisions"]
)

print("PASS: Final incident report reflects verified closure")
PY
```

---

## Stage 12 — Approval-controlled containment

Initialise and review the interface:

```bash
python -m scripts.initialize_v2_stage12
python -m scripts.manage_v2_stage12_containment --help
```

Request an automatic simulated blocklist action:

```bash
python -m scripts.manage_v2_stage12_containment request \
  --incident INC-V2-11-0001 \
  --action add_to_simulated_blocklist \
  --target-type ip_address \
  --target 192.0.2.10 \
  --actor responder01 \
  --reason "Contain the evidence-backed suspicious source address." \
  --evidence-reference \
  "access_policy:16334b8cc97e84b8123301e6b36c3a426ddaf9b133464ae94b8d587f0d5c1c01" \
  --request-id stage12-blocklist-001
```

Request an approval-controlled restriction:

```bash
python -m scripts.manage_v2_stage12_containment request \
  --incident INC-V2-11-0001 \
  --action restrict_account \
  --target-type username \
  --target responder01 \
  --actor responder01 \
  --reason "Temporarily restrict the risky simulated account." \
  --evidence-reference \
  "access_policy:16334b8cc97e84b8123301e6b36c3a426ddaf9b133464ae94b8d587f0d5c1c01" \
  --request-id stage12-restrict-account-001
```

Approve, execute and roll back the stored action:

```bash
python -m scripts.manage_v2_stage12_containment decide \
  --action-id 2 \
  --actor admin01 \
  --decision approved \
  --notes "Approve the evidence-backed simulated restriction."

python -m scripts.manage_v2_stage12_containment execute \
  --action-id 2 \
  --actor admin01

python -m scripts.manage_v2_stage12_containment rollback \
  --action-id 2 \
  --actor netshield01 \
  --reason "Restore simulated account access after review." \
  --rollback-id stage12-rollback-account-001
```

Validate Stage 12:

```bash
python -m scripts.validate_v2_stage12
```

Review actions, approvals and rollback:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT containment_action_id, action_type, target_value,
          requested_by, approved_by, executed_by, status
   FROM v2_containment_actions
   ORDER BY containment_action_id;

   SELECT containment_action_id, decision_status,
          self_approval_blocked, action_occurred
   FROM v2_containment_approvals
   ORDER BY containment_action_id;

   SELECT containment_action_id, rollback_action,
          rollback_status, real_action_executed
   FROM v2_containment_rollbacks
   ORDER BY containment_rollback_id;"
```

---

## Stage 13 — Eradication, recovery and review

Initialise and review the interface:

```bash
python -m scripts.initialize_v2_stage13
python -m scripts.manage_v2_stage13_recovery --help
```

Confirm successful containment:

```bash
python -m scripts.manage_v2_stage13_recovery \
  confirm-containment \
  --incident INC-V2-11-0001 \
  --actor responder01 \
  --notes "Confirm successful evidence-backed containment." \
  --request-id stage13-confirm-containment-001
```

Request an eradication action:

```bash
python -m scripts.manage_v2_stage13_recovery request \
  --incident INC-V2-11-0001 \
  --action remove_unauthorised_privileges \
  --target-type username \
  --target viewer01 \
  --actor responder01 \
  --reason "Remove the simulated unauthorised privilege change." \
  --evidence \
  "identity:9d970c63b0c9f91ae60fa0ae9719102d7da582c8832294b6e94851917eb94ffe" \
  --request-id stage13-remove-privilege-001
```

Approve and execute the action:

```bash
python -m scripts.manage_v2_stage13_recovery decide \
  --action-id 1 \
  --actor admin01 \
  --decision approved \
  --notes "Approve the evidence-backed simulated action."

python -m scripts.manage_v2_stage13_recovery execute \
  --action-id 1 \
  --actor admin01 \
  --outcome successful \
  --details "Simulated privilege correction completed."
```

Complete eradication:

```bash
python -m scripts.manage_v2_stage13_recovery \
  complete-eradication \
  --incident INC-V2-11-0001 \
  --actor responder01 \
  --notes "Confirm successful simulated eradication." \
  --request-id stage13-complete-eradication-001
```

Record the original-threat retest:

```bash
python -m scripts.manage_v2_stage13_recovery retest \
  --incident INC-V2-11-0001 \
  --type original_threat \
  --target-type username \
  --target viewer01 \
  --description "Retest the original privilege-change path." \
  --result blocked \
  --evidence \
  "identity:9d970c63b0c9f91ae60fa0ae9719102d7da582c8832294b6e94851917eb94ffe" \
  --actor responder01 \
  --request-id stage13-threat-retest-001
```

Record the original-vulnerability retest:

```bash
python -m scripts.manage_v2_stage13_recovery retest \
  --incident INC-V2-11-0001 \
  --type original_vulnerability \
  --target-type network_id \
  --target NetShield-Lab \
  --description "Retest the original Wi-Fi downgrade condition." \
  --result blocked \
  --evidence \
  "network:8ff8ca09d4339ba02069b4cba98c8d104f6bf86be33a88666217346c74ac1efc" \
  --actor responder01 \
  --request-id stage13-vulnerability-retest-001
```

Complete recovery and close the incident:

```bash
python -m scripts.manage_v2_stage13_recovery \
  complete-recovery \
  --incident INC-V2-11-0001 \
  --actor responder01 \
  --notes "Confirm successful simulated recovery." \
  --request-id stage13-complete-recovery-001

python -m scripts.manage_v2_stage13_recovery close \
  --incident INC-V2-11-0001 \
  --actor analyst01 \
  --lessons \
  "Containment, eradication and recovery require separate evidence-backed decisions." \
  --detection-improvement \
  "Prioritise related privilege, service-account and Wi-Fi downgrade activity." \
  --policy-improvement \
  "Require approval and successful retests before verified closure." \
  --closure-reason \
  "Simulated recovery completed and both original conditions were blocked." \
  --request-id stage13-close-001
```

Validate and review Stage 13:

```bash
python -m scripts.validate_v2_stage13

sqlite3 -header -column database/netshield.db \
  "SELECT recovery_action_id, phase, action_type,
          target_value, control_level, status,
          approved_by, executed_by
   FROM v2_recovery_actions
   ORDER BY recovery_action_id;

   SELECT recovery_retest_id, retest_type, target_value,
          observed_result, verification_status,
          confirmed_no_longer_succeeds
   FROM v2_recovery_retests
   ORDER BY recovery_retest_id;

   SELECT incident_id, review_status, recovery_verified,
          original_threat_blocked,
          original_vulnerability_blocked,
          closure_authorised, closure_actor
   FROM v2_post_incident_reviews
   ORDER BY incident_id;"
```

---

## Stage 14 — Full enterprise-concept validation

Validate the configuration and script:

```bash
python -m json.tool \
  config/v2_full_enterprise_validation.json >/dev/null

python -m py_compile scripts/validate_v2_stage14.py
```

Record the live database hash:

```bash
sha256sum database/netshield.db
```

Run Stage 14 twice:

```bash
PYTHONDONTWRITEBYTECODE=1 \
python -m scripts.validate_v2_stage14

PYTHONDONTWRITEBYTECODE=1 \
python -m scripts.validate_v2_stage14
```

Record the database hash again:

```bash
sha256sum database/netshield.db
```

The database hashes must remain identical.

Review Stage 14 changes:

```bash
git status --short --branch
git diff --check
git --no-pager diff --stat
```

---

## Stage 15 — Final revision and sign-off

Check documentation titles:

```bash
head -n 1 \
  README.md \
  docs/workflow.md \
  docs/security_logic.md \
  docs/notes.md \
  docs/commands.md \
  docs/handbook.md
```

Check Microsoft references:

```bash
grep -RniE \
  "Microsoft|Entra|Defender|Sentinel|XDR" \
  README.md docs
```

Every match must describe a design concept, comparison or XDR-style behaviour rather than a required Microsoft service.

Check high-risk secret patterns:

```bash
git grep -nEI \
  'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|password[[:space:]]*[:=][[:space:]]*[^[:space:]]+' \
  -- . \
  ':(exclude)docs/commands.md' || true
```

Check email addresses and personal home paths:

```bash
git grep -nEI \
  '[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|/home/[A-Za-z0-9._-]+' \
  -- . || true
```

Check temporary files:

```bash
find . \
  -path './.git' -prune -o \
  -path './.venv' -prune -o \
  -type f \
  \( -name '*.tmp' -o -name '*.bak' -o -name '*.swp' \
     -o -name '*~' -o -name '*.orig' -o -name '*.pyc' \) \
  -print
```

Check obsolete markers:

```bash
grep -RniE \
  'TODO|FIXME|obsolete|deprecated|unused|temporary workaround' \
  config scripts src tests \
  --include='*.py' \
  --include='*.json' || true
```

Review tracked file sizes and untracked files:

```bash
git ls-files -z |
xargs -0 -r du -h |
sort -h |
tail -20

git ls-files --others --exclude-standard
```

Run final syntax validation:

```bash
PYTHONDONTWRITEBYTECODE=1 \
python -m compileall -q src scripts tests lab
```

Run the complete regression suite:

```bash
PYTHONDONTWRITEBYTECODE=1 \
python -W error::ResourceWarning \
  -m unittest discover \
  -s tests \
  -p 'test*.py'
```

Run final integrated validation:

```bash
PYTHONDONTWRITEBYTECODE=1 \
python -m scripts.validate_v2_stage14
```

Check database integrity and formatting:

```bash
sqlite3 database/netshield.db \
  "PRAGMA integrity_check; PRAGMA foreign_key_check;"

git diff --check
git status --short --branch
```

Final sign-off is recorded only after implementation, documentation, the Word handbook, diagrams, privacy review, validation and Git review are complete.

---

## Python 3.14 warning check

Run the tests and save the output:

```bash
PYTHONDONTWRITEBYTECODE=1 \
PYTHONTRACEMALLOC=5 \
python -W always::ResourceWarning \
  -m unittest discover \
  -s tests \
  -p 'test*.py' 2>&1 |
tee /tmp/netshield_tests.log
```

Check for unclosed SQLite warnings:

```bash
if grep -q \
  "ResourceWarning: unclosed database" \
  /tmp/netshield_tests.log
then
  echo "FAIL: unclosed-database warning found"
else
  echo "PASS: no unclosed-database warning found"
fi
```

Treat resource warnings as failures:

```bash
PYTHONDONTWRITEBYTECODE=1 \
python -W error::ResourceWarning \
  -m unittest discover \
  -s tests \
  -p 'test*.py'
```

---

## Full project validation

Run the legacy validator:

```bash
python -m scripts.validate_stage11
```

Run every earlier V2 validator:

```bash
for module in \
  scripts.validate_v2_stage1 \
  scripts.validate_v2_stage2 \
  scripts.validate_v2_stage3 \
  scripts.validate_v2_stage4 \
  scripts.validate_v2_stage5 \
  scripts.validate_v2_stage6 \
  scripts.validate_v2_stage7 \
  scripts.validate_v2_stage8 \
  scripts.validate_v2_stage9 \
  scripts.validate_v2_stage10 \
  scripts.validate_v2_stage11 \
  scripts.validate_v2_stage12 \
  scripts.validate_v2_stage13
do
  echo "RUNNING: $module"
  PYTHONDONTWRITEBYTECODE=1 python -m "$module"
done
```

Run complete Stage 14 validation:

```bash
PYTHONDONTWRITEBYTECODE=1 \
python -m scripts.validate_v2_stage14
```

Check final database integrity:

```bash
sqlite3 database/netshield.db \
  "PRAGMA integrity_check; PRAGMA foreign_key_check;"
```

---

## Evidence and audit review

Review audit outcomes:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT result, COUNT(*) AS records
   FROM audit_events
   GROUP BY result
   ORDER BY result;"
```

Review containment and recovery audit records:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT event_id, actor, action, target, result
   FROM audit_events
   WHERE action LIKE '%stage12%'
      OR action LIKE '%stage13%'
   ORDER BY event_id;"
```

Review lifecycle decisions:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT actor, previous_status, new_status, decision
   FROM v2_incident_decisions
   WHERE incident_id = 'INC-V2-11-0001'
   ORDER BY incident_decision_id;"
```

Review evidence totals:

```bash
sqlite3 -header -column database/netshield.db \
  "SELECT 'incident' AS evidence_type, COUNT(*) AS records
   FROM v2_incident_evidence
   UNION ALL
   SELECT 'containment', COUNT(*)
   FROM v2_containment_evidence
   UNION ALL
   SELECT 'recovery', COUNT(*)
   FROM v2_recovery_evidence;"
```

---

## Final Git review

Review unstaged and staged changes:

```bash
git status --short --branch
git --no-pager diff --stat
git --no-pager diff --cached --stat
git diff --check
git diff --cached --check
```

Stage the reviewed Phase 3A V2 completion files:

```bash
git add \
  README.md \
  docs/workflow.md \
  docs/security_logic.md \
  docs/notes.md \
  docs/commands.md \
  docs/handbook.md \
  config/v2_full_enterprise_validation.json \
  scripts/validate_v2_stage14.py \
  scripts/generate_v2_stage11_reports.py \
  scripts/validate_v2_stage11.py \
  reports/v2/incidents/json/INC-V2-11-0001.json \
  reports/v2/incidents/json/INC-V2-11-0002.json \
  reports/v2/incidents/json/INC-V2-11-0003.json \
  reports/v2/incidents/text/INC-V2-11-0001.txt \
  reports/v2/incidents/text/INC-V2-11-0002.txt \
  reports/v2/incidents/text/INC-V2-11-0003.txt
```

Review the exact staged diff:

```bash
git --no-pager diff --cached --name-status
git --no-pager diff --cached --stat
git diff --cached --check
```

Commit only after explicit Stage 15 approval:

```bash
git commit -m "Complete Phase 3A V2 validation and sign-off"
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

After sign-off, changes should be limited to genuine defects, security improvements or justified engineering requirements.
