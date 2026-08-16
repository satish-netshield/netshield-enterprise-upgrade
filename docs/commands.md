# Commands

## Working directory

Run project commands from the repository root:

`cd /home/netshield01/netshield-phase3`

## Environment

Activate the project environment:

`source .venv/bin/activate`

## Stage 1 initialisation

`python -m scripts.initialize_stage1`

## Unit tests

`python -m unittest -v tests.test_stage1_controls`

## Complete validation

`python -m scripts.validate_stage1`

## JSON validation

- `python -m json.tool config/settings.json`
- `python -m json.tool config/rbac.json`
- `python -m json.tool config/automation_acl.json`

## Database review

- `sqlite3 database/netshield.db`
- `.tables`
- `SELECT * FROM system_metadata;`
- `SELECT * FROM user_roles;`
- `SELECT * FROM audit_events;`
- `.quit`

## Evidence verification

`sha256sum --check evidence/stage1_permission_test.sha256`

## Git review

- `git status`
- `git diff`
