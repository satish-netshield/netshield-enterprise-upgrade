# NetShield Phase 3 — Automation

NetShield Automation is a Python-based security automation project that processes security events, detects suspicious behaviour, assigns risk, creates incident records and supports controlled response actions.

The project runs inside an Ubuntu VirtualBox sandbox.

## Current status

Stage 1 establishes:

- Python virtual environment
- SQLite database
- Application and audit logging
- Role-Based Access Control
- CYOD device allowlist
- IP allowlist and simulated blocklist
- Automation-action ACL
- Evidence hashing and protection
- Default-deny testing boundaries

## Security approach

Actions are separated into:

- Automatic low-risk actions
- Actions requiring approval
- Manual-only disruptive actions

Unknown roles, permissions, devices, IP addresses and actions are not automatically trusted.

## Stage 1 validation

Stage 1 checks the project structure, JSON configuration, sandbox restrictions, access controls, device inventory, IP lists, database, logs, permissions and evidence integrity.

## Example output

```text
PASS: RBAC follows least privilege
PASS: Automation ACL follows default deny
PASS: Evidence hash and read-only protection are valid

STAGE 1 VALIDATION: PASS (12/12)
```

## Documentation

- [Workflow](docs/workflow.md)
- [Security logic](docs/security_logic.md)
- [Testing notes](docs/notes.md)
- [Commands](docs/commands.md)
- [Engineering handbook](docs/handbook.md)

## Known limitations

- The project currently operates inside one Ubuntu VM.
- CYOD, wireless and containment scenarios begin as simulations.
- The VirtualBox adapter is not a physical Wi-Fi adapter.
- Runtime logs, databases and evidence are excluded from Git.
- Load balancing, failover and elastic scaling are outside Phase 3.
