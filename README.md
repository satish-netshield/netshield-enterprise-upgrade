# NetShield Phase 3 — Automation

NetShield Automation is a Python cybersecurity project being built in stages inside an Ubuntu VirtualBox sandbox.

The environment and access controls are complete. The project can now generate, validate, normalise and store simulated security events.

Detection, correlation, incident handling and controlled response will be added in the remaining stages.

## Current build

### Stage 1 — Environment and access control

Stage 1 created the safe project foundation:

- Python virtual environment
- Project configuration
- SQLite database
- Application and audit logs
- File and directory permissions
- Viewer, Analyst, Responder and Administrator roles
- Role-Based Access Control
- CYOD device allowlist
- IP allowlist and simulated blocklist
- Automation-action ACL
- Evidence hashing and protection
- Safe sandbox boundaries

### Stage 2 — Security data pipeline

Stage 2 created the first working data pipeline:

- Generated safe simulated events
- Created authentication, network and Wi-Fi events
- Created endpoint, CPU and application events
- Read JSON Lines files one record at a time
- Validated required fields
- Converted timestamps to UTC
- Validated IP addresses, MAC addresses and CPU values
- Stored accepted events in SQLite
- Preserved rejected records with failure reasons
- Prevented duplicate accepted events
- Recorded each import batch and audit event

## How the pipeline works

1. Safe test events are generated in separate JSONL source files.
2. The collector reads and parses each line.
3. Required fields and values are validated.
4. Accepted events are normalised into one structure.
5. Valid events are stored in SQLite.
6. Invalid or duplicate events are stored separately with their rejection reason.

## Security approach

The project follows default deny and least privilege.

Unknown roles, permissions and automation actions are denied. Disruptive response actions require approval or remain manual.

The data pipeline accepts only the approved event sources:

- Authentication
- Network
- Wi-Fi
- Endpoint
- Application

Real external targets remain prohibited. All current activity stays inside the local sandbox.

## Testing

The combined test run completed successfully:

- 11 Stage 1 access-control tests passed
- 11 Stage 2 normalisation tests passed
- 6 Stage 2 pipeline tests passed
- 28 unit tests passed in total
- Stage 1 validation passed 12/12
- Stage 2 validation passed 14/14

The first Stage 2 import processed 19 simulated records:

- 15 valid records were accepted
- 4 deliberately malformed records were rejected
- Each of the five sources stored 3 accepted events

## Example output

```text
PASS: Generated 19 safe simulated records

application_events.jsonl: accepted=3 rejected=1 status=completed_with_rejections
authentication_events.jsonl: accepted=3 rejected=1 status=completed_with_rejections
endpoint_events.jsonl: accepted=3 rejected=1 status=completed_with_rejections
network_events.jsonl: accepted=3 rejected=1 status=completed_with_rejections
wifi_events.jsonl: accepted=3 rejected=0 status=completed

STAGE 2 IMPORT: files=5 total=19 accepted=15 rejected=4
```

```text
PASS: Accepted timestamps are normalised to UTC
PASS: Accepted raw events are preserved
PASS: Duplicate-event protection is active
PASS: Stage 2 import has an audit record

STAGE 2 VALIDATION: PASS (14/14)
```

## Notes from testing

The malformed records were included deliberately. They tested missing event IDs, invalid JSON, an invalid IP address and CPU usage above 100 percent.

JSONL worked well for this stage because one bad line could be rejected without stopping the remaining events.

Stage 2 converted the New Zealand test timestamps to UTC before storage. This will help later when events from different sources and locations are correlated.

Stage 1 was tested again after the pipeline was added and still passed all 12 validation checks.

## Known limitations

- Events are simulated rather than collected from live systems.
- The collector currently reads local JSONL files only.
- The project currently runs inside one Ubuntu VM.
- The VirtualBox adapter cannot provide real Wi-Fi heat-map data.
- CYOD, wireless and containment scenarios begin as simulations.
- SQLite suits this local lab but not a distributed deployment.
- Detection and alert creation begin in the later stages.
- Load balancing, failover and elastic scaling are outside Phase 3.
