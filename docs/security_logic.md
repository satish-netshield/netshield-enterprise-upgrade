# Security Logic

## Default deny

Access and automation are permitted only when explicitly defined. Unknown roles, permissions and actions are denied.

Stage 2 follows the same approach. Only approved event sources and valid fields enter the accepted-event table.

## Role-Based Access Control

- Viewer: reads alerts and closed reports.
- Analyst: investigates and classifies incidents.
- Responder: performs approved containment and records recovery.
- Administrator: manages rules, roles, inventories and configuration.

Application RBAC controls NetShield decisions. It does not create separate Ubuntu operating-system users.

## Automation-action ACL

- Automatic: alert creation, evidence preservation and simulated responses.
- Approval required: account restriction, session revocation, process termination, device quarantine and Ubuntu firewall changes.
- Manual only: credential resets, physical-device removal and infrastructure changes.

Undefined actions are denied.

## CYOD allowlist

CYOD provides a controlled list of approved devices. The VirtualBox device is the first approved test asset.

A MAC address helps with inventory checks but does not prove device identity because it can be spoofed. Later stages will also use hostname, assigned user and connection history.

## IP-list precedence

The blocklist is checked before the allowlist. An address appearing in both lists is treated as blocked until investigated.

Malformed IP addresses are rejected.

## Approved event sources

Stage 2 accepts:

- Authentication
- Network
- Wi-Fi
- Endpoint
- Application

An unsupported source type is rejected.

The source type inside an event must also match its source filename. This prevents incorrectly labelled data from entering the accepted-event table.

## Required event fields

Every accepted event must contain:

- Event ID
- Event timestamp
- Source type
- Event type

Required values must be non-empty text. Optional fields are validated when supplied.

## Timestamp handling

Event timestamps must use ISO 8601 and include a timezone.

Accepted timestamps are converted to UTC before storage. This gives later detection and correlation stages one consistent timeline.

## IP and MAC validation

IP addresses are validated using Python's standard `ipaddress` module.

MAC addresses must contain six hexadecimal pairs. Accepted MAC addresses are stored in lowercase with colon separators.

Consistent formatting supports later IP-list and CYOD inventory comparisons.

## CPU validation

CPU usage is optional because it does not apply to every event source.

When supplied, it must be numeric and between 0 and 100 percent. Invalid values are rejected rather than corrected silently.

## Malformed-event handling

Malformed input is separated from accepted security data.

Each rejected record stores:

- Rejection time
- Source filename
- Import batch
- Line number
- Failure reason
- Original input

This keeps invalid data available for troubleshooting without allowing it into later detection logic.

## Duplicate protection

The combination of source filename and source event ID must be unique.

The first valid event is accepted. A later copy is rejected as a duplicate and preserved in the rejected-event table.

## Raw-event preservation

Accepted events contain normalised searchable fields and the original JSON event.

The normalised fields support later detection. The original event preserves the source context.

## Import-batch tracking

Each source file receives a unique batch ID.

The batch records:

- Start and completion times
- Source filename and source type
- Total records
- Accepted records
- Rejected records
- Final status

The total number of records must equal accepted plus rejected.

## Parameterised SQL

Event values are passed separately from the SQL statements.

This treats event content as data rather than executable SQL syntax.

## Evidence protection

Evidence is kept in an owner-only directory. Preserved files receive a SHA-256 hash and read-only permission.

Hashing detects content changes. Read-only permission reduces accidental modification but is not enterprise immutable storage.

## Sandbox boundaries

- Testing remains inside Ubuntu VirtualBox.
- Stage 2 events are controlled and simulated.
- Real external targets are prohibited.
- SQL injection will target only the local test application.
- Containment begins as a simulation.
- Disruptive actions require approval.
- The Windows host and public systems are outside scope.
