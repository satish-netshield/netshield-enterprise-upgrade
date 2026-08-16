# Security Logic

## Default deny

Access and automation are permitted only when explicitly defined. Unknown roles, permissions and actions are denied.

## Role-Based Access Control

- Viewer: reads alerts and closed reports.
- Analyst: investigates and classifies incidents.
- Responder: performs approved containment and records recovery.
- Administrator: manages rules, roles, inventories and configuration.

## Automation-action ACL

- Automatic: alert creation, evidence preservation and simulated responses.
- Approval required: account restriction, session revocation, process termination, device quarantine and Ubuntu firewall changes.
- Manual only: credential resets, physical-device removal and infrastructure changes.

Undefined actions are denied.

## CYOD allowlist

CYOD provides a controlled list of approved devices. The VirtualBox device is the first approved test asset.

A MAC address is useful but does not prove identity because it can be spoofed. Later stages will add hostname, assigned user, vendor and connection history.

## IP-list precedence

The blocklist is checked before the allowlist. An address appearing in both lists is treated as blocked until investigated.

Malformed IP addresses are rejected.

## Evidence protection

Evidence is kept in an owner-only directory. Preserved files receive an SHA-256 hash and read-only permission.

Hashing detects content changes. Read-only permission reduces accidental modification but is not enterprise immutable storage.

## Sandbox boundaries

- Testing remains inside Ubuntu VirtualBox.
- Real external targets are prohibited.
- SQL injection targets only the local test application.
- Containment starts as a simulation.
- Disruptive actions require approval.
- The Windows host and public systems are outside scope.
